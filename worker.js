const PRIMARY_UPSTREAM = "api.asmr.one";
const BACKUP_UPSTREAMS = ["api.asmr-200.com", "api.asmr-100.com"];

// 单节点超时熔断时间（毫秒）
const TIMEOUT_LIMIT = 3500;

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get("Origin") || "*";

    // 1. CORS 预检处理（对齐官方镜像规范）
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Allow-Credentials": "true",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    const url = new URL(request.url);
    const isGet = request.method === "GET";
    const isHead = request.method === "HEAD";

    // 2. 判定可安全边缘缓存的公开元数据
    const isPublicStatic = (isGet || isHead) && (
      url.pathname.includes("/api/work/") ||
      url.pathname.includes("/api/tracks/") ||
      url.pathname.startsWith("/api/tags") ||
      url.pathname.startsWith("/api/circles") ||
      url.pathname.includes("/covers/") ||
      url.pathname.endsWith(".jpg") ||
      url.pathname.endsWith(".png") ||
      url.pathname.endsWith(".webp")
    );

    // 3. 利用 Cloudflare Cache API 绕过 Authorization 穿透
    const cache = caches.default;
    const cacheKey = new Request(url.toString(), { method: "GET" });

    if (isPublicStatic) {
      const cachedResponse = await cache.match(cacheKey);
      if (cachedResponse) {
        const hitHeaders = new Headers(cachedResponse.headers);
        hitHeaders.set("X-Worker-Cache", "HIT");
        hitHeaders.set("Access-Control-Allow-Origin", origin);
        hitHeaders.set("Access-Control-Allow-Credentials", "true");
        return new Response(cachedResponse.body, {
          status: cachedResponse.status,
          statusText: cachedResponse.statusText,
          headers: hitHeaders,
        });
      }
    }

    // 4. 构建转发头
    const cleanHeaders = new Headers(request.headers);
    cleanHeaders.set("Connection", "keep-alive");

    [
      "cf-connecting-ip",
      "cf-ipcountry",
      "cf-ray",
      "cf-visitor",
      "x-forwarded-for",
      "x-real-ip"
    ].forEach((h) => cleanHeaders.delete(h));

    if (request.headers.has("range")) {
      cleanHeaders.set("range", request.headers.get("range"));
    }

    const requestBody = (isGet || isHead) ? null : await request.arrayBuffer();
    const candidateHosts = [PRIMARY_UPSTREAM, ...BACKUP_UPSTREAMS];
    let lastError = null;

    // 5. 故障切换轮询
    for (const host of candidateHosts) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_LIMIT);

      try {
        const targetUrl = new URL(request.url);
        targetUrl.protocol = "https:";
        targetUrl.host = host;
        targetUrl.port = "";

        cleanHeaders.set("Host", host);
        cleanHeaders.set("Referer", `https://${host}/`);
        cleanHeaders.set("Origin", `https://${host}`);

        const fetchOptions = {
          method: request.method,
          headers: cleanHeaders,
          body: requestBody,
          redirect: "follow",
          signal: controller.signal,
        };

        const response = await fetch(targetUrl.toString(), fetchOptions);
        clearTimeout(timeoutId);

        if ([502, 503, 504].includes(response.status)) {
          lastError = new Error(`Host ${host} returned ${response.status}`);
          continue;
        }

        // 6. 构造响应头
        const responseHeaders = new Headers(response.headers);
        responseHeaders.set("Access-Control-Allow-Origin", origin);
        responseHeaders.set("Access-Control-Allow-Credentials", "true");
        responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
        responseHeaders.set("Access-Control-Allow-Headers", "*");
        responseHeaders.set(
          "Access-Control-Expose-Headers",
          "Content-Length, Content-Range, Accept-Ranges, Content-Type"
        );

        if (response.headers.has("accept-ranges")) {
          responseHeaders.set("Accept-Ranges", response.headers.get("accept-ranges"));
        }

        responseHeaders.delete("content-security-policy");
        responseHeaders.delete("content-security-policy-report-only");

        // 7. 写入边缘缓存
        if (isPublicStatic && response.status === 200) {
          responseHeaders.set("Cache-Control", "public, max-age=86400, s-maxage=86400");
          responseHeaders.set("X-Worker-Cache", "MISS");

          const responseToCache = new Response(response.clone().body, {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders,
          });

          ctx.waitUntil(cache.put(cacheKey, responseToCache));
        } else {
          responseHeaders.set("Cache-Control", "no-cache, no-store, must-revalidate");
        }

        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
        });
      } catch (err) {
        clearTimeout(timeoutId);
        lastError = err;
      }
    }

    return new Response(`All upstream endpoints unreachable: ${lastError?.message}`, {
      status: 504,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  },
};
