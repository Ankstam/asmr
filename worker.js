const PRIMARY_UPSTREAM = "api.asmr.one";
const BACKUP_UPSTREAMS = ["api.asmr-200.com", "api.asmr-100.com"];

// 阶梯竞速阈值：主站 800ms 未响应即自动唤醒备用站并发拉取
const RACE_DELAY = 800;
// 单请求全局硬超时
const MAX_TIMEOUT = 4000;

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get("Origin") || "*";

    // 1. CORS 跨域预检
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

    // 2. 动静路由分流判定
    const isWorkOrTrack = url.pathname.includes("/api/work/") || url.pathname.includes("/api/tracks/");
    const isStaticAsset = (
      url.pathname.includes("/covers/") ||
      url.pathname.endsWith(".jpg") ||
      url.pathname.endsWith(".png") ||
      url.pathname.endsWith(".webp")
    );
    // 广东移动网络优化：列表与标签走 180 秒微缓存，规避基站频繁重连
    const isListView = (
      url.pathname === "/api/works" ||
      url.pathname.startsWith("/api/tags") ||
      url.pathname.startsWith("/api/circles")
    );

    const isCacheable = (isGet || isHead) && (isWorkOrTrack || isStaticAsset || isListView);

    // 3. 边缘 Cache API 与 304 短路协商
    const cache = caches.default;
    const cacheKey = new Request(url.toString(), { method: "GET" });

    if (isCacheable) {
      const cachedResponse = await cache.match(cacheKey);
      if (cachedResponse) {
        const clientEtag = request.headers.get("If-None-Match");
        const cachedEtag = cachedResponse.headers.get("ETag");

        if (clientEtag && cachedEtag && clientEtag === cachedEtag) {
          return new Response(null, {
            status: 304,
            headers: {
              "ETag": cachedEtag,
              "Access-Control-Allow-Origin": origin,
              "Access-Control-Allow-Credentials": "true",
              "Cache-Control": cachedResponse.headers.get("Cache-Control") || "public, max-age=180",
            },
          });
        }

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

    // 4. 清理请求头
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

    // 5. 单节点请求封装
    const fetchFromUpstream = async (host, signal) => {
      const targetUrl = new URL(request.url);
      targetUrl.protocol = "https:";
      targetUrl.host = host;
      targetUrl.port = "";

      const headers = new Headers(cleanHeaders);
      headers.set("Host", host);
      headers.set("Referer", `https://${host}/`);
      headers.set("Origin", `https://${host}`);

      const res = await fetch(targetUrl.toString(), {
        method: request.method,
        headers: headers,
        body: requestBody,
        redirect: "follow",
        signal: signal,
      });

      if ([502, 503, 504].includes(res.status)) {
        throw new Error(`Upstream ${host} status: ${res.status}`);
      }
      return res;
    };

    // 6. 阶梯竞速机制 (Happy Eyeballs)
    let response;
    const globalAbort = new AbortController();
    const hardTimeout = setTimeout(() => globalAbort.abort(), MAX_TIMEOUT);

    try {
      const primaryPromise = fetchFromUpstream(PRIMARY_UPSTREAM, globalAbort.signal);

      const delayRace = new Promise((resolve) => setTimeout(resolve, RACE_DELAY)).then(() => {
        return fetchFromUpstream(BACKUP_UPSTREAMS[0], globalAbort.signal);
      });

      response = await Promise.race([
        primaryPromise,
        primaryPromise.catch(() => delayRace),
      ]);
    } catch (err) {
      try {
        response = await fetchFromUpstream(BACKUP_UPSTREAMS[1], globalAbort.signal);
      } catch (finalErr) {
        clearTimeout(hardTimeout);
        return new Response(`All upstream endpoints failed: ${finalErr.message}`, {
          status: 504,
          headers: { "Content-Type": "text/plain; charset=utf-8" },
        });
      }
    } finally {
      clearTimeout(hardTimeout);
    }

    // 7. 组装响应头
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set("Access-Control-Allow-Origin", origin);
    responseHeaders.set("Access-Control-Allow-Credentials", "true");
    responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
    responseHeaders.set("Access-Control-Allow-Headers", "*");
    responseHeaders.set(
      "Access-Control-Expose-Headers",
      "Content-Length, Content-Range, Accept-Ranges, Content-Type, ETag"
    );

    if (response.headers.has("accept-ranges")) {
      responseHeaders.set("Accept-Ranges", response.headers.get("accept-ranges"));
    }

    responseHeaders.delete("content-security-policy");
    responseHeaders.delete("content-security-policy-report-only");

    // 8. 响应体改写（将官方域名外链洗白为反代域名）
    const contentType = response.headers.get("content-type") || "";
    let finalBody = response.body;

    if (response.status === 200 && contentType.includes("application/json")) {
      let text = await response.text();
      text = text.replaceAll("https://api.asmr.one", `https://${url.host}`);
      text = text.replaceAll("https://www.asmr.one", `https://${url.host}`);
      finalBody = text;
    }

    // 9. 边缘缓存写入
    if (isCacheable && response.status === 200) {
      // 详情与静态资源 24 小时，列表 180 秒
      const maxAge = (isWorkOrTrack || isStaticAsset) ? 86400 : 180;
      responseHeaders.set(
        "Cache-Control",
        `public, max-age=${maxAge}, s-maxage=${maxAge}, stale-while-revalidate=60`
      );
      responseHeaders.set("X-Worker-Cache", "MISS");

      const responseToCache = new Response(finalBody, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });

      ctx.waitUntil(cache.put(cacheKey, responseToCache.clone()));
      return responseToCache;
    } else {
      responseHeaders.set("Cache-Control", "no-cache, no-store, must-revalidate");
      return new Response(finalBody, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    }
  },
};
