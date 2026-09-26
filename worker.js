// worker.js
const PRIMARY_UPSTREAM = "api.asmr.one";
const BACKUP_UPSTREAMS = ["api.asmr-200.com", "api.asmr-100.com"];
const FETCH_TIMEOUT = 9000; // 单源回源硬超时

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get("Origin") || "*";

    // 1. 预检请求快速响应
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Allow-Credentials": "true",
          "Access-Control-Max-Age": "86400"
        }
      });
    }

    const url = new URL(request.url);

    // 2. 边缘安全阻断：仅允许合法业务路由，非业务探测直接 404 丢弃，杜绝回源
    const isApi = url.pathname.startsWith("/api/");
    const isCover = url.pathname.startsWith("/covers/");
    const isStaticMedia = /\.(jpg|jpeg|png|webp|gif|mp3|m4a|flac|wav|lrc|txt|json)$/i.test(url.pathname);
    const isFavicon = url.pathname === "/favicon.ico";

    if (!isApi && !isCover && !isStaticMedia && !isFavicon) {
      return new Response("Not Found", {
        status: 404,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }

    const isGet = request.method === "GET";
    const isHead = request.method === "HEAD";
    const hasRange = request.headers.has("range");

    // 3. 路由类型与缓存资格判定
    const isWorkOrTrack = url.pathname.includes("/api/work/") || url.pathname.includes("/api/tracks/");
    const isStaticAsset = isCover || isStaticMedia;
    const isListView = url.pathname === "/api/works" || url.pathname.startsWith("/api/tags") || url.pathname.startsWith("/api/circles") || url.pathname.startsWith("/api/vas");

    // 含有 Range 的音频分片请求严禁写入 Cache API，保障断点续传与拖动进度条
    const isCacheable = (isGet || isHead) && !hasRange && (isWorkOrTrack || isStaticAsset || isListView);

    const cache = caches.default;
    const cacheKey = new Request(url.toString(), { method: "GET" });

    // 4. 检索边缘缓存
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
              "Cache-Control": cachedResponse.headers.get("Cache-Control") || "public, max-age=180"
            }
          });
        }

        const hitHeaders = new Headers(cachedResponse.headers);
        hitHeaders.set("X-Worker-Cache", "HIT");
        hitHeaders.set("Access-Control-Allow-Origin", origin);
        hitHeaders.set("Access-Control-Allow-Credentials", "true");

        return new Response(cachedResponse.body, {
          status: cachedResponse.status,
          statusText: cachedResponse.statusText,
          headers: hitHeaders
        });
      }
    }

    // 5. 标头清洗与上游准备
    const cleanHeaders = new Headers(request.headers);
    [
      "cf-connecting-ip", "cf-ipcountry", "cf-ray", "cf-visitor", 
      "x-forwarded-for", "x-real-ip"
    ].forEach((h) => cleanHeaders.delete(h));

    const requestBody = (isGet || isHead) ? null : request.body;

    // 单源请求封装
    async function fetchWithTimeout(host) {
      const targetUrl = new URL(request.url);
      targetUrl.protocol = "https:";
      targetUrl.host = host;
      targetUrl.port = "";

      const headers = new Headers(cleanHeaders);
      headers.set("Host", host);
      headers.set("Referer", `https://${host}/`);
      headers.set("Origin", `https://${host}`);

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

      try {
        const res = await fetch(targetUrl.toString(), {
          method: request.method,
          headers,
          body: requestBody,
          redirect: "follow",
          signal: controller.signal
        });

        // 遇到服务端故障主动跳过并尝试下一个备用源
        if ([500, 502, 503, 504, 525].includes(res.status)) {
          throw new Error(`Upstream ${host} returned ${res.status}`);
        }
        return res;
      } finally {
        clearTimeout(timer);
      }
    }

    // 6. 顺序容灾回退（平滑 Failover，避免并发过载）
    let response;
    const upstreams = [PRIMARY_UPSTREAM, ...BACKUP_UPSTREAMS];
    let lastError = null;

    for (const host of upstreams) {
      try {
        response = await fetchWithTimeout(host);
        break; // 请求成功立即退出循环
      } catch (err) {
        lastError = err;
      }
    }

    if (!response) {
      return new Response(`All upstream endpoints failed: ${lastError?.message || "Timeout"}`, {
        status: 504,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }

    // 7. 组装返回标头
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

    const contentType = response.headers.get("content-type") || "";
    let finalBody = response.body;

    // 仅在明确为正常 JSON 时改写媒体链接
    if (response.status === 200 && contentType.includes("application/json")) {
      let text = await response.text();
      text = text.replaceAll("https://api.asmr.one", `https://${url.host}`);
      text = text.replaceAll("https://www.asmr.one", `https://${url.host}`);
      finalBody = text;
    }

    // 8. 写入边缘缓存（排除 206 分片及 Range 请求）
    if (isCacheable && response.status === 200) {
      const maxAge = isWorkOrTrack || isStaticAsset ? 86400 : 180;
      responseHeaders.set(
        "Cache-Control",
        `public, max-age=${maxAge}, s-maxage=${maxAge}, stale-while-revalidate=60`
      );
      responseHeaders.set("X-Worker-Cache", "MISS");

      const responseToCache = new Response(finalBody, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      });

      ctx.waitUntil(cache.put(cacheKey, responseToCache.clone()));
      return responseToCache;
    } else {
      if (!responseHeaders.has("Cache-Control")) {
        responseHeaders.set("Cache-Control", "no-cache, no-store, must-revalidate");
      }
      return new Response(finalBody, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      });
    }
  }
};
