// 主上游锁定官方主站，配置备用容灾源
const PRIMARY_UPSTREAM = "api.asmr.one";
const BACKUP_UPSTREAMS = ["api.asmr-200.com", "api.asmr-100.com"];

export default {
  async fetch(request, env, ctx) {
    // 1. 跨域预检快速响应（缓存 24 小时减少握手）
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    const url = new URL(request.url);
    const isGet = request.method === "GET";
    const isHead = request.method === "HEAD";

    // 2. 边缘缓存策略判断（元数据、标签、封面文件走边缘加速）
    const isCacheableStatic = isGet && (
      url.pathname.includes("/covers/") ||
      url.pathname.includes("/images/") ||
      url.pathname.endsWith(".jpg") ||
      url.pathname.endsWith(".png") ||
      url.pathname.endsWith(".webp") ||
      url.pathname.startsWith("/api/tags") ||
      url.pathname.startsWith("/api/circles")
    );

    // 3. 构建请求头，剥离高危头并强制复用长连接
    const cleanHeaders = new Headers(request.headers);
    cleanHeaders.set("Host", PRIMARY_UPSTREAM);
    cleanHeaders.set("Referer", `https://${PRIMARY_UPSTREAM}/`);
    cleanHeaders.set("Origin", `https://${PRIMARY_UPSTREAM}`);
    cleanHeaders.set("Connection", "keep-alive");

    [
      "cf-connecting-ip",
      "cf-ipcountry",
      "cf-ray",
      "cf-visitor",
      "x-forwarded-for",
      "x-real-ip"
    ].forEach((h) => cleanHeaders.delete(h));

    // 严格透传 Range 分段请求头以确保音频即点即播
    if (request.headers.has("range")) {
      cleanHeaders.set("range", request.headers.get("range"));
    }

    const candidateHosts = [PRIMARY_UPSTREAM, ...BACKUP_UPSTREAMS];
    let lastError = null;

    // 4. 发起主备节点轮询（带请求超时控制）
    for (const host of candidateHosts) {
      try {
        const targetUrl = new URL(request.url);
        targetUrl.protocol = "https:";
        targetUrl.host = host;
        targetUrl.port = "";

        cleanHeaders.set("Host", host);
        cleanHeaders.set("Referer", `https://${host}/`);
        cleanHeaders.set("Origin", `https://${host}`);

        // 设置边缘请求参数
        const fetchOptions = {
          method: request.method,
          headers: cleanHeaders,
          body: (isGet || isHead) ? null : request.body,
          redirect: "follow",
          cf: isCacheableStatic ? {
            cacheEverything: true,
            cacheTtl: 86400, // 封面与元数据缓存在边缘节点 24 小时
          } : {
            cacheEverything: false,
          },
        };

        const response = await fetch(targetUrl.toString(), fetchOptions);

        // 如果主站出现 502/503/504 错误，快速切换到备选节点
        if ([502, 503, 504].includes(response.status)) {
          lastError = new Error(`Upstream ${host} returned ${response.status}`);
          continue;
        }

        // 5. 拼装优化后的响应头
        const responseHeaders = new Headers(response.headers);
        responseHeaders.set("Access-Control-Allow-Origin": "*");
        responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
        responseHeaders.set("Access-Control-Allow-Headers", "*");
        responseHeaders.set(
          "Access-Control-Expose-Headers",
          "Content-Length, Content-Range, Accept-Ranges, Content-Type"
        );

        if (response.headers.has("accept-ranges")) {
          responseHeaders.set("Accept-Ranges", response.headers.get("accept-ranges"));
        }

        // 针对静态封面资源追加浏览器端强缓存
        if (isCacheableStatic) {
          responseHeaders.set("Cache-Control", "public, max-age=604800, immutable");
        } else {
          responseHeaders.set("Cache-Control", "no-cache, no-store, must-revalidate");
        }

        responseHeaders.delete("content-security-policy");
        responseHeaders.delete("content-security-policy-report-only");

        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
        });
      } catch (err) {
        lastError = err;
      }
    }

    return new Response(`All upstream endpoints unreachable: ${lastError?.message}`, {
      status: 502,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  },
};
