// 主上游锁定官方主站，配置备用源
const PRIMARY_UPSTREAM = "api.asmr.one";
const BACKUP_UPSTREAMS = ["api.asmr-200.com", "api.asmr-100.com"];

// 单节点超时阈值（毫秒）：超过此时间直接换下一个节点，防止客户端转圈卡死
const TIMEOUT_LIMIT = 4000;

export default {
  async fetch(request, env, ctx) {
    // 1. 处理 CORS 跨域预检
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

    // 2. 智能判断可边缘缓存的数据（作品详情、音轨列表、封面图、标签）
    // 动态接口（登录 me、收藏、评论等）严禁缓存
    const isCacheable = (isGet || isHead) && (
      url.pathname.includes("/api/work/") ||
      url.pathname.includes("/api/tracks/") ||
      url.pathname.includes("/api/tags") ||
      url.pathname.includes("/covers/") ||
      url.pathname.endsWith(".jpg") ||
      url.pathname.endsWith(".png") ||
      url.pathname.endsWith(".webp")
    );

    // 3. 构建安全高效的转发头
    const cleanHeaders = new Headers(request.headers);
    cleanHeaders.set("Connection", "keep-alive");

    // 剥离 Cloudflare 内部标记，防止环路风控
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

    // 预读取非 GET 请求体
    const requestBody = (isGet || isHead) ? null : await request.arrayBuffer();
    const candidateHosts = [PRIMARY_UPSTREAM, ...BACKUP_UPSTREAMS];
    let lastError = null;

    // 4. 带超时熔断的多节点轮询
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
          cf: isCacheable ? {
            cacheEverything: true,
            cacheTtl: 14400, // 在 Cloudflare 边缘缓存 4 小时，秒开浏览
          } : {
            cacheEverything: false,
          },
        };

        const response = await fetch(targetUrl.toString(), fetchOptions);
        clearTimeout(timeoutId);

        // 如果节点返回 5xx 服务端故障，立即尝试备选源
        if ([502, 503, 504].includes(response.status)) {
          lastError = new Error(`Node ${host} status ${response.status}`);
          continue;
        }

        // 5. 拼装优化后的客户端响应头
        const responseHeaders = new Headers(response.headers);
        responseHeaders.set("Access-Control-Allow-Origin", "*");
        responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
        responseHeaders.set("Access-Control-Allow-Headers", "*");
        responseHeaders.set(
          "Access-Control-Expose-Headers",
          "Content-Length, Content-Range, Accept-Ranges, Content-Type"
        );

        if (response.headers.has("accept-ranges")) {
          responseHeaders.set("Accept-Ranges", response.headers.get("accept-ranges"));
        }

        if (isCacheable) {
          responseHeaders.set("Cache-Control", "public, max-age=14400, stale-while-revalidate=3600");
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
        clearTimeout(timeoutId);
        lastError = err;
        // 发生超时或连接失败，循环自动进入下一个节点
      }
    }

    return new Response(`All upstream endpoints failed. Last error: ${lastError?.message}`, {
      status: 504,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  },
};
