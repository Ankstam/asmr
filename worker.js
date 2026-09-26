export default {
  async fetch(request, env, ctx) {
    // 1. 处理浏览器跨域预检请求 (CORS preflight)
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

    // 2. 映射目标上游为 asmr.one
    const upstreamHost = "asmr.one";
    const targetUrl = new URL(request.url);
    targetUrl.protocol = "https:";
    targetUrl.host = upstreamHost;
    targetUrl.port = "";

    // 3. 重写与清洗请求头
    const newHeaders = new Headers(request.headers);
    newHeaders.set("Host", upstreamHost);
    newHeaders.set("Referer", `https://${upstreamHost}/`);
    newHeaders.set("Origin", `https://${upstreamHost}`);

    // 清洗可能引起上游 CDN 递归检测或拦截的特有请求头
    const hopHeaders = [
      "cf-connecting-ip",
      "cf-ipcountry",
      "cf-ray",
      "cf-visitor",
      "x-forwarded-for",
      "x-real-ip"
    ];
    for (const h of hopHeaders) {
      newHeaders.delete(h);
    }

    // 传递音频分段请求头（保证进度条随意拖动）
    if (request.headers.has("range")) {
      newHeaders.set("range", request.headers.get("range"));
    }

    try {
      // 4. 发送流式请求
      const response = await fetch(targetUrl.toString(), {
        method: request.method,
        headers: newHeaders,
        body: ["GET", "HEAD"].includes(request.method) ? null : request.body,
        redirect: "follow",
      });

      // 5. 组装响应头
      const responseHeaders = new Headers(response.headers);
      responseHeaders.set("Access-Control-Allow-Origin", "*");
      responseHeaders.set("Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS");
      responseHeaders.set("Access-Control-Allow-Headers", "*");
      responseHeaders.set(
        "Access-Control-Expose-Headers",
        "Content-Length, Content-Range, Accept-Ranges, Content-Type"
      );

      if (response.headers.has("accept-ranges")) {
        responseHeaders.set("Accept-Ranges", response.headers.get("accept-ranges"));
      }

      // 移除原有的 CSP 策略，防止本地前端渲染被阻断
      responseHeaders.delete("content-security-policy");
      responseHeaders.delete("content-security-policy-report-only");

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (err) {
      return new Response(`Proxy Error: ${err.message}`, {
        status: 502,
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    }
  },
};
