// 锁定官方主站 API
const UPSTREAM_HOST = "api.asmr.one";

export default {
  async fetch(request, env, ctx) {
    // 1. 处理 CORS 跨域
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

    const targetUrl = new URL(request.url);
    targetUrl.protocol = "https:";
    targetUrl.host = UPSTREAM_HOST;
    targetUrl.port = "";

    // 2. 伪装请求头并清洗 Cloudflare 专有标记
    const newHeaders = new Headers(request.headers);
    newHeaders.set("Host", UPSTREAM_HOST);
    newHeaders.set("Referer", `https://${UPSTREAM_HOST}/`);
    newHeaders.set("Origin", `https://${UPSTREAM_HOST}`);

    [
      "cf-connecting-ip",
      "cf-ipcountry",
      "cf-ray",
      "cf-visitor",
      "x-forwarded-for",
      "x-real-ip"
    ].forEach((h) => newHeaders.delete(h));

    if (request.headers.has("range")) {
      newHeaders.set("range", request.headers.get("range"));
    }

    try {
      const response = await fetch(targetUrl.toString(), {
        method: request.method,
        headers: newHeaders,
        body: ["GET", "HEAD"].includes(request.method) ? null : request.body,
        redirect: "follow",
      });

      // 3. 构造完整响应头，保留音频流支持
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
