// 官方上游备选池
const UPSTREAM_LIST = [
  "api.asmr-200.com",
  "api.asmr.one",
  "api.asmr-100.com",
  "api.asmr-300.com"
];

export default {
  async fetch(request, env, ctx) {
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

    const requestBody = ["GET", "HEAD"].includes(request.method) ? null : await request.arrayBuffer();
    let lastError = null;

    for (const upstreamHost of UPSTREAM_LIST) {
      try {
        const targetUrl = new URL(request.url);
        targetUrl.protocol = "https:";
        targetUrl.host = upstreamHost;
        targetUrl.port = "";

        const newHeaders = new Headers(request.headers);
        newHeaders.set("Host", upstreamHost);
        newHeaders.set("Referer", `https://${upstreamHost}/`);
        newHeaders.set("Origin", `https://${upstreamHost}`);

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

        if (request.headers.has("range")) {
          newHeaders.set("range", request.headers.get("range"));
        }

        const response = await fetch(targetUrl.toString(), {
          method: request.method,
          headers: newHeaders,
          body: requestBody,
          redirect: "follow",
        });

        if ([502, 503, 504].includes(response.status)) {
          lastError = new Error(`Node ${upstreamHost} returned ${response.status}`);
          continue;
        }

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
        lastError = err;
      }
    }

    return new Response(`All upstream nodes failed. Last error: ${lastError ? lastError.message : "Unknown"}`, {
      status: 502,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  },
};
