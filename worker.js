// worker.js
const PRIMARY_UPSTREAM = "api.asmr.one";
const BACKUP_UPSTREAMS = ["api.asmr-200.com", "api.asmr-100.com"];
const RACE_DELAY = 1000;      // 毫秒：主源响应若超过此阈值，启动第一备用源竞速
const MAX_TIMEOUT = 8000;     // 毫秒：全局硬超时中断

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
    const isGet = request.method === "GET";
    const isHead = request.method === "HEAD";
    const hasRange = request.headers.has("range");

    // 2. 路由与资源类型判定
    const isWorkOrTrack = url.pathname.includes("/api/work/") || url.pathname.includes("/api/tracks/");
    const isStaticAsset = url.pathname.includes("/covers/") || /\.(jpg|png|webp|mp3|m4a|flac)$/i.test(url.pathname);
    const isListView = url.pathname === "/api/works" || url.pathname.startsWith("/api/tags") || url.pathname.startsWith("/api/circles");

    // 含有 Range 的音频分片请求严禁走基础 Cache API，避免破坏断点续传/Seek
    const isCacheable = (isGet || isHead) && !hasRange && (isWorkOrTrack || isStaticAsset || isListView);

    const cache = caches.default;
    const cacheKey = new Request(url.toString(), { method: "GET" });

    // 3. 边缘缓存检索
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

    // 4. 清洗与准备向上游透传的标头
    const cleanHeaders = new Headers(request.headers);
    [
      "cf-connecting-ip",
      "cf-ipcountry",
      "cf-ray",
      "cf-visitor",
      "x-forwarded-for",
      "x-real-ip"
    ].forEach((h) => cleanHeaders.delete(h));

    // 流式透传 Request Body，避免占用 Worker 内存
    const requestBody = (isGet || isHead) ? null : request.body;

    // 单源请求封装（绑定独立中断控制器）
    async function fetchFromHost(host, signal) {
      const targetUrl = new URL(request.url);
      targetUrl.protocol = "https:";
      targetUrl.host = host;
      targetUrl.port = "";

      const upstreamHeaders = new Headers(cleanHeaders);
      upstreamHeaders.set("Host", host);
      upstreamHeaders.set("Referer", `https://${host}/`);
      upstreamHeaders.set("Origin", `https://${host}`);

      const res = await fetch(targetUrl.toString(), {
        method: request.method,
        headers: upstreamHeaders,
        body: requestBody,
        redirect: "follow",
        signal
      });

      if ([502, 503, 504].includes(res.status)) {
        throw new Error(`Upstream ${host} responded with status: ${res.status}`);
      }
      return res;
    }

    // 5. 阶梯式主备竞速调度
    let response;
    const globalAbort = new AbortController();
    const hardTimeout = setTimeout(() => globalAbort.abort(), MAX_TIMEOUT);

    try {
      response = await executeAdaptiveRace(
        PRIMARY_UPSTREAM,
        BACKUP_UPSTREAMS[0],
        RACE_DELAY,
        globalAbort.signal,
        fetchFromHost
      );
    } catch (raceErr) {
      // 主源和第一备用源均失活，切换兜底第二备用源
      try {
        response = await fetchFromHost(BACKUP_UPSTREAMS[1], globalAbort.signal);
      } catch (finalErr) {
        clearTimeout(hardTimeout);
        return new Response(`All upstream endpoints failed: ${finalErr.message}`, {
          status: 504,
          headers: { "Content-Type": "text/plain; charset=utf-8" }
        });
      }
    } finally {
      clearTimeout(hardTimeout);
    }

    // 6. 构造返回标头
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

    // 移除限制跨域加载的 CSP 标头
    responseHeaders.delete("content-security-policy");
    responseHeaders.delete("content-security-policy-report-only");

    const contentType = response.headers.get("content-type") || "";
    let finalBody = response.body;

    // 仅在返回 200 且明确为 JSON 时进行 API 域名重写
    if (response.status === 200 && contentType.includes("application/json")) {
      let text = await response.text();
      text = text.replaceAll("https://api.asmr.one", `https://${url.host}`);
      text = text.replaceAll("https://www.asmr.one", `https://${url.host}`);
      finalBody = text;
    }

    // 7. 写入边缘缓存（排除 206 分片及 Range 请求）
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

/**
 * 阶梯式竞速调度控制器：
 * 主源优先发起；若超过 raceDelay 毫秒未就绪，拉起第一备用源并发竞速。
 * 任一方成功响应即刻中断（Abort）对方，避免子请求泄漏与配额浪费。
 */
async function executeAdaptiveRace(primaryHost, backupHost, raceDelay, parentSignal, fetcher) {
  const primaryCtrl = new AbortController();
  const backupCtrl = new AbortController();

  const onParentAbort = () => {
    primaryCtrl.abort();
    backupCtrl.abort();
  };
  parentSignal.addEventListener("abort", onParentAbort);

  try {
    return await new Promise((resolve, reject) => {
      let settled = false;
      let primaryFailed = false;
      let backupFailed = false;
      let backupTriggered = false;

      const p1 = fetcher(primaryHost, primaryCtrl.signal);

      p1.then((res) => {
        if (!settled) {
          settled = true;
          backupCtrl.abort();
          resolve(res);
        }
      }).catch(() => {
        primaryFailed = true;
        if (!backupTriggered) {
          triggerBackup();
        } else if (backupFailed) {
          reject(new Error("Both Primary and Backup0 failed."));
        }
      });

      const delayTimer = setTimeout(() => {
        if (!settled && !primaryFailed) {
          triggerBackup();
        }
      }, raceDelay);

      function triggerBackup() {
        if (backupTriggered) return;
        backupTriggered = true;

        fetcher(backupHost, backupCtrl.signal)
          .then((res) => {
            if (!settled) {
              settled = true;
              primaryCtrl.abort();
              resolve(res);
            }
          })
          .catch(() => {
            backupFailed = true;
            if (primaryFailed) {
              reject(new Error("Both Primary and Backup0 failed."));
            }
          });
      }
    });
  } finally {
    parentSignal.removeEventListener("abort", onParentAbort);
  }
}
