/**
 * ASMR Proxy / Transparent Reverse Proxy Worker
 *
 * 适用域名:
 *   asmr.1010088.xyz
 *
 * 核心目标:
 *
 * 1. 尽可能完整地代理主站请求
 * 2. 不限制 /api/、/media/、/search/、/tag/ 等路径
 * 3. 搜索、标签、关键词、分页、筛选、排序全部允许
 * 4. 默认关闭 Worker Cache API
 * 5. 防止代理缓存造成与主站数据不一致
 * 6. 支持 4 个上游顺序故障切换
 * 7. POST / PUT / PATCH 等请求支持安全重试
 * 8. 支持 Range / 音频 / 大文件
 * 9. 保留 CORS
 * 10. 清洗部分上游响应 Header
 */

// ============================================================
// 1. 核心配置
// ============================================================

const CONFIG = {

  // ----------------------------------------------------------
  // 上游服务器
  // 按顺序进行故障切换
  // ----------------------------------------------------------

  UPSTREAMS: [
    'https://api.asmr-200.com',
    'https://api.asmr.one',
    'https://api.asmr-100.com',
    'https://api.asmr-300.com'
  ],


  // ----------------------------------------------------------
  // 单个上游最大等待时间
  // ----------------------------------------------------------

  TIMEOUT_MS: 3000,


  // ----------------------------------------------------------
  // 是否启用 Worker Cache API
  //
  // 为了保证搜索、标签、关键词等功能与主站一致，
  // 默认关闭。
  //
  // 如以后确认某些接口可以缓存，再单独改造。
  // ----------------------------------------------------------

  ENABLE_CACHE: false,


  // ----------------------------------------------------------
  // 扫描器 UA 过滤
  //
  // 只作为基础过滤，不是完整 WAF。
  // ----------------------------------------------------------

  BLOCKED_UA_KEYWORDS: [
    'sqlmap',
    'nikto',
    'gobuster',
    'dirbuster',
    'nmap',
    'masscan',
    'zgrab',
    'python-requests',
    'aiohttp'
  ],


  // ----------------------------------------------------------
  // 清理上游响应中的部分技术 Header
  // ----------------------------------------------------------

  HEADERS_TO_REMOVE: [
    'x-powered-by',
    'x-acc-new',
    'x-cache',
    'server-timing',
    'cf-ray',
    'cf-cache-status'
  ]

};


// ============================================================
// 2. Worker 主入口
// ============================================================

export default {

  async fetch(request, env, ctx) {

    const url =
      new URL(request.url);


    const pathname =
      url.pathname;


    const userAgent =
      request.headers.get('User-Agent') || '';


    // ========================================================
    // 2.1 基础 User-Agent 过滤
    // ========================================================

    if (
      !userAgent ||
      CONFIG.BLOCKED_UA_KEYWORDS.some(
        keyword =>
          userAgent
            .toLowerCase()
            .includes(keyword)
      )
    ) {

      return new Response(
        'Access Denied',
        {
          status: 403,

          headers: {
            'Content-Type':
              'text/plain; charset=utf-8',

            'X-Worker-Cache':
              'BYPASS'
          }
        }
      );
    }


    // ========================================================
    // 2.2 CORS OPTIONS
    //
    // 不访问上游。
    // ========================================================

    if (
      request.method === 'OPTIONS'
    ) {

      return handleCorsPreflight();
    }


    // ========================================================
    // 2.3 所有路径均允许代理
    //
    // 不再限制:
    //
    // /api/
    // /media/
    // /search/
    // /tag/
    // /tags/
    // /category/
    // /graphql
    // /config
    // 等路径。
    //
    // 这样可以最大程度避免主站新增 API 或前端接口
    // 因为路径白名单导致 404。
    // ========================================================


    // ========================================================
    // 2.4 Media / Range 请求
    //
    // 直接回源。
    // ========================================================

    const hasRangeHeader =
      request.headers.has('range');


    const isMediaRequest =
      pathname.includes('/media/') ||
      pathname.includes('/stream/') ||
      pathname.includes('/audio/') ||
      pathname.includes('/download/');


    if (
      hasRangeHeader ||
      isMediaRequest
    ) {

      const response =
        await fetchWithFailover(
          request,
          url
        );


      return addWorkerCacheHeader(
        response,
        'BYPASS'
      );
    }


    // ========================================================
    // 2.5 GET / HEAD
    //
    // 默认完全直通。
    //
    // 不使用 Cache API。
    //
    // 这样搜索、标签、关键词、分页、筛选、
    // 排序、推荐等动态接口都不会被 Worker 缓存。
    // ========================================================

    if (
      request.method === 'GET' ||
      request.method === 'HEAD'
    ) {

      // ------------------------------------------------------
      // 默认关闭缓存
      // ------------------------------------------------------

      if (
        !CONFIG.ENABLE_CACHE
      ) {

        const response =
          await fetchWithFailover(
            request,
            url
          );


        return addWorkerCacheHeader(
          response,
          'BYPASS'
        );
      }


      // ------------------------------------------------------
      // 如果以后打开 ENABLE_CACHE，
      // 仍然默认直接回源。
      //
      // 这里故意不做自动缓存。
      // ------------------------------------------------------

      const response =
        await fetchWithFailover(
          request,
          url
        );


      return addWorkerCacheHeader(
        response,
        'BYPASS'
      );
    }


    // ========================================================
    // 2.6 POST / PUT / PATCH / DELETE 等
    //
    // 全部直接回源。
    // ========================================================

    const response =
      await fetchWithFailover(
        request,
        url
      );


    return addWorkerCacheHeader(
      response,
      'BYPASS'
    );
  }

};


// ============================================================
// 3. 上游故障切换
// ============================================================

async function fetchWithFailover(
  request,
  url
) {

  let lastError =
    null;


  // ==========================================================
  // 3.1 预读取 Request Body
  //
  // GET / HEAD 不读取 Body。
  //
  // POST / PUT / PATCH / DELETE 等请求，
  // 先转成 ArrayBuffer。
  //
  // 后面切换多个上游时可以重复使用。
  // ==========================================================

  let bodyBuffer =
    null;


  if (
    request.method !== 'GET' &&
    request.method !== 'HEAD'
  ) {

    bodyBuffer =
      await request.arrayBuffer();
  }


  // ==========================================================
  // 3.2 按优先级轮询上游
  // ==========================================================

  for (
    const originBase
    of CONFIG.UPSTREAMS
  ) {

    // --------------------------------------------------------
    // 保留原始 Path + Query
    //
    // 例如:
    //
    // /api/search?q=test&page=2
    //
    // 会原样变成:
    //
    // https://api.asmr-200.com/api/search?q=test&page=2
    // --------------------------------------------------------

    const targetUrl =
      new URL(
        url.pathname +
        url.search,
        originBase
      );


    // --------------------------------------------------------
    // 复制客户端请求 Header
    // --------------------------------------------------------

    const upstreamHeaders =
      new Headers(
        request.headers
      );


    // --------------------------------------------------------
    // 设置当前上游 Host
    // --------------------------------------------------------

    upstreamHeaders.set(
      'Host',
      new URL(originBase).host
    );


    // --------------------------------------------------------
    // 删除这些代理链 Header
    // --------------------------------------------------------

    upstreamHeaders.delete(
      'cf-connecting-ip'
    );

    upstreamHeaders.delete(
      'x-real-ip'
    );

    upstreamHeaders.delete(
      'x-forwarded-proto'
    );


    // --------------------------------------------------------
    // 防止 Worker 自己的调试 Header
    // 被发送给源站
    // --------------------------------------------------------

    upstreamHeaders.delete(
      'X-Worker-Cache'
    );


    // ========================================================
    // 3.3 Timeout
    // ========================================================

    const controller =
      new AbortController();


    const timeoutId =
      setTimeout(
        () => {
          controller.abort();
        },
        CONFIG.TIMEOUT_MS
      );


    try {

      const response =
        await fetch(
          targetUrl.toString(),
          {
            method:
              request.method,

            headers:
              upstreamHeaders,

            body:
              bodyBuffer,

            redirect:
              'follow',

            signal:
              controller.signal
          }
        );


      clearTimeout(
        timeoutId
      );


      // ======================================================
      // 3.4 5xx → 当前上游故障
      //
      // 继续尝试下一个上游。
      // ======================================================

      if (
        response.status >= 500 &&
        response.status <= 599
      ) {

        continue;
      }


      // ======================================================
      // 3.5 其他状态码直接返回
      //
      // 包括:
      //
      // 200
      // 206
      // 301
      // 302
      // 400
      // 401
      // 403
      // 404
      // 405
      // 409
      // 429
      //
      // 不因为这些状态码而错误切换上游。
      // ======================================================

      return sanitizeResponse(
        response
      );

    } catch (err) {

      clearTimeout(
        timeoutId
      );


      lastError =
        err;


      // ------------------------------------------------------
      // Timeout / 网络错误
      // 继续下一个上游。
      // ------------------------------------------------------

      continue;
    }
  }


  // ==========================================================
  // 3.6 所有上游均失败
  // ==========================================================

  return new Response(

    JSON.stringify({

      error:
        'All Upstreams Unavailable',

      details:
        lastError?.message ||
        'Gateway Timeout'

    }),

    {
      status: 502,

      headers: {

        'Content-Type':
          'application/json; charset=utf-8',

        'Access-Control-Allow-Origin':
          '*',

        'Access-Control-Allow-Methods':
          'GET, POST, PUT, DELETE, PATCH, OPTIONS',

        'Access-Control-Allow-Headers':
          '*',

        'X-Worker-Cache':
          'BYPASS'
      }
    }
  );
}


// ============================================================
// 4. Response Header 清洗
// ============================================================

function sanitizeResponse(
  response
) {

  const newHeaders =
    new Headers(
      response.headers
    );


  // ----------------------------------------------------------
  // 删除技术指纹 Header
  // ----------------------------------------------------------

  for (
    const header
    of CONFIG.HEADERS_TO_REMOVE
  ) {

    newHeaders.delete(
      header
    );
  }


  // ----------------------------------------------------------
  // CORS
  // ----------------------------------------------------------

  newHeaders.set(
    'Access-Control-Allow-Origin',
    '*'
  );


  newHeaders.set(
    'Access-Control-Allow-Methods',
    'GET, POST, PUT, DELETE, PATCH, OPTIONS'
  );


  newHeaders.set(
    'Access-Control-Allow-Headers',
    '*'
  );


  newHeaders.set(
    'Access-Control-Expose-Headers',
    [
      'Content-Length',
      'Content-Range',
      'Accept-Ranges',
      'Content-Type',
      'ETag'
    ].join(', ')
  );


  newHeaders.set(
    'Access-Control-Max-Age',
    '864000'
  );


  // ----------------------------------------------------------
  // 注意：
  //
  // 这里不强行修改 Cache-Control。
  //
  // 主站返回什么 Cache-Control，
  // 就尽量保留什么 Cache-Control。
  //
  // Worker 自己也不使用 Cache API。
  // ----------------------------------------------------------


  return new Response(
    response.body,
    {
      status:
        response.status,

      statusText:
        response.statusText,

      headers:
        newHeaders
    }
  );
}


// ============================================================
// 5. Worker Cache 状态
// ============================================================

function addWorkerCacheHeader(
  response,
  status
) {

  const headers =
    new Headers(
      response.headers
    );


  headers.set(
    'X-Worker-Cache',
    status
  );


  return new Response(
    response.body,
    {
      status:
        response.status,

      statusText:
        response.statusText,

      headers
    }
  );
}


// ============================================================
// 6. CORS Preflight
// ============================================================

function handleCorsPreflight() {

  return new Response(
    null,
    {
      status: 204,

      headers: {

        'Access-Control-Allow-Origin':
          '*',

        'Access-Control-Allow-Methods':
          'GET, POST, PUT, DELETE, PATCH, OPTIONS',

        'Access-Control-Allow-Headers':
          '*',

        'Access-Control-Max-Age':
          '864000',

        'X-Worker-Cache':
          'BYPASS'
      }
    }
  );
}
