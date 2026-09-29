/**
 * ASMR Proxy & Edge Security Acceleration Worker
 *
 * 适用域名:
 *   asmr.1010088.xyz
 *
 * 核心设计:
 *
 * 1. Request Body 预先读取为 ArrayBuffer
 *    解决 POST/PUT/PATCH 等请求故障切换时 Request Body 被消费的问题。
 *
 * 2. 4 组上游顺序故障切换
 *    单源超时 3000ms。
 *
 * 3. 严格路径白名单
 *    只允许 /api/ 与 /media/。
 *
 * 4. 搜索 / 标签 / 关键词 / 用户接口默认不缓存
 *    防止代理缓存导致数据与主站不同步。
 *
 * 5. 带 Cookie / Authorization 的请求绝不进入公共缓存。
 *
 * 6. 只有明确加入 CACHEABLE_PATH_PREFIXES 的公开 GET 接口才允许缓存。
 *
 * 7. Range / Media 请求直接回源，不使用 Worker Cache API。
 *
 * 8. 清洗部分上游响应技术 Header。
 *
 * 9. CORS 预检直接在 Worker 边缘返回。
 */

// ============================================================
// 1. 核心配置
// ============================================================

const CONFIG = {

  // ----------------------------------------------------------
  // 上游服务器
  // 按优先级顺序进行故障切换
  // ----------------------------------------------------------
  UPSTREAMS: [
    'https://api.asmr-200.com',
    'https://api.asmr.one',
    'https://api.asmr-100.com',
    'https://api.asmr-300.com'
  ],

  // ----------------------------------------------------------
  // 单个上游请求最大等待时间
  // ----------------------------------------------------------
  TIMEOUT_MS: 3000,

  // ----------------------------------------------------------
  // 严格允许访问的路径
  // 不在这些前缀中的请求直接 404，不回源
  // ----------------------------------------------------------
  ALLOWED_PATH_PREFIXES: [
    '/api/',
    '/media/'
  ],

  // ----------------------------------------------------------
  // 允许进入 Cache API 的公开接口
  //
  // 非常重要：
  //
  // 这里默认留空。
  //
  // 也就是说：
  // /api/* 默认全部不缓存。
  //
  // 如果以后确认某个 API 是完全公开、与用户身份无关、
  // 且允许短时间数据延迟，再把它加入这里。
  //
  // 例如：
  //
  // CACHEABLE_PATH_PREFIXES: [
  //   '/api/public/',
  //   '/api/categories/'
  // ]
  //
  // 不建议把 /api/search/、/api/tag/、
  // /api/auth/、/api/user/ 等接口放进去。
  // ----------------------------------------------------------
  CACHEABLE_PATH_PREFIXES: [],

  // ----------------------------------------------------------
  // 明确禁止缓存的动态接口关键词
  //
  // 即使以后 CACHEABLE_PATH_PREFIXES 配得比较宽，
  // 这些接口仍然会强制 BYPASS。
  // ----------------------------------------------------------
  NEVER_CACHE_PATH_KEYWORDS: [
    '/search',
    '/search/',
    '/tag',
    '/tag/',
    '/tags',
    '/tags/',
    '/keyword',
    '/keywords',
    '/suggest',
    '/suggest/',
    '/autocomplete',
    '/autocomplete/',
    '/auth',
    '/auth/',
    '/login',
    '/logout',
    '/user',
    '/user/',
    '/users',
    '/users/',
    '/account',
    '/account/',
    '/profile',
    '/profile/',
    '/me',
    '/review',
    '/review/',
    '/history',
    '/history/',
    '/favorite',
    '/favorites',
    '/bookmark',
    '/bookmarks'
  ],

  // ----------------------------------------------------------
  // 动态 Query 参数
  //
  // 如果 URL 中出现这些参数，则强制不缓存。
  //
  // 例如：
  //
  // /api/list?page=2
  // /api/search?q=xxx
  // /api/list?keyword=xxx
  //
  // 都不会因为误配置进入缓存。
  // ----------------------------------------------------------
  NEVER_CACHE_QUERY_KEYS: [
    'q',
    'query',
    'keyword',
    'keywords',
    'search',
    'tag',
    'tags',
    'page',
    'pageNo',
    'pageNum',
    'offset',
    'limit',
    'sort',
    'order',
    'filter',
    'category',
    'categories',
    'id',
    'ids'
  ],

  // ----------------------------------------------------------
  // UA 黑名单
  // 这里只做低成本扫描器过滤。
  // 不应把它当成完整 WAF。
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
  // 需要从上游 Response 中删除的 Header
  // ----------------------------------------------------------
  HEADERS_TO_REMOVE: [
    'x-powered-by',
    'x-acc-new',
    'x-cache',
    'server-timing',
    'cf-ray',
    'cf-cache-status'
  ],

  // ----------------------------------------------------------
  // Cache API 缓存时间
  //
  // 当前公开缓存接口才会使用。
  // ----------------------------------------------------------
  CACHE_MAX_AGE: 180,

  CACHE_S_MAXAGE: 180,

  CACHE_STALE_WHILE_REVALIDATE: 60
};


// ============================================================
// 2. Worker 主入口
// ============================================================

export default {

  async fetch(request, env, ctx) {

    const url = new URL(request.url);

    const pathname = url.pathname;

    const userAgent =
      request.headers.get('User-Agent') || '';


    // ========================================================
    // A. User-Agent 基础过滤
    // ========================================================

    if (
      !userAgent ||
      CONFIG.BLOCKED_UA_KEYWORDS.some(keyword =>
        userAgent.toLowerCase().includes(keyword)
      )
    ) {

      return new Response('Access Denied', {
        status: 403,

        headers: {
          'Content-Type':
            'text/plain; charset=utf-8',

          'X-Worker-Cache':
            'BYPASS'
        }
      });
    }


    // ========================================================
    // B. 严格路径白名单
    // ========================================================

    const isAllowedPath =
      CONFIG.ALLOWED_PATH_PREFIXES.some(prefix =>
        pathname.startsWith(prefix)
      );


    if (!isAllowedPath) {

      return new Response('Not Found', {
        status: 404,

        headers: {
          'Content-Type':
            'text/plain; charset=utf-8',

          'X-Worker-Cache':
            'BYPASS'
        }
      });
    }


    // ========================================================
    // C. CORS OPTIONS 预检
    // ========================================================

    if (request.method === 'OPTIONS') {

      return handleCorsPreflight();
    }


    // ========================================================
    // D. Media / Range 请求
    //
    // 绝不进入 Cache API。
    // ========================================================

    const hasRangeHeader =
      request.headers.has('range');

    const isMediaStream =
      pathname.includes('/media/') ||
      pathname.includes('/stream/');


    if (
      hasRangeHeader ||
      isMediaStream
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
    // E. 非 GET 请求
    //
    // POST / PUT / PATCH / DELETE
    // 全部直通，不进入 Cache API。
    // ========================================================

    if (
      request.method !== 'GET' &&
      request.method !== 'HEAD'
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
    // F. HEAD 请求
    //
    // 默认不缓存。
    // ========================================================

    if (request.method === 'HEAD') {

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
    // G. GET 请求缓存判断
    // ========================================================

    const cacheDecision =
      shouldUseCache(request, url);


    // --------------------------------------------------------
    // 不允许缓存
    // --------------------------------------------------------

    if (!cacheDecision.cacheable) {

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
    // H. Cache API
    // ========================================================

    const cache =
      caches.default;


    /*
     * 使用当前完整 URL + Request 创建 Cache Key。
     *
     * 因此 Query String 会参与 Cache Key。
     */
    const cacheKey =
      new Request(
        url.toString(),
        request
      );


    // --------------------------------------------------------
    // 尝试读取缓存
    // --------------------------------------------------------

    const cachedResponse =
      await cache.match(cacheKey);


    if (cachedResponse) {

      const sanitized =
        sanitizeResponse(
          cachedResponse,
          true
        );

      return addWorkerCacheHeader(
        sanitized,
        'HIT'
      );
    }


    // --------------------------------------------------------
    // Cache MISS
    // --------------------------------------------------------

    const originResponse =
      await fetchWithFailover(
        request,
        url
      );


    // --------------------------------------------------------
    // 只有 HTTP 200 才进入 Cache
    // --------------------------------------------------------

    if (
      originResponse.status === 200
    ) {

      const responseToCache =
        originResponse.clone();


      /*
       * 异步写入 Cache。
       *
       * 不阻塞当前用户响应。
       */
      ctx.waitUntil(
        cache.put(
          cacheKey,
          responseToCache
        )
      );
    }


    const freshResponse =
      sanitizeResponse(
        originResponse,
        true
      );


    return addWorkerCacheHeader(
      freshResponse,
      'MISS'
    );
  }
};


// ============================================================
// 3. 判断 GET 是否允许缓存
// ============================================================

function shouldUseCache(request, url) {

  const pathname =
    url.pathname;


  // ----------------------------------------------------------
  // 只有明确配置 CACHEABLE_PATH_PREFIXES 才允许缓存
  // ----------------------------------------------------------

  const explicitlyCacheable =
    CONFIG.CACHEABLE_PATH_PREFIXES.some(
      prefix =>
        pathname.startsWith(prefix)
    );


  if (!explicitlyCacheable) {

    return {
      cacheable: false,
      reason: 'PATH_NOT_CACHEABLE'
    };
  }


  // ----------------------------------------------------------
  // Authorization 存在
  // ----------------------------------------------------------

  if (
    request.headers.has('Authorization')
  ) {

    return {
      cacheable: false,
      reason: 'AUTHORIZATION_PRESENT'
    };
  }


  // ----------------------------------------------------------
  // Cookie 存在
  // ----------------------------------------------------------

  if (
    request.headers.has('Cookie')
  ) {

    return {
      cacheable: false,
      reason: 'COOKIE_PRESENT'
    };
  }


  // ----------------------------------------------------------
  // 客户端主动要求 no-cache / no-store
  // ----------------------------------------------------------

  const requestCacheControl =
    (
      request.headers.get(
        'Cache-Control'
      ) || ''
    ).toLowerCase();


  if (
    requestCacheControl.includes('no-cache') ||
    requestCacheControl.includes('no-store') ||
    requestCacheControl.includes('private')
  ) {

    return {
      cacheable: false,
      reason: 'CLIENT_NO_CACHE'
    };
  }


  // ----------------------------------------------------------
  // 明确禁止缓存的动态接口
  // ----------------------------------------------------------

  const lowerPath =
    pathname.toLowerCase();


  const matchedNeverCachePath =
    CONFIG.NEVER_CACHE_PATH_KEYWORDS.some(
      keyword =>
        lowerPath.includes(
          keyword.toLowerCase()
        )
    );


  if (matchedNeverCachePath) {

    return {
      cacheable: false,
      reason: 'DYNAMIC_PATH'
    };
  }


  // ----------------------------------------------------------
  // 检查 Query 参数
  // ----------------------------------------------------------

  for (
    const key
    of url.searchParams.keys()
  ) {

    const normalizedKey =
      key.toLowerCase();


    const isDynamicQuery =
      CONFIG.NEVER_CACHE_QUERY_KEYS.some(
        blockedKey =>
          normalizedKey ===
          blockedKey.toLowerCase()
      );


    if (isDynamicQuery) {

      return {
        cacheable: false,
        reason: 'DYNAMIC_QUERY'
      };
    }
  }


  // ----------------------------------------------------------
  // 通过所有安全检查
  // ----------------------------------------------------------

  return {
    cacheable: true,
    reason: 'PUBLIC_CACHEABLE'
  };
}


// ============================================================
// 4. 顺序故障切换
// ============================================================

async function fetchWithFailover(
  request,
  url
) {

  let lastError = null;


  // ----------------------------------------------------------
  // Body 预缓冲
  //
  // 防止 POST / PUT / PATCH 等请求在第一次 fetch 后
  // Request Body Stream 被消费，导致后续重试失败。
  // ----------------------------------------------------------

  let bodyBuffer = null;


  if (
    request.method !== 'GET' &&
    request.method !== 'HEAD'
  ) {

    bodyBuffer =
      await request.arrayBuffer();
  }


  // ==========================================================
  // 按优先级顺序访问上游
  // ==========================================================

  for (
    const originBase
    of CONFIG.UPSTREAMS
  ) {

    const targetUrl =
      new URL(
        url.pathname +
        url.search,
        originBase
      );


    // --------------------------------------------------------
    // 构造上游 Headers
    // --------------------------------------------------------

    const upstreamHeaders =
      new Headers(
        request.headers
      );


    // --------------------------------------------------------
    // 明确设置上游 Host
    // --------------------------------------------------------

    upstreamHeaders.set(
      'Host',
      new URL(originBase).host
    );


    // --------------------------------------------------------
    // 删除代理链信息
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
    // 不把 Worker 自己的缓存判断 Header
    // 转给上游
    // --------------------------------------------------------

    upstreamHeaders.delete(
      'X-Worker-Cache'
    );


    // --------------------------------------------------------
    // 超时控制
    // --------------------------------------------------------

    const controller =
      new AbortController();


    const timeoutId =
      setTimeout(
        () => controller.abort(),
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


      clearTimeout(timeoutId);


      // ------------------------------------------------------
      // 上游 5xx
      //
      // 认为当前节点异常，继续下一个节点。
      // ------------------------------------------------------

      if (
        response.status >= 500 &&
        response.status <= 599
      ) {

        continue;
      }


      // ------------------------------------------------------
      // 其他状态：
      //
      // 200
      // 206
      // 301
      // 302
      // 400
      // 401
      // 403
      // 404
      // 429
      // 等等
      //
      // 都直接返回，不盲目切换节点。
      // ------------------------------------------------------

      return sanitizeResponse(
        response,
        false
      );

    } catch (err) {

      clearTimeout(timeoutId);

      lastError =
        err;

      // ------------------------------------------------------
      // 网络异常 / Timeout
      // 继续下一个上游。
      // ------------------------------------------------------

      continue;
    }
  }


  // ==========================================================
  // 所有上游均失败
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

        'X-Worker-Cache':
          'BYPASS'
      }
    }
  );
}


// ============================================================
// 5. Response Header 清洗
// ============================================================

function sanitizeResponse(
  response,
  allowCacheControl = false
) {

  const newHeaders =
    new Headers(
      response.headers
    );


  // ----------------------------------------------------------
  // 删除指定技术 Header
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
    'Content-Length, Content-Range, Accept-Ranges, Content-Type, ETag'
  );

  newHeaders.set(
    'Access-Control-Max-Age',
    '864000'
  );


  // ----------------------------------------------------------
  // 只有真正允许缓存的接口才设置 public Cache-Control
  // ----------------------------------------------------------

  if (
    allowCacheControl &&
    !newHeaders.has('Cache-Control')
  ) {

    newHeaders.set(
      'Cache-Control',

      [
        `public, max-age=${CONFIG.CACHE_MAX_AGE}`,
        `s-maxage=${CONFIG.CACHE_S_MAXAGE}`,
        `stale-while-revalidate=${CONFIG.CACHE_STALE_WHILE_REVALIDATE}`
      ].join(', ')
    );
  }


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
// 6. Worker Cache 状态 Header
// ============================================================

function addWorkerCacheHeader(
  response,
  cacheStatus
) {

  const headers =
    new Headers(
      response.headers
    );


  headers.set(
    'X-Worker-Cache',
    cacheStatus
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
// 7. CORS OPTIONS 预检
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
