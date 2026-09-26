/**
 * ASMR Proxy & Edge Security Acceleration Worker
 * 适用域名: asmr.1010088.xyz
 * 
 * 核心优化特性:
 * 1. 严格业务白名单与漏洞扫描边缘拦截（1ms 阻断且不消耗上游算力）
 * 2. 深度清洗上游特征标头（抹除 Express、x-acc-new 等指纹）
 * 3. 完整对接 KikoFlu 四组官方源站（顺序容灾 Failover）
 * 4. Cache API 边缘加速（分类标签、作品列表毫秒级返回）
 * 5. 音频与流媒体 Range 206 断点分片透传，保障拖动进度条不重置
 */

// =================== 1. 核心配置 ===================
const CONFIG = {
  // KikoFlu 官方集群上游源站列表（按顺序故障转移）
  UPSTREAMS: [
    'https://api.asmr.one',
    'https://api.asmr-100.com',
    'https://api.asmr-200.com',
    'https://api.asmr-300.com'
  ],
  
  // 单个源站请求超时阈值（毫秒）
  // 设为 4500ms，保障多个源站发生故障时仍能在全局超时前平滑切换
  TIMEOUT_MS: 4500,

  // 严格路由白名单（非此前缀的请求直接在边缘抛弃）
  ALLOWED_PATH_PREFIXES: [
    '/api/',
    '/media/'
  ],

  // 恶意扫描工具常见指纹拦截
  BLOCKED_UA_KEYWORDS: [
    'sqlmap', 'nikto', 'gobuster', 'dirbuster', 'nmap', 
    'masscan', 'zgrab', 'python-requests', 'aiohttp'
  ],

  // 需清洗的指纹标头（消除源站后端技术栈特征暴露）
  HEADERS_TO_REMOVE: [
    'x-powered-by',
    'x-acc-new',
    'x-cache',
    'server-timing',
    'cf-ray',
    'cf-cache-status'
  ]
};

// =================== 2. 主逻辑入口 ===================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const userAgent = request.headers.get('User-Agent') || '';

    // 1. 恶意嗅探工具阻断
    if (!userAgent || CONFIG.BLOCKED_UA_KEYWORDS.some(k => userAgent.toLowerCase().includes(k))) {
      return new Response('Access Denied', {
        status: 403,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    // 2. 严格正向白名单拦截（杜绝针对 .env、.git、.yaml、phpinfo 的嗅探）
    const isAllowedPath = CONFIG.ALLOWED_PATH_PREFIXES.some(prefix => pathname.startsWith(prefix));
    if (!isAllowedPath) {
      return new Response('Not Found', {
        status: 404,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    // 3. 处理 OPTIONS 跨域预检
    if (request.method === 'OPTIONS') {
      return handleCorsPreflight();
    }

    // 4. 音频/大文件 Range 分片请求直接透传（绕开 Cache API 限制）
    const hasRangeHeader = request.headers.has('range');
    const isMediaStream = pathname.includes('/media/') || pathname.includes('/stream/');
    if (hasRangeHeader || isMediaStream) {
      return fetchWithFailover(request, url, ctx, false);
    }

    // 5. 鉴权与个人数据接口直通（不缓存带有 Token 的私有交互接口）
    const isAuthOrPrivate = pathname.startsWith('/api/auth/') || pathname.startsWith('/api/review');
    if (isAuthOrPrivate) {
      return fetchWithFailover(request, url, ctx, false);
    }

    // 6. 普通 GET 列表与元数据请求走 Cache API
    if (request.method === 'GET') {
      const cache = caches.default;
      const cacheKey = new Request(url.toString(), request);
      let cachedResponse = await cache.match(cacheKey);

      if (cachedResponse) {
        const sanitized = sanitizeResponse(cachedResponse);
        sanitized.headers.set('X-Worker-Cache', 'HIT');
        return sanitized;
      }

      // 未命中缓存，发起回源请求并写入边缘缓存
      const originResponse = await fetchWithFailover(request, url, ctx, true);
      
      if (originResponse.status === 200) {
        const responseToCache = originResponse.clone();
        ctx.waitUntil(cache.put(cacheKey, responseToCache));
      }

      const freshResponse = sanitizeResponse(originResponse);
      freshResponse.headers.set('X-Worker-Cache', 'MISS');
      return freshResponse;
    }

    // 其他写入类请求（POST/PUT/DELETE 等）直接直通
    return fetchWithFailover(request, url, ctx, false);
  }
};

// =================== 3. 四节点顺序故障转移 ===================
async function fetchWithFailover(request, url, ctx, allowCacheControl) {
  let lastError = null;

  for (const originBase of CONFIG.UPSTREAMS) {
    const targetUrl = new URL(url.pathname + url.search, originBase);
    
    // 构建上游请求头并清洗客户端真实 IP
    const upstreamHeaders = new Headers(request.headers);
    upstreamHeaders.set('Host', new URL(originBase).host);
    upstreamHeaders.delete('cf-connecting-ip');
    upstreamHeaders.delete('x-real-ip');
    upstreamHeaders.delete('x-forwarded-proto');

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.TIMEOUT_MS);

    try {
      const response = await fetch(targetUrl.toString(), {
        method: request.method,
        headers: upstreamHeaders,
        body: request.body,
        redirect: 'follow',
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      // 上游返回 5xx 服务器错误时，顺延尝试下一个备用源站
      if (response.status >= 500 && response.status <= 599) {
        continue;
      }

      return sanitizeResponse(response, allowCacheControl);
    } catch (err) {
      clearTimeout(timeoutId);
      lastError = err;
      continue;
    }
  }

  // 四组官方源站全部不可用时的兜底响应
  return new Response(JSON.stringify({ error: 'All Upstreams Unavailable', details: lastError?.message }), {
    status: 502,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

// =================== 4. 标头清洗与隐蔽脱敏 ===================
function sanitizeResponse(response, allowCacheControl = false) {
  const newHeaders = new Headers(response.headers);

  // 清理全部上游技术特征标头
  for (const header of CONFIG.HEADERS_TO_REMOVE) {
    newHeaders.delete(header);
  }

  // 补齐标准跨域标头
  newHeaders.set('Access-Control-Allow-Origin', '*');
  newHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  newHeaders.set('Access-Control-Allow-Headers', '*');
  newHeaders.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, Content-Type, ETag');
  newHeaders.set('Access-Control-Max-Age', '864000');

  // 规范缓存标头策略
  if (allowCacheControl && !newHeaders.has('Cache-Control')) {
    newHeaders.set('Cache-Control', 'public, max-age=180, s-maxage=180, stale-while-revalidate=60');
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  });
}

// =================== 5. CORS 预检响应 ===================
function handleCorsPreflight() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Max-Age': '864000'
    }
  });
}
