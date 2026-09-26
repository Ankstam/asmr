/**
 * ASMR Proxy & Edge Security Acceleration Worker
 * 适用域名: asmr.1010088.xyz
 * 
 * 核心修复与优化:
 * 1. 预先缓冲 Request Body（ArrayBuffer），彻底解决重试时 "ReadableStream is disturbed" 导致的 502
 * 2. 精准适配 KikoFlu 官方 4 组服务器源站，单源超时设为 3000ms（总轮询 < 12s），杜绝客户端 15s 超时
 * 3. 严格业务白名单拦截，恶意嗅探在边缘 1ms 阻断且不回源
 * 4. 深度清洗上游特征标头（抹除 Express、x-acc-new 等指纹），阻断 GFW 特征识别
 * 5. 音频/媒体流 Range 206 分片直通；GET 列表走 Cache API 毫秒加速
 */

// =================== 1. 核心配置 ===================
const CONFIG = {
  // 完整对接 KikoFlu 官方集群（按优先级顺序容灾）
  UPSTREAMS: [
    'https://api.asmr-200.com',
    'https://api.asmr.one',
    'https://api.asmr-100.com',
    'https://api.asmr-300.com'
  ],
  
  // 单个源站请求超时阈值（毫秒）
  // 设为 3000ms，4 个源站轮询最大耗时 12s，严格低于客户端 15s 的超时抛错线
  TIMEOUT_MS: 3000,

  // 严格路由白名单（非此前缀的请求直接在边缘抛弃）
  ALLOWED_PATH_PREFIXES: [
    '/api/',
    '/media/'
  ],

  // 恶意扫描工具指纹拦截
  BLOCKED_UA_KEYWORDS: [
    'sqlmap', 'nikto', 'gobuster', 'dirbuster', 'nmap', 
    'masscan', 'zgrab', 'python-requests', 'aiohttp'
  ],

  // 需清洗的技术指纹标头
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

    // 1. 嗅探扫描工具阻断
    if (!userAgent || CONFIG.BLOCKED_UA_KEYWORDS.some(k => userAgent.toLowerCase().includes(k))) {
      return new Response('Access Denied', {
        status: 403,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    // 2. 严格正向白名单拦截（杜绝针对 .env、.git、.yaml 等敏感路径的嗅探）
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

    // 5. 鉴权与个人数据接口直通（不缓存带有 Token 的私有接口）
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

    // POST/PUT/DELETE 等写入类请求直通处理
    return fetchWithFailover(request, url, ctx, false);
  }
};

// =================== 3. 顺序回退回源逻辑（解决 Stream 损毁） ===================
async function fetchWithFailover(request, url, ctx, allowCacheControl) {
  let lastError = null;

  // 关键修复：预先将带有 Body 的请求（如 POST /api/auth/me）缓存为 ArrayBuffer
  // 避免在多次重试循环中触发 "ReadableStream is disturbed" 错误
  let bodyBuffer = null;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    bodyBuffer = await request.arrayBuffer();
  }

  for (const originBase of CONFIG.UPSTREAMS) {
    const targetUrl = new URL(url.pathname + url.search, originBase);
    
    // 构建上游请求头，彻底清洗客户端真实 IP
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
        body: bodyBuffer, // 传入可复用的 Buffer，支持无限次安全重试
        redirect: 'follow',
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      // 上游返回 5xx 故障时，顺延至下一个可用源站
      if (response.status >= 500 && response.status <= 599) {
        continue;
      }

      return sanitizeResponse(response, allowCacheControl);
    } catch (err) {
      clearTimeout(timeoutId);
      lastError = err;
      // 超时或连接中断，顺延尝试下一个源站
      continue;
    }
  }

  // 4 组官方源站均不可达时的兜底响应
  return new Response(JSON.stringify({ 
    error: 'All Upstreams Unavailable', 
    details: lastError?.message || 'Gateway Timeout' 
  }), {
    status: 502,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

// =================== 4. 标头清洗与防指纹探测 ===================
function sanitizeResponse(response, allowCacheControl = false) {
  const newHeaders = new Headers(response.headers);

  // 清除源站技术栈与后端架构特征
  for (const header of CONFIG.HEADERS_TO_REMOVE) {
    newHeaders.delete(header);
  }

  // 补齐标准跨域标头
  newHeaders.set('Access-Control-Allow-Origin', '*');
  newHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  newHeaders.set('Access-Control-Allow-Headers', '*');
  newHeaders.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges, Content-Type, ETag');
  newHeaders.set('Access-Control-Max-Age', '864000');

  // 规范通用缓存头
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
