const BLOCKLIST_URL = "https://raw.githubusercontent.com/realeteryu/dns-blocklists/refs/heads/main/output/doh_combined.txt";
const DEFAULT_UPSTREAM = "https://cloudflare-dns.com/dns-query";
const CACHE_TTL = 3600 * 1000;   // 1 godzina
const ERROR_RETRY_TTL = 5 * 60 * 1000; // 5 minut po błędzie
const UPSTREAM_TIMEOUT = 8000;    // 8 sekund
const MAX_DNS_SIZE = 4096;        // 512 UDP + bufor EDNS0

let blocklistSet = new Set();
let nextRefreshTime = 0;
let blocklistETag = null;
let loadPromise = null;

function normalizeDomain(d) {
  return d.trim().toLowerCase().replace(/\.$/, '');
}

// Filtruje puste linie i komentarze – chroni przed nadpisaniem bloklisty
function parseBlocklist(text) {
  const set = new Set();
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith('#') || line.startsWith('//') || line.startsWith('!')) continue;
    const d = normalizeDomain(line);
    if (d) set.add(d);
  }
  return set;
}

async function loadBlocklist(env) {
  // Deduplikacja: równoległe żądania czekają na jedno pobranie
  if (loadPromise) return loadPromise;

  loadPromise = (async () => {
    const now = Date.now();
    if (blocklistSet.size > 0 && now < nextRefreshTime) return;

    // 1. główne źródło: cloudflare kv
    try {
      if (env && env.DNS_KV) {
        const kvData = await env.DNS_KV.get("blocklist", { cacheTtl: 21600 }); // 6h cache
        if (kvData) {
          const newSet = parseBlocklist(kvData);
          if (newSet.size > 0) {
            blocklistSet = newSet;
            nextRefreshTime = now + CACHE_TTL;
            console.log(`Załadowano z KV: ${blocklistSet.size} domen.`);
            return;
          }
        }
      }
    } catch (err) {
      console.error("Błąd odczytu z KV:", err);
    }

    // 2. fallback: github
    try {
      const headers = { "User-Agent": "doh-worker/1.0" };
      if (blocklistETag) headers["If-None-Match"] = blocklistETag;

      const res = await fetch(BLOCKLIST_URL, { headers });

      if (res.status === 304) {
        nextRefreshTime = now + CACHE_TTL;
        console.log("Bloklista bez zmian (304).");
        return;
      }

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const newETag = res.headers.get("ETag");
      if (newETag) blocklistETag = newETag;

      const text = await res.text();
      const newSet = parseBlocklist(text);

      if (newSet.size > 0) {
        blocklistSet = newSet;
        nextRefreshTime = now + CACHE_TTL;
        console.log(`Załadowano z GitHuba: ${blocklistSet.size} domen.`);
      } else {
        // Pusta lista – nie nadpisuj działającej
        nextRefreshTime = now + ERROR_RETRY_TTL;
      }
    } catch (err) {
      console.error("Błąd podczas pobierania bloklisty z GitHuba:", err);
      nextRefreshTime = now + ERROR_RETRY_TTL;

      if (blocklistSet.size === 0) {
        console.log("Brak dostępnych źródeł blokad. Worker działa w trybie Fail-Open.");
      }
    }
  })();

  try {
    await loadPromise;
  } finally {
    loadPromise = null;
  }
}

function isBlocked(domain, blocklist) {
  const cleanDomain = normalizeDomain(domain);
  if (blocklist.has(cleanDomain)) return true;

  let dotIndex = cleanDomain.indexOf('.');
  while (dotIndex !== -1) {
    const parent = cleanDomain.substring(dotIndex + 1);
    if (blocklist.has(parent)) return true;
    dotIndex = cleanDomain.indexOf('.', dotIndex + 1);
  }
  return false;
}

function extractDomainFromDNS(buffer) {
  try {
    let offset = 12;
    const parts = [];
    let safety = 0;
    // Reużycie TextDecoder dla całej pętli (mniej alokacji)
    const decoder = new TextDecoder();

    while (offset < buffer.byteLength && safety < 128) {
      safety++;
      const len = buffer[offset];

      if (len === 0) break;

      if ((len & 0xC0) === 0xC0) {
        if (offset + 1 >= buffer.byteLength) break;
        const pointer = ((len & 0x3F) << 8) | buffer[offset + 1];
        // Bezpieczeństwo: wskaźnik musi wskazywać na wcześniejszy bajt
        if (pointer >= offset) break;
        offset = pointer;
        continue;
      }

      offset++;
      if (offset + len > buffer.byteLength) break;
      const label = decoder.decode(buffer.subarray(offset, offset + len));
      parts.push(label);
      offset += len;
    }

    return parts.join('.');
  } catch (e) {
    return "";
  }
}

function buildNxdomainWireFormat(requestBuffer) {
  const fallback = () => new Uint8Array([
    0x00, 0x00, 0x81, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);

  if (!requestBuffer || requestBuffer.byteLength < 12) return fallback();

  const qdcount = (requestBuffer[4] << 8) | requestBuffer[5];
  if (qdcount === 0 || requestBuffer.byteLength < 17) {
    const buf = fallback();
    buf[0] = requestBuffer[0];
    buf[1] = requestBuffer[1];
    return buf;
  }

  // Jedna kopia bufora (bez slice)
  const responseBuffer = new Uint8Array(requestBuffer);
  responseBuffer[2] = (requestBuffer[2] & 0x01) | 0x80;
  responseBuffer[3] = 0x83;
  responseBuffer[6] = 0x00; responseBuffer[7] = 0x00;
  responseBuffer[8] = 0x00; responseBuffer[9] = 0x00;
  // ARCOUNT bez zmian – zachowuje OPT/EDNS0

  return responseBuffer;
}

function buildServfailWireFormat(requestBuffer) {
  const fallback = () => new Uint8Array([
    0x00, 0x00, 0x81, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);

  if (!requestBuffer || requestBuffer.byteLength < 12) return fallback();

  const responseBuffer = new Uint8Array(requestBuffer);
  responseBuffer[2] = (requestBuffer[2] & 0x01) | 0x80;
  responseBuffer[3] = 0x82;
  responseBuffer[6] = 0x00; responseBuffer[7] = 0x00;
  responseBuffer[8] = 0x00; responseBuffer[9] = 0x00;

  return responseBuffer;
}

function buildNxdomainResponseForDomain(domainName, qtype = 1) {
  const cleanDomain = normalizeDomain(domainName);
  const rawLabels = cleanDomain ? cleanDomain.split('.') : [];
  // TextEncoder zamiast charCodeAt – poprawne znaki wielobajtowe
  const encoder = new TextEncoder();
  const labels = [];

  for (const l of rawLabels) {
    if (!l) continue;
    const bytes = encoder.encode(l);
    if (bytes.length > 0 && bytes.length <= 63) labels.push(bytes);
  }

  let qnameLen = 1;
  for (const b of labels) qnameLen += b.length + 1;

  const responseBuffer = new Uint8Array(12 + qnameLen + 4);
  responseBuffer[2] = 0x81; responseBuffer[3] = 0x83;
  responseBuffer[5] = 0x01;

  let offset = 12;
  for (const b of labels) {
    responseBuffer[offset++] = b.length;
    responseBuffer.set(b, offset);
    offset += b.length;
  }
  responseBuffer[offset++] = 0x00;
  responseBuffer[offset++] = (qtype >> 8) & 0xFF;
  responseBuffer[offset++] = qtype & 0xFF;
  responseBuffer[offset++] = 0x00;
  responseBuffer[offset++] = 0x01;

  return responseBuffer;
}

async function fetchUpstream(upstreamUrl, request, queryBuffer) {
  const isPost = request.method === "POST";
  const forwardHeaders = new Headers(request.headers);
  forwardHeaders.delete("host");
  forwardHeaders.delete("cf-connecting-ip");
  forwardHeaders.delete("cf-ray");
  forwardHeaders.delete("cf-ipcountry");

  // GET nie ma ciała – usuń nagłówki Content-*
  if (!isPost) {
    forwardHeaders.delete("content-type");
    forwardHeaders.delete("content-length");
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT);

  try {
    return await fetch(upstreamUrl + new URL(request.url).search, {
      method: request.method,
      headers: forwardHeaders,
      body: isPost ? queryBuffer : null,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeoutId);
  }
}

// 1 retry przy 5xx / timeout (4xx zwracamy od razu)
async function fetchUpstreamWithRetry(upstreamUrl, request, queryBuffer, retries = 1) {
  let lastErr;
  for (let i = 0; i <= retries; i++) {
    try {
      const res = await fetchUpstream(upstreamUrl, request, queryBuffer);
      if (res.status < 500) return res;
      lastErr = new Error(`HTTP ${res.status}`);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upstreamUrl = (env && env.UPSTREAM_DOH) ? env.UPSTREAM_DOH : DEFAULT_UPSTREAM;

    // Ładuj bloklistę tylko gdy pusta lub po TTL
    if (blocklistSet.size === 0) {
      await loadBlocklist(env);
    } else if (Date.now() >= nextRefreshTime) {
      ctx.waitUntil(loadBlocklist(env));
    }

    if (url.pathname === "/") {
      return new Response("doh-worker is running.", { status: 200 });
    }

    if (url.pathname !== "/dns-query") {
      return new Response("Not Found", { status: 404 });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: { "Allow": "GET, POST, OPTIONS", "Access-Control-Max-Age": "86400" }
      });
    }

    let domainName = "";
    let queryBuffer = null;

    if (request.method === "GET") {
      const dnsParam = url.searchParams.get("dns");
      if (dnsParam) {
        try {
          let base64 = dnsParam.replace(/-/g, '+').replace(/_/g, '/');
          while (base64.length % 4) base64 += '=';
          const binaryString = atob(base64);
          queryBuffer = new Uint8Array(binaryString.length);
          for (let i = 0; i < binaryString.length; i++) {
            queryBuffer[i] = binaryString.charCodeAt(i);
          }
        } catch (e) {
          return new Response("Bad Request: invalid dns parameter", { status: 400 });
        }
      } else {
        domainName = url.searchParams.get("name") || "";
      }
    } else if (request.method === "POST") {
      const arrayBuffer = await request.arrayBuffer();
      queryBuffer = new Uint8Array(arrayBuffer);
    } else {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { "Allow": "GET, POST, OPTIONS" }
      });
    }

    // Odrzuć zbyt duże zapytania (ochrona pamięci)
    if (queryBuffer && queryBuffer.byteLength > MAX_DNS_SIZE) {
      return new Response("DNS query too large", { status: 400 });
    }

    if (queryBuffer) {
      domainName = extractDomainFromDNS(queryBuffer);
    }

    if (domainName && isBlocked(domainName, blocklistSet)) {
      let responseBuffer;
      if (queryBuffer) {
        responseBuffer = buildNxdomainWireFormat(queryBuffer);
      } else {
        const typeParam = parseInt(url.searchParams.get("type")) || 1;
        responseBuffer = buildNxdomainResponseForDomain(domainName, typeParam);
      }

      return new Response(responseBuffer, {
        status: 200,
        headers: { "Content-Type": "application/dns-message", "Cache-Control": "public, max-age=300" }
      });
    }

    try {
      return await fetchUpstreamWithRetry(upstreamUrl, request, queryBuffer);
    } catch (err) {
      console.error("Błąd upstreamu:", err);

      if (queryBuffer) {
        return new Response(buildServfailWireFormat(queryBuffer), {
          status: 200,
          headers: { "Content-Type": "application/dns-message", "Cache-Control": "no-store" }
        });
      }

      return new Response("Bad Gateway", { status: 502 });
    }
  }
};
