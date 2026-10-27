const BLOCKLIST_URL = "https://raw.githubusercontent.com/realeteryu/dns-blocklists/refs/heads/main/output/doh_combined.txt";
const DEFAULT_UPSTREAM = "https://cloudflare-dns.com/dns-query";
const CACHE_TTL = 3600 * 1000;   // 1 godzina
const UPSTREAM_TIMEOUT = 8000;    // 8 sekund

let blocklistSet = new Set();
let lastFetchTime = 0;
let blocklistETag = null;
let isFetching = false; // Zapobiega wielokrotnemu ładowaniu naraz

async function loadBlocklist(env) {
  const now = Date.now();

  if (blocklistSet.size > 0 && (now - lastFetchTime) < CACHE_TTL) {
    return;
  }
  if (isFetching) return;
  isFetching = true;

  try {
    if (env && env.DNS_KV) {
      const kvData = await env.DNS_KV.get("blocklist", { cacheTtl: 3600 });
      if (kvData) {
        // Optymalizacja: unikamy trim() na wielkim stringu
        const lines = kvData.split('\n');
        const newSet = new Set();
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (line) newSet.add(line);
        }
        
        if (newSet.size > 0) {
          blocklistSet = newSet;
          lastFetchTime = now;
          console.log(`Załadowano z KV: ${blocklistSet.size} domen.`);
          return;
        }
      }
    }
  } catch (err) {
    console.error("Błąd odczytu z KV:", err);
  }

  // Fallback GitHub
  try {
    const headers = { "User-Agent": "doh-worker/1.0" };
    if (blocklistETag) headers["If-None-Match"] = blocklistETag;

    const res = await fetch(BLOCKLIST_URL, { headers });

    if (res.status === 304) {
      lastFetchTime = now;
      return;
    }

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const newETag = res.headers.get("ETag");
    if (newETag) blocklistETag = newETag;

    const text = await res.text();
    const lines = text.split('\n');
    const newSet = new Set();
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line) newSet.add(line);
    }

    if (newSet.size > 0) {
      blocklistSet = newSet;
      lastFetchTime = now;
      console.log(`Załadowano z GitHuba: ${blocklistSet.size} domen.`);
    }
  } catch (err) {
    console.error("Błąd podczas pobierania z GitHuba:", err);
    lastFetchTime = now; 
  } finally {
    isFetching = false;
  }
}

function isBlocked(domain, blocklist) {
  let cleanDomain = domain.toLowerCase();
  if (cleanDomain.endsWith('.')) {
    cleanDomain = cleanDomain.slice(0, -1);
  }
  
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
    const decoder = new TextDecoder();

    while (offset < buffer.byteLength && safety < 128) {
      safety++;
      const len = buffer[offset];

      if (len === 0) break;

      if ((len & 0xC0) === 0xC0) {
        if (offset + 1 >= buffer.byteLength) break;
        const pointer = ((len & 0x3F) << 8) | buffer[offset + 1];
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

  if (!requestBuffer || requestBuffer.byteLength < 12) {
    return fallback();
  }

  const qdcount = (requestBuffer[4] << 8) | requestBuffer[5];
  if (qdcount === 0 || requestBuffer.byteLength < 17) {
    const buf = fallback();
    buf[0] = requestBuffer[0];
    buf[1] = requestBuffer[1];
    return buf;
  }

  const responseBuffer = new Uint8Array(requestBuffer.slice(0));
  responseBuffer[2] = (requestBuffer[2] & 0x01) | 0x80;
  responseBuffer[3] = 0x83;
  responseBuffer[6] = 0x00; responseBuffer[7] = 0x00;
  responseBuffer[8] = 0x00; responseBuffer[9] = 0x00;

  return responseBuffer;
}

function buildServfailWireFormat(requestBuffer) {
  const fallback = () => new Uint8Array([
    0x00, 0x00, 0x81, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);

  if (!requestBuffer || requestBuffer.byteLength < 12) {
    return fallback();
  }

  const responseBuffer = new Uint8Array(requestBuffer.slice(0));
  responseBuffer[2] = (requestBuffer[2] & 0x01) | 0x80;
  responseBuffer[3] = 0x82;
  responseBuffer[6] = 0x00; responseBuffer[7] = 0x00;
  responseBuffer[8] = 0x00; responseBuffer[9] = 0x00;

  return responseBuffer;
}

function buildNxdomainResponseForDomain(domainName, qtype = 1) {
  const cleanDomain = domainName.toLowerCase().replace(/\.$/, '');
  const rawLabels = cleanDomain ? cleanDomain.split('.') : [];
  const labels = rawLabels.filter(l => l.length > 0 && l.length <= 63);

  let qnameLen = 1;
  for (const label of labels) {
    qnameLen += label.length + 1;
  }

  const bufferLen = 12 + qnameLen + 4;
  const responseBuffer = new Uint8Array(bufferLen);

  responseBuffer[0] = 0x00; responseBuffer[1] = 0x00;
  responseBuffer[2] = 0x81; responseBuffer[3] = 0x83;
  responseBuffer[4] = 0x00; responseBuffer[5] = 0x01;

  let offset = 12;
  for (const label of labels) {
    responseBuffer[offset] = label.length;
    offset++;
    for (let i = 0; i < label.length; i++) {
      responseBuffer[offset] = label.charCodeAt(i);
      offset++;
    }
  }
  responseBuffer[offset] = 0x00;
  offset++;

  responseBuffer[offset] = (qtype >> 8) & 0xFF;
  responseBuffer[offset + 1] = qtype & 0xFF;
  offset += 2;
  responseBuffer[offset] = 0x00; responseBuffer[offset + 1] = 0x01;

  return responseBuffer;
}

async function fetchUpstream(upstreamUrl, request, queryBuffer) {
  const isPost = request.method === "POST";
  const forwardHeaders = new Headers(request.headers);
  forwardHeaders.delete("host");
  forwardHeaders.delete("cf-connecting-ip");
  forwardHeaders.delete("cf-ray");
  forwardHeaders.delete("cf-ipcountry");

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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upstreamUrl = (env && env.UPSTREAM_DOH) ? env.UPSTREAM_DOH : DEFAULT_UPSTREAM;

    // KLUCZOWA ZMIANA: Nie blokujemy żądania. Ładujemy w tle.
    if (blocklistSet.size === 0) {
      ctx.waitUntil(loadBlocklist(env));
    } else {
      ctx.waitUntil(loadBlocklist(env));
    }

    if (url.pathname === "/") {
      return new Response("doh-worker is running.", { status: 200 });
    }

    if (url.pathname !== "/dns-query") {
      return new Response("Not Found", { status: 404 });
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
      return new Response("Method Not Allowed", { status: 405 });
    }

    if (queryBuffer) {
      domainName = extractDomainFromDNS(queryBuffer);
    }

    // Sprawdzamy tylko jeśli lista jest już załadowana
    if (blocklistSet.size > 0 && domainName && isBlocked(domainName, blocklistSet)) {
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
      return await fetchUpstream(upstreamUrl, request, queryBuffer);
    } catch (err) {
      console.error("Błąd upstreamu:", err);
      
      if (queryBuffer) {
        return new Response(buildServfailWireFormat(queryBuffer), {
          status: 200,
          headers: { "Content-Type": "application/dns-message" }
        });
      }
      
      return new Response("Bad Gateway", { status: 502 });
    }
  }
};
