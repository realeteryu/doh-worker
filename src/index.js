const BLOCKLIST_URL = "https://raw.githubusercontent.com/realeteryu/dns-blocklists/refs/heads/main/output/doh_combined.txt";
const DEFAULT_UPSTREAM = "https://cloudflare-dns.com/dns-query";
const CACHE_TTL = 3600 * 1000;         // 1 godzina
const ERROR_RETRY_TTL = 5 * 60 * 1000; // 5 minut po błędzie
const UPSTREAM_TIMEOUT = 8000;         // 8 sekund
const MAX_DNS_SIZE = 4096;             // 512 UDP + bufor EDNS0

let blocklistSet = new Set();
let nextRefreshTime = 0;
let loadPromise = null;

function normalizeDomain(d) {
  return d.trim().toLowerCase().replace(/\.$/, '');
}

// Filtruje puste linie i komentarze – chroni przed nadpisaniem bloklisty
function parseBlocklist(text) {
  const set = new Set();
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const c = line.charCodeAt(0);
    if (c === 35 || c === 33) continue;                 // # lub !
    if (c === 47 && line.charCodeAt(1) === 47) continue; // //
    const lower = line.toLowerCase();
    if (lower.charCodeAt(lower.length - 1) === 46) {
      if (lower.length > 1) set.add(lower.slice(0, -1)); // usuń końcową kropkę
    } else {
      set.add(lower);
    }
  }
  return set;
}

async function loadBlocklist(env) {
  // Deduplikacja: równoległe żądania czekają na jedno pobranie
  if (loadPromise) return loadPromise;

  loadPromise = (async () => {
    const now = Date.now();
    if (blocklistSet.size > 0 && now < nextRefreshTime) return;

    // 1. cloudflare kv
    try {
      if (env?.DNS_KV) {
        const data = await env.DNS_KV.get("blocklist", { cacheTtl: 3600 });
        if (data) {
          const set = parseBlocklist(data);
          if (set.size > 0) {
            blocklistSet = set;
            nextRefreshTime = now + CACHE_TTL;
            console.log(`KV: ${set.size} domen.`);
            return;
          }
        }
      }
    } catch (err) {
      console.error("KV:", err);
    }

    // 2. fallback: github
    try {
      const res = await fetch(BLOCKLIST_URL, { headers: { "User-Agent": "doh-worker/1.0" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const set = parseBlocklist(await res.text());
      if (set.size > 0) {
        blocklistSet = set;
        nextRefreshTime = now + CACHE_TTL;
        console.log(`GitHub: ${set.size} domen.`);
      } else {
        nextRefreshTime = now + ERROR_RETRY_TTL;
      }
    } catch (err) {
      console.error("GitHub:", err);
      nextRefreshTime = now + ERROR_RETRY_TTL;
    }
  })();

  try {
    await loadPromise;
  } finally {
    loadPromise = null;
  }
}

function isBlocked(domain, blocklist) {
  const clean = normalizeDomain(domain);
  if (blocklist.has(clean)) return true;
  let dot = clean.indexOf('.');
  while (dot !== -1) {
    if (blocklist.has(clean.substring(dot + 1))) return true;
    dot = clean.indexOf('.', dot + 1);
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
        const ptr = ((len & 0x3F) << 8) | buffer[offset + 1];
        if (ptr >= offset) break;
        offset = ptr;
        continue;
      }
      offset++;
      if (offset + len > buffer.byteLength) break;
      parts.push(decoder.decode(buffer.subarray(offset, offset + len)));
      offset += len;
    }
    return parts.join('.');
  } catch {
    return "";
  }
}

function buildNxdomainWireFormat(buf) {
  const fallback = () => new Uint8Array([0,0,0x81,0x83,0,0,0,0,0,0,0,0]);
  if (!buf || buf.byteLength < 12) return fallback();
  const qdcount = (buf[4] << 8) | buf[5];
  if (qdcount === 0 || buf.byteLength < 17) {
    const f = fallback();
    f[0] = buf[0]; f[1] = buf[1];
    return f;
  }
  const out = new Uint8Array(buf);
  out[2] = (buf[2] & 0x01) | 0x80;
  out[3] = 0x83;
  out[6] = 0; out[7] = 0;
  out[8] = 0; out[9] = 0;
  return out;
}

function buildServfailWireFormat(buf) {
  const fallback = () => new Uint8Array([0,0,0x81,0x82,0,0,0,0,0,0,0,0]);
  if (!buf || buf.byteLength < 12) return fallback();
  const out = new Uint8Array(buf);
  out[2] = (buf[2] & 0x01) | 0x80;
  out[3] = 0x82;
  out[6] = 0; out[7] = 0;
  out[8] = 0; out[9] = 0;
  return out;
}

function buildNxdomainResponseForDomain(domainName, qtype = 1) {
  const clean = normalizeDomain(domainName);
  const encoder = new TextEncoder();
  const labels = [];
  for (const l of clean.split('.')) {
    if (!l) continue;
    const b = encoder.encode(l);
    if (b.length > 0 && b.length <= 63) labels.push(b);
  }
  let qnameLen = 1;
  for (const b of labels) qnameLen += b.length + 1;

  const out = new Uint8Array(12 + qnameLen + 4);
  out[2] = 0x81; out[3] = 0x83;
  out[5] = 0x01;

  let o = 12;
  for (const b of labels) {
    out[o++] = b.length;
    out.set(b, o);
    o += b.length;
  }
  out[o++] = 0;
  out[o++] = (qtype >> 8) & 0xFF;
  out[o++] = qtype & 0xFF;
  out[o++] = 0;
  out[o++] = 1;
  return out;
}

async function fetchUpstream(upstreamUrl, request, queryBuffer) {
  const isPost = request.method === "POST";
  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("cf-connecting-ip");
  headers.delete("cf-ray");
  headers.delete("cf-ipcountry");
  if (!isPost) {
    headers.delete("content-type");
    headers.delete("content-length");
  }

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), UPSTREAM_TIMEOUT);
  try {
    return await fetch(upstreamUrl + new URL(request.url).search, {
      method: request.method,
      headers,
      body: isPost ? queryBuffer : null,
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(t);
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upstream = env?.UPSTREAM_DOH || DEFAULT_UPSTREAM;

    // Ładuj bloklistę tylko gdy pusta lub po TTL
    if (blocklistSet.size === 0) await loadBlocklist(env);
    else if (Date.now() >= nextRefreshTime) ctx.waitUntil(loadBlocklist(env));

    if (url.pathname === "/") return new Response("doh-worker is running.");
    if (url.pathname !== "/dns-query") return new Response("Not Found", { status: 404 });

    let domainName = "";
    let queryBuffer = null;

    if (request.method === "GET") {
      const dns = url.searchParams.get("dns");
      if (dns) {
        try {
          let b64 = dns.replace(/-/g, '+').replace(/_/g, '/');
          while (b64.length % 4) b64 += '=';
          const bin = atob(b64);
          queryBuffer = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) queryBuffer[i] = bin.charCodeAt(i);
        } catch {
          return new Response("Bad Request", { status: 400 });
        }
      } else {
        domainName = url.searchParams.get("name") || "";
      }
    } else if (request.method === "POST") {
      queryBuffer = new Uint8Array(await request.arrayBuffer());
    } else {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { Allow: "GET, POST" },
      });
    }

    if (queryBuffer && queryBuffer.byteLength > MAX_DNS_SIZE)
      return new Response("DNS query too large", { status: 400 });

    if (queryBuffer) domainName = extractDomainFromDNS(queryBuffer);

    if (domainName && isBlocked(domainName, blocklistSet)) {
      const responseBuffer = queryBuffer
        ? buildNxdomainWireFormat(queryBuffer)
        : buildNxdomainResponseForDomain(domainName, parseInt(url.searchParams.get("type")) || 1);

      return new Response(responseBuffer, {
        headers: {
          "Content-Type": "application/dns-message",
          "Cache-Control": "public, max-age=300",
        },
      });
    }

    try {
      return await fetchUpstream(upstream, request, queryBuffer);
    } catch (err) {
      console.error("upstream:", err);
      if (queryBuffer) {
        return new Response(buildServfailWireFormat(queryBuffer), {
          headers: {
            "Content-Type": "application/dns-message",
            "Cache-Control": "no-store",
          },
        });
      }
      return new Response("Bad Gateway", { status: 502 });
    }
  },
};
