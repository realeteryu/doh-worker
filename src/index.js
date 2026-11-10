import { decode } from '@msgpack/msgpack';

const BLOCKLIST_BIN_URL = "https://raw.githubusercontent.com/realeteryu/dns-blocklists/refs/heads/main/output/doh_combined.msgpack";
const DEFAULT_UPSTREAM = "https://cloudflare-dns.com/dns-query";
const CACHE_TTL = 3600 * 1000;         // 1 godzina
const ERROR_RETRY_TTL = 5 * 60 * 1000; // 5 minut po błędzie
const UPSTREAM_TIMEOUT = 8000;         // 8 sekund
const MAX_DNS_SIZE = 4096;             // 512 UDP + bufor EDNS0

let blocklistSet = new Set();
let nextRefreshTime = 0;
let loadPromise = null;
const textDecoder = new TextDecoder();

function normalizeDomain(d) {
  return d.trim().toLowerCase().replace(/\.$/, '');
}

async function loadBlocklist(env) {
  // deduplikacja
  if (loadPromise) return loadPromise;

  loadPromise = (async () => {
    const now = Date.now();

    // blokuj ponowne próby w oknie błędu (bez tego: retry storm)
    if (now < nextRefreshTime) return;

    // 1. cloudflare kv (bin)
    try {
      if (env?.DNS_KV) {
        const buffer = await env.DNS_KV.get("blocklist_bin", { type: "arrayBuffer", cacheTtl: 3600 });
        if (buffer) {
          const domains = decode(new Uint8Array(buffer));
          const set = new Set(domains);
          if (set.size > 0) {
            blocklistSet = set;
            nextRefreshTime = now + CACHE_TTL;
            console.log(`KV (bin): ${set.size} domen.`);
            return;
          }
        }
      }
    } catch (err) {
      console.error("KV (bin):", err);
    }

    // 2. fallback: github (bin)
    try {
      const res = await fetch(BLOCKLIST_BIN_URL, { headers: { "User-Agent": "doh-worker/1.0" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const buffer = await res.arrayBuffer();
      const domains = decode(new Uint8Array(buffer));
      const set = new Set(domains);

      if (set.size > 0) {
        blocklistSet = set;
        nextRefreshTime = now + CACHE_TTL;
        console.log(`GitHub (bin): ${set.size} domen.`);
      } else {
        nextRefreshTime = now + ERROR_RETRY_TTL;
      }
    } catch (err) {
      console.error("GitHub (bin):", err);
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
      parts.push(textDecoder.decode(buffer.subarray(offset, offset + len)));
      offset += len;
    }
    return parts.join('.');
  } catch {
    return "";
  }
}

// offset końca sekcji pytania (QNAME + QTYPE + QCLASS) lub -1.
function findQuestionEnd(buf) {
  let offset = 12;
  const len = buf.byteLength;
  let safety = 0;
  while (offset < len && safety < 128) {
    safety++;
    const l = buf[offset];
    if (l === 0) {
      offset++;
      if (offset + 4 > len) return -1;
      return offset + 4;
    }
    if ((l & 0xC0) !== 0) return -1; // kompresja w pytaniu – nieoczekiwane
    offset += 1 + l;
    if (offset > len) return -1;
  }
  return -1;
}

function buildNxdomainWireFormat(buf) {
  const fallback = () => {
    const f = new Uint8Array([0,0,0x81,0x83,0,0,0,0,0,0,0,0]);
    if (buf && buf.byteLength >= 2) { f[0] = buf[0]; f[1] = buf[1]; }
    return f;
  };
  if (!buf || buf.byteLength < 17) return fallback();
  const qdcount = (buf[4] << 8) | buf[5];
  if (qdcount !== 1) return fallback();
  const qEnd = findQuestionEnd(buf);
  if (qEnd === -1) return fallback();
  const out = buf.slice(0, qEnd);
  out[2] = (buf[2] & 0x01) | 0x80;
  out[3] = 0x83;
  out[6] = 0; out[7] = 0;
  out[8] = 0; out[9] = 0;
  return out;
}

function buildServfailWireFormat(buf) {
  const fallback = () => {
    const f = new Uint8Array([0,0,0x81,0x82,0,0,0,0,0,0,0,0]);
    if (buf && buf.byteLength >= 2) { f[0] = buf[0]; f[1] = buf[1]; }
    return f;
  };
  if (!buf || buf.byteLength < 17) return fallback();
  const qdcount = (buf[4] << 8) | buf[5];
  if (qdcount !== 1) return fallback();
  const qEnd = findQuestionEnd(buf);
  if (qEnd === -1) return fallback();
  const out = buf.slice(0, qEnd);
  out[2] = (buf[2] & 0x01) | 0x80;
  out[3] = 0x82;
  out[6] = 0; out[7] = 0;
  out[8] = 0; out[9] = 0;
  return out;
}

async function fetchUpstream(upstreamUrl, request, queryBuffer) {
  const isPost = request.method === "POST";
  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("cf-connecting-ip");
  headers.delete("cf-ray");
  headers.delete("cf-ipcountry");
  headers.delete("x-real-ip");
  headers.delete("cf-visitor");
  headers.delete("connection");
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
  // cron: utrzymuje ciepły isolate i świeżą bloklistę poza ścieżką żądań
  async scheduled(controller, env, ctx) {
    await loadBlocklist(env);
    console.log(`Cron: blocklist refreshed at ${new Date().toISOString()}`);
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upstream = env?.UPSTREAM_DOH || DEFAULT_UPSTREAM;

    if (url.pathname === "/") return new Response("doh-worker is running.");
    if (url.pathname !== "/dns-query") return new Response("Not Found", { status: 404 });

    // pierwsze ładowanie: czekaj (bez tego przeglądarka cache'uje nieprzefiltrowane odpowiedzi)
    // po załadowaniu: odświeżaj w tle
    if (blocklistSet.size === 0) {
      await loadBlocklist(env);
    } else if (Date.now() >= nextRefreshTime) {
      ctx.waitUntil(loadBlocklist(env));
    }

    let queryBuffer = null;

    if (request.method === "GET") {
      const dns = url.searchParams.get("dns");
      if (!dns) return new Response("Bad Request: missing dns parameter", { status: 400 });
      try {
        let b64 = dns.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) b64 += '=';
        const bin = atob(b64);
        queryBuffer = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) queryBuffer[i] = bin.charCodeAt(i);
      } catch {
        return new Response("Bad Request", { status: 400 });
      }
    } else if (request.method === "POST") {
      queryBuffer = new Uint8Array(await request.arrayBuffer());
    } else {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { Allow: "GET, POST" },
      });
    }

    if (queryBuffer.byteLength > MAX_DNS_SIZE)
      return new Response("DNS query too large", { status: 400 });

    const domainName = extractDomainFromDNS(queryBuffer);

    if (domainName && isBlocked(domainName, blocklistSet)) {
      return new Response(buildNxdomainWireFormat(queryBuffer), {
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
      return new Response(buildServfailWireFormat(queryBuffer), {
        headers: {
          "Content-Type": "application/dns-message",
          "Cache-Control": "no-store",
        },
      });
    }
  },
};
