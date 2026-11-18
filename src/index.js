import { decode } from '@msgpack/msgpack';

const POLICY_BIN_URL = "https://raw.githubusercontent.com/realeteryu/dns-blocklists/refs/heads/main/output/doh_policy.msgpack";

const DEFAULT_UPSTREAM = "https://cloudflare-dns.com/dns-query";
const CACHE_TTL = 3600 * 1000;
const ERROR_RETRY_TTL = 5 * 60 * 1000;
const UPSTREAM_TIMEOUT = 8000;
const MAX_DNS_SIZE = 4096;

let blocklistSet = new Set();
let allowlistSet = new Set();

let nextRefreshTime = 0;
let loadPromise = null;

const textDecoder = new TextDecoder();

function normalizeDomain(domain) {
  if (typeof domain !== "string") return "";

  return domain.trim().toLowerCase().replace(/\.$/, "");
}

function decodeDomainList(list, name, allowEmpty = false) {
  if (!Array.isArray(list)) {
    throw new Error(`${name}: nieprawidłowy format listy`);
  }

  const domains = new Set();

  for (const item of list) {
    if (typeof item !== "string") {
      throw new Error(`${name}: wpis nie jest tekstem`);
    }

    const domain = normalizeDomain(item);

    if (
      !domain ||
      domain.length > 253 ||
      domain.split(".").length < 2 ||
      domain.split(".").some(
        label =>
          !label ||
          label.length > 63 ||
          !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
      )
    ) {
      throw new Error(`${name}: nieprawidłowa domena: ${item}`);
    }

    if (domain !== item) {
      throw new Error(`${name}: domena nie jest znormalizowana: ${item}`);
    }

    if (domains.has(domain)) {
      throw new Error(`${name}: powtórzona domena: ${domain}`);
    }

    domains.add(domain);
  }

  if (!allowEmpty && domains.size === 0) {
    throw new Error(`${name}: lista jest pusta`);
  }

  return domains;
}

function decodePolicy(buffer, name) {
  const decoded = decode(new Uint8Array(buffer));

  if (
    !decoded ||
    typeof decoded !== "object" ||
    Array.isArray(decoded)
  ) {
    throw new Error(`${name}: nieprawidłowa struktura polityki`);
  }

  const keys = Object.keys(decoded).sort();

  if (
    keys.length !== 2 ||
    keys[0] !== "allowlist" ||
    keys[1] !== "blocklist"
  ) {
    throw new Error(`${name}: polityka musi zawierać tylko blocklist i allowlist`);
  }

  const blocks = decodeDomainList(
    decoded.blocklist,
    `${name} blocklist`
  );

  const allows = decodeDomainList(
    decoded.allowlist,
    `${name} allowlist`,
    true
  );

  validateLists(blocks, allows);

  return { blocks, allows };
}

function validateLists(blocks, allows) {
  for (const domain of allows) {
    if (blocks.has(domain)) {
      throw new Error(
        `Konflikt list: ${domain} znajduje się na obu listach`
      );
    }
  }
}

async function loadBlocklist(env) {
  if (loadPromise) return loadPromise;

  loadPromise = (async () => {
    const now = Date.now();

    if (now < nextRefreshTime) return;

    // 1. Próba pobrania połączonej polityki z Cloudflare KV.
    try {
      if (env?.DNS_KV) {
        const policyBuffer = await env.DNS_KV.get("policy_bin", {
          type: "arrayBuffer",
          cacheTtl: 60,
        });

        if (!policyBuffer) {
          throw new Error("Brak polityki w Cloudflare KV");
        }

        const { blocks, allows } = decodePolicy(
          policyBuffer,
          "KV policy"
        );

        // Podmieniamy obie listy dopiero po pełnej walidacji.
        blocklistSet = blocks;
        allowlistSet = allows;

        nextRefreshTime = now + CACHE_TTL;

        console.log(
          `KV: ${blocks.size} blokad, ${allows.size} wyjątków`
        );

        return;
      }
    } catch (err) {
      console.error("KV:", err);
    }

    // 2. Fallback: połączona polityka z GitHub.
    try {
      const response = await fetch(POLICY_BIN_URL, {
        headers: { "User-Agent": "doh-worker/1.0" },
      });

      if (!response.ok) {
        throw new Error(`GitHub policy HTTP ${response.status}`);
      }

      const policyBuffer = await response.arrayBuffer();

      if (policyBuffer.byteLength === 0) {
        throw new Error("GitHub policy: pobrany plik jest pusty");
      }

      const { blocks, allows } = decodePolicy(
        policyBuffer,
        "GitHub policy"
      );

      blocklistSet = blocks;
      allowlistSet = allows;

      nextRefreshTime = now + CACHE_TTL;

      console.log(
        `GitHub: ${blocks.size} blokad, ${allows.size} wyjątków`
      );
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

function isBlocked(domain) {
  const clean = normalizeDomain(domain);

  if (!clean) return false;

  const labels = clean.split(".");

  // Sprawdzamy od najbardziej szczegółowej domeny
  // do domeny nadrzędnej. Pierwsza znaleziona reguła wygrywa.
  for (let index = 0; index < labels.length - 1; index++) {
    const candidate = labels.slice(index).join(".");

    if (allowlistSet.has(candidate)) {
      return false;
    }

    if (blocklistSet.has(candidate)) {
      return true;
    }
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

      if (len > 63) break;

      offset++;

      if (offset + len > buffer.byteLength) break;

      parts.push(
        textDecoder.decode(buffer.subarray(offset, offset + len))
      );

      offset += len;
    }

    return parts.join(".");
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

    if ((l & 0xC0) !== 0) return -1;

    if (l > 63) return -1;

    offset += 1 + l;

    if (offset > len) return -1;
  }

  return -1;
}

function buildNxdomainWireFormat(buf) {
  const fallback = () => {
    const f = new Uint8Array([
      0, 0, 0x81, 0x83,
      0, 0, 0, 0,
      0, 0, 0, 0,
    ]);

    if (buf && buf.byteLength >= 2) {
      f[0] = buf[0];
      f[1] = buf[1];
    }

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

  out[6] = 0;
  out[7] = 0;
  out[8] = 0;
  out[9] = 0;

  return out;
}

function buildServfailWireFormat(buf) {
  const fallback = () => {
    const f = new Uint8Array([
      0, 0, 0x81, 0x82,
      0, 0, 0, 0,
      0, 0, 0, 0,
    ]);

    if (buf && buf.byteLength >= 2) {
      f[0] = buf[0];
      f[1] = buf[1];
    }

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

  out[6] = 0;
  out[7] = 0;
  out[8] = 0;
  out[9] = 0;

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
  const timeout = setTimeout(
    () => ctrl.abort(),
    UPSTREAM_TIMEOUT
  );

  try {
    return await fetch(
      upstreamUrl + new URL(request.url).search,
      {
        method: request.method,
        headers,
        body: isPost ? queryBuffer : null,
        signal: ctrl.signal,
      }
    );
  } finally {
    clearTimeout(timeout);
  }
}

export default {
  // Cron okresowo odświeża politykę poza ścieżką żądań DNS.
  async scheduled(controller, env, ctx) {
    await loadBlocklist(env);

    console.log(
      `Cron: polityka odświeżona ${new Date().toISOString()}`
    );
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upstream = env?.UPSTREAM_DOH || DEFAULT_UPSTREAM;

    if (url.pathname === "/") {
      return new Response("doh-worker is running.");
    }

    if (url.pathname !== "/dns-query") {
      return new Response("Not Found", { status: 404 });
    }

    // Pierwsze ładowanie odbywa się przed obsługą zapytania.
    if (blocklistSet.size === 0) {
      await loadBlocklist(env);
    } else if (Date.now() >= nextRefreshTime) {
      ctx.waitUntil(loadBlocklist(env));
    }

    let queryBuffer = null;

    if (request.method === "GET") {
      const dns = url.searchParams.get("dns");

      if (!dns) {
        return new Response(
          "Bad Request: missing dns parameter",
          { status: 400 }
        );
      }

      try {
        let b64 = dns.replace(/-/g, "+").replace(/_/g, "/");

        while (b64.length % 4) {
          b64 += "=";
        }

        const bin = atob(b64);

        queryBuffer = new Uint8Array(bin.length);

        for (let i = 0; i < bin.length; i++) {
          queryBuffer[i] = bin.charCodeAt(i);
        }
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

    if (queryBuffer.byteLength > MAX_DNS_SIZE) {
      return new Response("DNS query too large", { status: 400 });
    }

    if (queryBuffer.byteLength < 12) {
      return new Response("Bad Request: invalid DNS message", {
        status: 400,
      });
    }

    const domainName = extractDomainFromDNS(queryBuffer);

    if (domainName && isBlocked(domainName)) {
      return new Response(
        buildNxdomainWireFormat(queryBuffer),
        {
          headers: {
            "Content-Type": "application/dns-message",
            "Cache-Control": "public, max-age=300",
          },
        }
      );
    }

    try {
      return await fetchUpstream(
        upstream,
        request,
        queryBuffer
      );
    } catch (err) {
      console.error("upstream:", err);

      return new Response(
        buildServfailWireFormat(queryBuffer),
        {
          headers: {
            "Content-Type": "application/dns-message",
            "Cache-Control": "no-store",
          },
        }
      );
    }
  },
};
