const BLOCKLIST_URL = "https://raw.githubusercontent.com/realeteryu/dns-blocklists/refs/heads/main/output/doh_combined.txt";
const DEFAULT_UPSTREAM = "https://cloudflare-dns.com/dns-query";
const CACHE_TTL = 3600 * 1000;   // 1 godzina
const UPSTREAM_TIMEOUT = 8000;    // 8 sekund

// Awaryjna lista blokad na wypadek braku łączności z GitHubem
const FALLBACK_BLOCKLIST = new Set([
  "doubleclick.net",
  "googlesyndication.com",
  "googleadservices.com",
  "google-analytics.com",
  "googletagmanager.com",
  "facebook.com",
  "facebook.net",
  "fbcdn.net",
  "adservice.google.com",
  "ads.google.com",
  "telemetry.microsoft.com",
  "v10.events.data.microsoft.com"
]);

let blocklistSet = new Set();
let lastFetchTime = 0;
let blocklistETag = null;

async function loadBlocklist() {
  const now = Date.now();

  // Jeśli bloklista jest aktualna – nic nie rób
  if (blocklistSet.size > 0 && (now - lastFetchTime) < CACHE_TTL) {
    return;
  }

  try {
    const headers = { "User-Agent": "doh-worker/1.0" };
    if (blocklistETag) {
      headers["If-None-Match"] = blocklistETag;
    }

    const res = await fetch(BLOCKLIST_URL, { headers });

    if (res.status === 304) {
      // Lista się nie zmieniła – odśwież tylko czas, nie parsuj ponownie
      lastFetchTime = now;
      console.log("Bloklista bez zmian (304), używam poprzedniej wersji.");
      return;
    }

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const newETag = res.headers.get("ETag");
    if (newETag) {
      blocklistETag = newETag;
    }

    const text = await res.text();
    const lines = text.split('\n');
    const newSet = new Set();

    for (let i = 0; i < lines.length; i++) {
      let line = lines[i].trim();
      if (!line || line.startsWith('#')) continue;
      line = line.replace(/^(0\.0\.0\.0|127\.0\.0\.1)\s+/, '').split('#')[0].trim();
      if (line) {
        newSet.add(line.toLowerCase().replace(/\.$/, ''));
      }
    }

    if (newSet.size > 0) {
      blocklistSet = newSet;
      lastFetchTime = now;
      console.log(`Załadowano bloklistę: ${blocklistSet.size} domen.`);
    }
  } catch (err) {
    console.error("Błąd podczas pobierania bloklisty:", err);
    lastFetchTime = now; // zapobiega retry storm przy dłuższej awarii

    if (blocklistSet.size === 0) {
      blocklistSet = FALLBACK_BLOCKLIST;
      console.log("Użyto awaryjnej listy blokad.");
    }
  }
}

// Sprawdzanie blokady hierarchicznie, z uwzględnieniem subdomen
function isBlocked(domain, blocklist) {
  const cleanDomain = domain.toLowerCase().replace(/\.$/, '');
  if (blocklist.has(cleanDomain)) return true;

  const parts = cleanDomain.split('.');
  for (let i = 1; i < parts.length; i++) {
    const parent = parts.slice(i).join('.');
    if (blocklist.has(parent)) return true;
  }
  return false;
}

// Parser domeny z bufora DNS, z obsługą kompresji RFC 1035
function extractDomainFromDNS(buffer) {
  try {
    let offset = 12;
    const parts = [];
    let safety = 0;

    while (offset < buffer.byteLength && safety < 128) {
      safety++;
      const len = buffer[offset];

      if (len === 0) break;

      // Wskaźnik kompresji: dwa górne bity ustawione
      if ((len & 0xC0) === 0xC0) {
        if (offset + 1 >= buffer.byteLength) break;
        const pointer = ((len & 0x3F) << 8) | buffer[offset + 1];
        offset = pointer;
        continue;
      }

      offset++;
      if (offset + len > buffer.byteLength) break;
      const label = new TextDecoder().decode(buffer.subarray(offset, offset + len));
      parts.push(label);
      offset += len;
    }

    return parts.join('.');
  } catch (e) {
    return "";
  }
}

// Odpowiedź NXDOMAIN na podstawie zapytania binarnego
function buildNxdomainWireFormat(requestBuffer) {
  const fallback = () => new Uint8Array([
    0x00, 0x00,
    0x81, 0x83,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00
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
  // QR=1, zachowaj oryginalną flagę RD z requestu
  responseBuffer[2] = (requestBuffer[2] & 0x01) | 0x80;
  responseBuffer[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)
  responseBuffer[6] = 0x00; responseBuffer[7] = 0x00; // ANCOUNT
  responseBuffer[8] = 0x00; responseBuffer[9] = 0x00; // NSCOUNT
  // ARCOUNT zostawiamy bez zmian – sekcja additional (OPT) pozostaje w buforze

  return responseBuffer;
}

// Odpowiedź NXDOMAIN dla zapytań ?name=...
function buildNxdomainResponseForDomain(domainName, qtype = 1) {
  const cleanDomain = domainName.toLowerCase().replace(/\.$/, '');
  const rawLabels = cleanDomain ? cleanDomain.split('.') : [];

  // Walidacja etykiet: 1–63 znaki
  const labels = rawLabels.filter(l => l.length > 0 && l.length <= 63);

  let qnameLen = 1;
  for (const label of labels) {
    qnameLen += label.length + 1;
  }

  const bufferLen = 12 + qnameLen + 4;
  const responseBuffer = new Uint8Array(bufferLen);

  responseBuffer[0] = 0x00;
  responseBuffer[1] = 0x00;
  responseBuffer[2] = 0x81;
  responseBuffer[3] = 0x83;
  responseBuffer[4] = 0x00;
  responseBuffer[5] = 0x01;

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
  responseBuffer[offset] = 0x00;
  responseBuffer[offset + 1] = 0x01;

  return responseBuffer;
}

// Fetch do upstreamu z timeoutem i filtrowaniem nagłówków
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

    // Jeśli bloklista nie jest jeszcze załadowana – czekamy.
    // W przeciwnym razie odświeżamy w tle, żeby nie blokować requestu.
    if (blocklistSet.size === 0) {
      await loadBlocklist();
    } else {
      ctx.waitUntil(loadBlocklist());
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
        headers: {
          "Content-Type": "application/dns-message",
          "Cache-Control": "public, max-age=300"
        }
      });
    }

    try {
      return await fetchUpstream(upstreamUrl, request, queryBuffer);
    } catch (err) {
      console.error("Błąd upstreamu:", err);
      return new Response("Bad Gateway", { status: 502 });
    }
  }
};
