export function handleDiagnostics(request, blocklistSize) {
  const url = new URL(request.url);
  const clientIP = request.headers.get("CF-Connecting-IP") || "nieznany";
  const country = request.headers.get("CF-IPCountry") || "nieznany";
  
  const diagnostics = {
    status: "ok",
    resolver: "Cloudflare (doh-worker)",
    clientIP: clientIP,
    country: country,
    protocol: "DoH (DNS-over-HTTPS)",
    loadedDomains: blocklistSize,
    server: url.hostname,
    timestamp: new Date().toISOString()
  };

  if (url.pathname === "/test.json") {
    return new Response(JSON.stringify(diagnostics, null, 2), {
      headers: { "Content-Type": "application/json" }
    });
  }

  const html = `<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Status | doh-worker</title>
  <style>
    body { 
      background: #0a0a0a; 
      color: #d4d4d4; 
      font-family: monospace; 
      padding: 24px; 
      line-height: 1.5; 
      font-size: 14px;
    }
    a { color: #3b82f6; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .ok { color: #22c55e; font-weight: bold; }
    hr { border: 0; border-top: 1px dashed #333; margin: 16px 0; }
    pre { margin: 0; white-space: pre-wrap; word-wrap: break-word; }
  </style>
</head>
<body>
  <div style="color: #fff; font-weight: bold;">doh-worker / diagnostics</div>
  <hr>
  <pre><span style="color: #888;">status........:</span> <span class="ok">${diagnostics.status}</span>
<span style="color: #888;">resolver......:</span> ${diagnostics.resolver}
<span style="color: #888;">client_ip.....:</span> ${diagnostics.clientIP}
<span style="color: #888;">country.......:</span> ${diagnostics.country}
<span style="color: #888;">loaded_domains:</span> ${diagnostics.loadedDomains}
<span style="color: #888;">protocol......:</span> ${diagnostics.protocol}
<span style="color: #888;">server........:</span> ${diagnostics.server}
<span style="color: #888;">timestamp.....:</span> ${diagnostics.timestamp}</pre>
  <hr>
  <div>raw_json: <a href="/test.json">/test.json</a></div>
  <br>
  <pre>${JSON.stringify(diagnostics, null, 2)}</pre>
</body>
</html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}
