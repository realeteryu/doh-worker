export function handleDiagnostics(request, blocklistSize) {
  const url = new URL(request.url);
  const clientIP = request.headers.get("CF-Connecting-IP") || "nieznany";
  const country = request.headers.get("CF-IPCountry") || "nieznany";
  
  // Dane diagnostyczne
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

  // Endpoint JSON (np. do skryptów monitorujących)
  if (url.pathname === "/test.json") {
    return new Response(JSON.stringify(diagnostics, null, 2), {
      headers: { "Content-Type": "application/json" }
    });
  }

  // Endpoint HTML
  const html = `<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Status | doh-worker</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
    .card { background: #1e293b; padding: 2rem; border-radius: 1rem; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); max-width: 500px; width: 90%; }
    h1 { color: #38bdf8; margin-top: 0; font-size: 1.5rem; }
    pre { background: #0f172a; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; color: #a5b4fc; font-size: 0.9em; }
    .status { color: #4ade80; font-weight: bold; text-transform: uppercase; }
    a { color: #38bdf8; text-decoration: none; }
    a:hover { text-decoration: underline; }
    hr { border-color: #334155; margin: 1.5rem 0; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🛡️ Diagnostyka sieci</h1>
    <p><strong>Status:</strong> <span class="status">${diagnostics.status}</span></p>
    <p><strong>Resolver:</strong> ${diagnostics.resolver}</p>
    <p><strong>Twój adres IP:</strong> <code>${diagnostics.clientIP}</code></p>
    <p><strong>Kraj:</strong> ${diagnostics.country}</p>
    <p><strong>Załadowane domeny w pamięci:</strong> ${diagnostics.loadedDomains}</p>
    <hr>
    <p><strong>Format JSON:</strong> <a href="/test.json">/test.json</a></p>
    <pre>${JSON.stringify(diagnostics, null, 2)}</pre>
  </div>
</body>
</html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}
