# doh-worker ⚡

Wydajny, bezserwerowy resolver DNS-over-HTTPS (DoH) działający na krawędzi (Cloudflare Workers). 

Automatycznie pobiera i buforuje listę blokad z Cloudflare KV (z fallbackiem do repozytorium `dns-blocklists`), filtrując reklamy, trackery i malware w locie – bez potrzeby utrzymywania własnego VPS-a czy homelabu.

---

## Kluczowe funkcje

* **Zgodność z RFC 8484:** Natywna obsługa binarnych zapytań DNS (`application/dns-message`) przesyłanych metodami GET i POST.
* **Hierarchiczne dopasowanie:** Inteligentnie sprawdza domeny i subdomeny (np. blokada `bad.com` automatycznie obejmuje `tracker.bad.com`).
* **Parser DNS (RFC 1035):** Wbudowane parsowanie binarnego bufora z pełną obsługą wskaźników kompresji.
* **Architektura Fail-Open (3-poziomowy fallback):** 
  1. W pierwszej kolejności Worker pobiera dane z **Cloudflare KV** (błyskawiczny start i wysoka dostępność).
  2. W razie awarii lub braku danych w KV, następuje fallback do **GitHub Actions** (z obsługą ETag i zapobieganiem *retry storms*).
  3. Jeśli oba źródła zawiodą, Worker działa w trybie **Fail-Open** (przepuszcza ruch bez blokad przez Cloudflare), zapobiegając całkowitemu odcięciu internetu.
* **Krawędziowe NXDOMAIN:** Generuje i zwraca gotową odpowiedź blokady bezpośrednio z Cloudflare, bez odpytywania upstreamu.
* **Bezpieczeństwo transportu:** Usuwa nagłówki identyfikacyjne klienta przed przekazaniem legalnego ruchu do nadrzędnego resolvera.
