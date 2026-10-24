# doh-worker ⚡

Wydajny, bezserwerowy resolver DNS-over-HTTPS (DoH) działający na krawędzi sieci (Cloudflare Workers). 

Automatycznie pobiera i buforuje listę blokad z Cloudflare KV (z fallbackiem do repozytorium `dns-blocklists`), filtrując reklamy, trackery i zagrożenia (np. phishing) w locie. Nie wymaga utrzymywania własnego VPS-a, homelabu ani instalowania zewnętrznych aplikacji na urządzeniu końcowym.

---

## Kluczowe funkcje

* **Zgodność z RFC 8484:** Natywna obsługa binarnych zapytań DNS (`application/dns-message`) przesyłanych metodami GET i POST.
* **Hierarchiczne dopasowanie:** Inteligentnie sprawdza domeny i subdomeny (np. blokada `bad.com` automatycznie obejmuje `tracker.bad.com`), co pozwala na utrzymanie wyjątkowo lekkiej listy blokad.
* **Bezpieczny parser (RFC 1035 + RFC 9267):** Wbudowane parsowanie binarnego bufora z pełną obsługą wskaźników kompresji. Zaimplementowano rygorystyczną walidację wskaźników, co chroni przed złośliwymi pakietami próbującymi wywołać pętle (ataki wyczerpania CPU).
* **Architektura Fail-Open (3-poziomowy fallback):** 
  1. W pierwszej kolejności Worker pobiera dane z **Cloudflare KV** (z wykorzystaniem `cacheTtl`, co zapewnia błyskawiczny odczyt z pamięci brzegowej).
  2. W razie awarii lub braku danych w KV, następuje fallback do **GitHub** (z obsługą ETag i zapobieganiem *retry storms*).
  3. Jeśli oba źródła zawiodą, Worker działa w trybie **Fail-Open** (przepuszcza ruch bez blokad), zapobiegając całkowitemu odcięciu internetu.
* **Krawędziowe NXDOMAIN:** Generuje i zwraca gotową odpowiedź blokady bezpośrednio z Cloudflare, bez odpytywania upstreamu (oszczędność czasu i transferu).
* **Odporność na awarie upstreamu:** Zastosowano limit czasu (timeout 8s) oraz generowanie poprawnych pakietów DNS `SERVFAIL` w formacie binarnym, jeśli zewnętrzny resolver nie odpowie.
* **Prywatność i bezpieczeństwo transportu:** Worker nie loguje odwiedzanych domen. Przed przekazaniem legalnego ruchu do nadrzędnego resolvera usuwa nagłówki identyfikacyjne klienta (m.in. `cf-connecting-ip`, `cf-ray`, `host`).
