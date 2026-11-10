# doh-worker

Prywatny resolver DNS-over-HTTPS (DoH) działający na Cloudflare Workers. Filtruje ruch na podstawie bloklisty z repozytorium [dns-blocklists](https://github.com/realeteryu/dns-blocklists).

## Działanie

*   Obsługuje DoH (RFC 8484) dla metod GET (`?dns=`) i POST. Endpoint: `/dns-query`.
*   Blokuje domeny i ich subdomeny na podstawie listy z Cloudflare KV (z fallbackiem do GitHuba, jeśli KV zawiedzie lub zwróci pustą listę).
*   Zwraca NXDOMAIN dla zablokowanych zapytań oraz SERVFAIL w przypadku awarii upstreamu (timeout 8 s).
*   Usuwa nagłówki identyfikujące klienta (`cf-connecting-ip`, `cf-ray`, `cf-ipcountry`, `x-real-ip`, `host`, `cf-visitor`, `connection`) przed przekazaniem ruchu do upstreamu.
*   Domyślny upstream to Cloudflare DNS (`https://cloudflare-dns.com/dns-query`), konfigurowalny przez zmienną środowiskową `UPSTREAM_DOH`.
*   W przypadku awarii KV i GitHuba przepuszcza ruch bez filtracji przez okno 5 minut, ale nadal utrzymuje szyfrowany tunel DoH (fail-open).

## Wydajność

Lista blokad jest przechowywana w formacie binarnym (MsgPack). Worker dekoduje ją bezpośrednio do struktury `Set`, co redukuje zużycie CPU przy zimnym starcie w porównaniu do formatów tekstowych (TXT/JSON).

## Znane ograniczenia

*   Nie blokuje łańcuchów CNAME. Jeśli dozwolona domena ma CNAME na domenę z bloklisty, zapytanie przejdzie. Blokowanie CNAME wymagałoby parsowania sekcji Answer odpowiedzi.
*   Fail-open przez 5 minut po błędzie ładowania bloklisty. Świadoma decyzja: priorytetem jest dostępność.
*   Brak ochrony przed DNS rebindingiem. Worker jest publiczny, ale nie jest przeznaczony do użytku przez osoby trzecie.
