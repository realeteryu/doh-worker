# doh-worker

Prywatny resolver DNS-over-HTTPS (DoH) działający na Cloudflare Workers. Filtruje ruch na podstawie bloklisty z repozytorium [dns-blocklists](https://github.com/realeteryu/dns-blocklists).

## Działanie

*   Obsługuje DoH (RFC 8484) dla metod GET i POST.
*   Blokuje domeny i ich subdomeny na podstawie listy z Cloudflare KV.
*   Zwraca NXDOMAIN dla zablokowanych zapytań oraz SERVFAIL w przypadku awarii upstreamu.
*   Usuwa nagłówki identyfikujące klienta przed przekazaniem ruchu do upstreamu.
*   W przypadku awarii KV, pobiera listę awaryjnie z GitHuba. Jeśli oba źródła zawiodą, przepuszcza ruch bez filtracji, ale nadal utrzymuje szyfrowany tunel DoH.

## Wydajność

Lista blokad jest przechowywana w formacie binarnym (MsgPack). Worker dekoduje ją bezpośrednio do struktury `Set`, co redukuje zużycie CPU przy zimnym starcie do minimum.
