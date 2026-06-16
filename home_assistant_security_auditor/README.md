# Home Assistant Security Auditor

Controleer of je Home Assistant veilig van buitenaf bereikbaar is.

Deze add-on helpt bij setups met onder andere Cloudflare, DuckDNS, Let's Encrypt, Nginx Proxy Manager en andere reverse proxies. De scanner is bewust non-invasief en geeft per bevinding een praktisch advies.

## Features

- Ingress web UI in Home Assistant.
- TLS en certificaatcontrole.
- DNS en providerherkenning.
- HTTP security header checks.
- Detectie van proxy-signalen.
- Lokale configuratiecontrole op bekende Home Assistant security instellingen.

## Eerste gebruik

Vul in de add-on opties `public_url` in, bijvoorbeeld:

```text
https://home.example.com
```

Start daarna de add-on en open de web UI via de zijbalk of de add-on pagina.

