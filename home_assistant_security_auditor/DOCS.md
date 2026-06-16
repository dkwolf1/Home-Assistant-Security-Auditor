# Documentatie

## Opties

### `public_url`

De publieke URL of hostnaam van je Home Assistant installatie. Voorbeelden:

- `https://home.example.com`
- `https://example.duckdns.org`
- `home.example.com`

Wanneer het schema ontbreekt gebruikt de add-on `https://`.

### `scan_common_ports`

Wanneer ingeschakeld controleert de add-on of veelgebruikte poorten open lijken vanaf de add-on container. Dit is geen volledige externe poortscan en vervangt geen scan vanaf het internet.

### `request_timeout_seconds`

Timeout voor netwerkcontroles.

## Wat wordt gecontroleerd?

- DNS-resolutie en herkenbare providers zoals Cloudflare en DuckDNS.
- TLS-certificaat, geldigheid en uitgever.
- HTTP security headers zoals HSTS, X-Frame-Options, Content-Security-Policy en Referrer-Policy.
- Bekende Home Assistant endpointresponsen.
- Lokale configuratiepatronen in `configuration.yaml`.

## Beperkingen

De add-on voert geen aanvallende testen uit. Resultaten zijn bedoeld als signalering en advies. Voor hoge zekerheid blijft een externe audit of scan vanaf een ander netwerk nuttig.

