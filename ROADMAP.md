# Roadmap

## Fase 1 - Add-on basis en lokale audit

- Professionele ingress UI met risicosamenvatting, bevindingen en adviezen.
- Add-on metadata volgens Home Assistant add-on conventies.
- Non-invasieve controles voor publieke URL, TLS, DNS, HTTP security headers en bekende Home Assistant paden.
- Basale detectie van Cloudflare, DuckDNS, Let's Encrypt en reverse proxy signalen.
- Lokale Home Assistant configuratie checks op patronen rond `http`, `trusted_proxies`, `ip_ban_enabled`, `ssl_certificate` en `ssl_key`.

## Fase 2 - Betere analyse en rapportage

- Export naar JSON en PDF.
- Historische scans met trendweergave.
- Severity model met duidelijke prioriteiten: kritisch, hoog, medium, laag en info.
- Wizard voor veelgebruikte setups: Cloudflare Tunnel, DuckDNS + Let's Encrypt, Nginx Proxy Manager en externe reverse proxy.
- Uitleg per finding met concrete Home Assistant configuratievoorbeelden.

## Fase 3 - Integraties

- Home Assistant repairs of persistent notifications voor kritieke bevindingen.
- Optionele sensor entities voor score, laatste scanstatus en aantal hoge risico's.
- Integratie met Supervisor API voor add-on en netwerkcontext waar beschikbaar.
- Detectie van geinstalleerde proxy- en certificate add-ons.

## Fase 4 - Geavanceerde checks

- Rate-limit en lockout verificatie zonder brute force.
- Cloudflare API optioneel gebruiken om zone instellingen te controleren.
- Controle op HSTS, certificate chain details, minimum TLS versie en cipher beleid.
- Detectie van onbedoeld publiek toegankelijke endpoints en dashboards.

## Fase 5 - Hardening assistent

- Stapsgewijze remediation flow per setup.
- Vergelijking met best-practice profielen.
- Pre-flight check voor nieuwe externe toegang.
- Periodieke automatische scan met notificaties.

