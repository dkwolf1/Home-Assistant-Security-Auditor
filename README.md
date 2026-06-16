# Home Assistant Security Auditor

Home Assistant Security Auditor is een Home Assistant add-on om veelvoorkomende beveiligingsrisico's rond externe toegang inzichtelijk te maken.

De eerste versie richt zich op non-invasieve controles voor configuraties met Cloudflare, DuckDNS, Let's Encrypt, Nginx Proxy Manager, reverse proxies en TLS. De add-on biedt een nette ingress UI, een samenvatting van risico's en concrete adviezen.

## Installatie als lokale add-on repository

1. Kopieer deze repository naar een Git remote of lokale add-on repository locatie.
2. Voeg de repository toe in Home Assistant via **Settings > Add-ons > Add-on Store > Repositories**.
3. Installeer **Home Assistant Security Auditor**.
4. Vul in de add-on opties je publieke Home Assistant URL of hostnaam in.
5. Start de add-on en open de UI.

## Structuur

- `home_assistant_security_auditor/` bevat de add-on.
- `home_assistant_security_auditor/config.yaml` bevat Home Assistant add-on metadata.
- `home_assistant_security_auditor/rootfs/app/` bevat de web UI en audit engine.
- `ROADMAP.md` beschrijft de geplande uitbreidingen.

## Veiligheid

De scanner voert alleen passieve en lichte controles uit. Er worden geen brute-force, exploit- of denial-of-service testen uitgevoerd.

