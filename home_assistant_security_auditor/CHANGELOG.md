# Changelog

## 0.1.4

- Switched to a plain Alpine runtime to avoid s6-overlay startup permission issues on `/init`.

## 0.1.3

- Removed the custom AppArmor profile so Supervisor can use the default Home Assistant confinement profile.

## 0.1.2

- Expanded the AppArmor profile for the Home Assistant base image s6-overlay init path.

## 0.1.1

- Fixed AppArmor startup permission for the Home Assistant base image init process.

## 0.1.0

- Eerste versie met ingress UI.
- Non-invasieve audit engine voor publieke URL, TLS, DNS, headers en lokale configuratie.
- Roadmap toegevoegd.

