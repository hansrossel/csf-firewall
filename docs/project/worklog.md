# Worklog - csf-firewall

> Register voor werk-types die geen ander register hebben: taken (TASK), onderhoud
> (MAINT), onderzoek (RES), documentatie-werk (DOC) en feature-groeperingen (FEAT).
> Aanvullend op `known-issues.md` (bugs/vulns), `deviations.md` (afwijkingen),
> `decisions.md` (beslissingen) en `pipeline-index.json` (fasen). Naamgeving en
> type=>thuis-mapping: zie de `project-conventions` skill en `CONVENTIONS.md`
> (canoniek in ~/.claude, fleet-breed gedragen door de globale CLAUDE.md + de skill).
>
> Alle OPEN-items vormen samen de backlog. IN-PROGRESS-entries worden bij
> sessie-start geinjecteerd via `hooks/worklog-session-start.sh` (met hun
> continuiteitsvelden).

## Statussen

- **OPEN**: aangemaakt, nog niet gestart. Default voor een nieuw item.
- **IN-PROGRESS**: er wordt aan gewerkt. `Eigenaar-sessie` ingevuld.
- **DONE**: afgerond. `Vastgelegd in commit` (hash) verplicht.
- **CANCELLED**: bewust niet uitgevoerd. `Motivatie` verplicht.

## Entry-formaat

Per-type doorlopende volgnummers: TASK-001, MAINT-001, RES-001, DOC-001, FEAT-001
(elk type telt apart). Bij cross-device werk voeg een UTC-timestamp-suffix toe, bv.
TASK-005-20260705-1410. Ken toe via de `project-conventions` skill
(`skills/project-conventions/scripts/next-id.sh --reserve <PREFIX>`). Elke entry
heeft een beschrijvende titel in zijn `##`-heading.

Velden per entry: Type, Aangemaakt, Omschrijving, Status, Eigenaar-sessie, Links,
Next-step, Open-questions, To-avoid, Motivatie (alleen CANCELLED), Vastgelegd in
commit. **Next-step**, **Open-questions** en **To-avoid** zijn VERPLICHT bij
IN-PROGRESS (max 40/40/30 woorden); bij DONE op "(afgerond)".

<!-- Nog geen entries. Registreer werk via de project-conventions skill; de
     eerste ## TASK-/MAINT-/RES-/DOC-/FEAT- entry vervangt deze regel. -->


## TASK-001: Pariteit met cPanel CSF 16.31 (CVE-2026-67402) plus Codex-security-review

- **Type**: TASK
- **Aangemaakt**: 2026-09-03
- **Omschrijving**: cPanel bracht op 2026-09-03 CSF 16.31 uit met CVE-2026-67402 in de MESSENGER-dienst. De inhoud van die release is vastgesteld op mesoc.koba.be, waar 16.31 al draaide (`cpanel-csf-16.31-1.2.1.cpanel.noarch`), door de RPM-changelog en de geinstalleerde broncode te vergelijken met deze fork. Zeven van de tien punten uit die release zijn hier van toepassing en zijn gebackport; de drie andere zijn met bewijs als niet-van-toepassing vastgelegd in de README. Daarnaast draaide een Codex-security-review over de messenger-aanvalsoppervlakte, die de P0 onafhankelijk bevestigde en drie extra bevindingen opleverde die ook zijn opgelost.
- **Status**: DONE
- **Eigenaar-sessie**: 2026-09-03/04
- **Links**: KI-002 (restbevindingen uit de review), CVE-2026-67402
- **Next-step**: (afgerond)
- **Open-questions**: (afgerond)
- **To-avoid**: (afgerond)
- **Vastgelegd in commit**: 4ba1e7a, f7b3ab5, 47a5b70, efe1e45, 62fd918, 406b462

## TASK-002: unblock-protocol van de messenger harden (nieuwe functionaliteit, bewust uitgesteld)

- **Type**: TASK
- **Aangemaakt**: 2026-09-05
- **Omschrijving**: verzamelentry voor het deel van de KI-002-remedie dat NIEUWE FUNCTIONALITEIT vereist en daarom buiten de security-only-scope van 2026-09-05 valt. Vier onderdelen: (1) begrensde POST-ondersteuning in de v1-listener plus `index.recaptcha.html` van `method='GET'` naar POST, zodat het CAPTCHA-token niet langer in de URL staat (en dus niet in de Referer, proxy-logs en de messenger-log); (2) een nieuwe configsleutel `RECAPTCHA_HTTPS_ONLY` in de zeven `csf*.conf`-varianten, afgedwongen in de vhost-generatie (`<LimitExcept GET HEAD>`) zodat de eigenschap niet van het gekopieerde PHP-script afhangt; (3) een limiet op verify-calls per bron-IP in `index.recaptcha.php`; (4) een migratiemechanisme dat een bestaande stock-kopie van `public_html/index.php` vervangt, want zonder dat bereikt geen enkele PHP-fix een bestaande installatie.
- **Vastgestelde feiten die deze taak sturen** (gemeten, niet aangenomen):
  - `remoteip` bindt NIETS. Google's siteverify-doc noemt hem "Optional. The user's IP address." en documenteert geen validatie tegen het token. De Next-step van KI-002 schrijft hem voor als binding; dat is schijnzekerheid.
  - Een server-nonce sluit de on-path replay evenmin: de aanvaller haalt een eigen nonce op zijn eigen IP op en koppelt die aan het gestolen token. Wat wel werkt is vertrouwelijkheid (token uit de URL, TLS afdwingen).
  - Tokens zijn eenmalig en twee minuten geldig (zelfde bron), dus de aanval is een race binnen dat venster: de aanvaller wint een gratis CAPTCHA-oplossing voor zijn eigen adres en brandt het token op, waardoor de deblokkade van het slachtoffer faalt.
  - `messengerv2()` (regel 594) en `messengerv3()` (regel 849) kopieren `index.recaptcha.php` alleen `unless (-e $public_html."/index.php")`. Een bestaande installatie houdt dus haar oude kopie; zonder onderdeel (4) landt (3) nergens.
  - `hashlimit` op de bestaande iptables-regels is GEEN alternatief voor (3): `csf.pl` regel 1899, 1903-1904, 1914 en 1918-1919 zijn OUTPUT-regels met `--sport`, waar `--hashlimit-mode srcip` het SERVERadres bucket. Bovendien vergroot per-bron-bucketing het totale aanvallersbudget en telt het pakketten, geen verify-calls.
- **Status**: OPEN
- **Links**: KI-002 (de bevindingen die dit adresseert), KI-003 (raakt dezelfde `unless (-e ...)`-constructies als onderdeel 4)
- **Next-step**: eigen sessie, en pas na expliciete toestemming: dit is per definitie nieuwe functionaliteit. Begin bij onderdeel (4), want zonder migratiepad is (1) tot (3) alleen zichtbaar op verse installaties. Stem (4) af met de eigenaar van KI-003.
- **Open-questions**: moet `RECAPTCHA_HTTPS_ONLY` default `1` (veilig, maar gedragswijziging bij upgrade) of `0` (behoudt gedrag, laat de bevinding open)? En wat bij TLS-geconfigureerd-maar-niet-gereed: fail-open op beschikbaarheid of fail-closed?
- **To-avoid**: geen `remoteip` of nonce als "binding" presenteren; geen hashlimit op de OUTPUT-regels; geen blind overschrijven van een aangepaste `public_html/index.php`.
- **Vastgelegd in commit**: [hash, alleen bij DONE]
<!-- worklog-synced-with-commit: 406b462842b351fbbe41fb5af35b4470af53c76d -->
