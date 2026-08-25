# Known Issues - csf-firewall

> Persistent register van bekende bugs en security-vulnerabilities die over sessies heen
> blijven bestaan. Doel: doorbreek het "(pre-existing)"-meeslepen. Een item dat hier OPEN
> staat is BEKEND en moet door de huidige agent opgepakt worden (fix-first), afgesplitst via
> `mcp__ccd_session__spawn_task`, of gemotiveerd op ACCEPTED gezet. Een vuln/bug die je
> ontdekt en niet meteen fixt, hoort HIER, niet in een terloops "(pre-existing)".
>
> Aanvullend op `deviations.md` (afwijkingen van plan), `decisions.md` (pre-architectuur)
> en `MEMORY.md` (permanente kennis). Zie de CLAUDE.md-sectie
> "Bug- en vulnerability-eigenaarschap".

## Statussen

- **OPEN**: ontdekt, nog niet aangepakt. Default voor een nieuw item.
- **IN-PROGRESS**: er wordt deze of een recente sessie aan gewerkt. `Eigenaar-sessie` ingevuld.
- **FIXED**: opgelost in code. `Vastgelegd in commit` (hash) verplicht.
- **ACCEPTED**: bewust NIET opgelost (risico aanvaard, niet exploiteerbaar, of upstream).
  `Motivatie` + `Akkoord van` (naam + datum) verplicht; voor een vulnerability is
  human-bevestiging verplicht. Dit is de ENIGE legitieme manier om een item te laten liggen.
  "(pre-existing)" zonder ACCEPTED-entry is geen excuus.
- **MERGED**: gebundeld in een carrier-entry die de volledige sessie-taak draagt (DEC-012,
  config-repo). `Gebundeld in` (KI-NNN) verplicht; de carrier moet bestaan, live zijn
  (OPEN/IN-PROGRESS) en zelf niet MERGED zijn. Geen FIXED en geen ACCEPTED: het defect
  blijft bestaan en wordt via de carrier opgevolgd.

## Entry-formaat

Volgnummers KI-001, KI-002, etc. Bij cross-device werk (laptop + mobile) voeg een
UTC-timestamp suffix toe om ID-collisions te vermijden, bv. KI-005-20260603-1410. Verwijder of
vervang de placeholder-entry hieronder zodra een echt item wordt vastgelegd.

## KI-001: Cloudflare-api-key live in csf.cloudflare + twee PEM server-sleutels in history

- **Ontdekt**: 2026-08-25
- **Type**: vuln
- **Severity**: medium-high
- **Bron**: gitleaks fleet-sweep TASK-270 (config-repo, 2026-08-25), feitenrapport in `~/.claude/state` (0600)
- **Component**: `csf/csf.cloudflare` (Cloudflare-api-key, 15-hex-vorm, **nu nog op HEAD**); `ui/server.key` en `ssl-expired/server.key` (PEM private keys, alleen in de git-history)
- **Omschrijving**: de CSF-Cloudflare-integratie draagt haar api-key plaintext in een getrackt configbestand, en twee PEM private keys van de CSF-webui staan in de git-history. Cloudflare kent twee soorten credentials en dat verschil bepaalt de ernst: een klassieke **global API key** geeft volledige account-toegang (alle zones, DNS, firewall), een **scoped API token** is veel beperkter. Welke van de twee dit is, is nog niet vastgesteld.
- **Oorzaak**: infra-config met embedded credential in git; de sleutelbestanden zijn gecommit voordat de canonieke secrets-gitignore-block bestond.
- **Status**: OPEN
- **Eigenaar-sessie**: (geen)
- **Next-step**: zie het fleet-actiedoc `~/.claude/docs/project/notes/20260825-rotatie-actieplan-fleet-gitleaks.md` (sectie 6). Concreet: (1) stel vast of de Cloudflare-waarde een global API key of een scoped token is - global => onmiddellijk roteren in het Cloudflare-account, scoped => de scopes vastleggen en op basis daarvan kiezen tussen roteren en formeel accepteren; (2) vervang de waarde server-side en template het veld in git (placeholder in git, echte waarde alleen op de server) - `csf.cloudflare` NIET uit git halen, het IS de config; (3) bevestig met bewijs dat beide server-sleutels vervangen zijn en de bijbehorende certificaten verlopen; zijn ze nog in gebruik, dan is een nieuw sleutelpaar de neutralisatie. History bevat alles nog => rotatie is de neutralisatie, en pinnen gebeurt pas daarna.
- **Motivatie**: [alleen bij ACCEPTED]
- **Akkoord van**: [naam + datum, alleen bij ACCEPTED]
- **Gebundeld in**: [KI-NNN, alleen bij MERGED]
- **Vastgelegd in commit**: [hash, alleen bij FIXED]

<!-- known-issues-synced-with-commit: dd35dfebd7d0bb89b38a77145a0b1d6000a8d661 -->
