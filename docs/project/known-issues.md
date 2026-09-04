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


## KI-002: Restbevindingen Codex-security-review messenger (2 medium, 2 low, 2 betterments)

- **Ontdekt**: 2026-09-04
- **Type**: vuln
- **Severity**: medium (hoogste in de bundel)
- **Bron**: Codex security-review (route A, `--mode security`, model `gpt-daybreak-blue-latest`, effort `ultra`, geattesteerd), gedraaid op de messenger-aanvalsoppervlakte tijdens TASK-001. Run-uniek rapport buiten git: `~/.claude/state/codex-reviews/1788492427-14454/codex-review.md` (0600).
- **Component**: `csf/messenger/index.recaptcha.html`, `csf/messenger/index.php`, `csf/ConfigServer/Messenger.pm`
- **Omschrijving**: verzamel-entry voor de bevindingen uit die review die NIET in 16.31 zijn opgelost, conform de security-review-conventie (high/critical elk een eigen entry, medium/low gebundeld met telling). De review gaf verdict DO-NOT-SHIP; de drie zwaarste bevindingen (P0 CGI-mapping van `/usr/bin`, P1 symlink-clobber op `recaptcha.php`, P1 TLS-verificatie uit bij reCAPTCHA-verify) zijn wel opgelost in deze release. Wat openblijft:
  - **2x medium**: (a) de unblock-token is niet gebonden aan de peer die de CAPTCHA oploste en reist over platte HTTP wanneer de HTML-messenger aanstaat, zodat een on-path partij hem kan onderscheppen en racen; (b) er is geen rate-limiting op de anonieme verify-aanroep. Van (b) is de stall-helft in deze release wel afgedekt met connect- en totaal-timeouts (commit 62fd918); de ontbrekende helft is het aantal aanroepen per bron.
  - **2x low**: onder `DEBUG` belanden runtime-details in de HTTP-respons, en de door de client gekozen request-regel wordt verbatim gelogd (controltekens plus de CAPTCHA-token in het log).
  - **2x betterment**: `index.php` en `index.recaptcha.php` leiden een include-pad af uit `HTTP_ACCEPT_LANGUAGE`, en twee plekken in `Messenger.pm` behandelen csf-configwaarden als commandotekst. Beide vereisen een voorwaarde die op een correct opgezette host niet geldt.
- **Waarom niet nu opgelost**: (a) vraagt een ontwerpwijziging (server-side nonce plus `remoteip`-binding en HTTPS-only unblock), geen regelfix, en raakt het unblock-protocol zelf; de rest is bewust buiten de scope van een pariteitsrelease gehouden. Alles hierboven is bovendien alleen bereikbaar wanneer `MESSENGER` aanstaat, en die staat in elke meegeleverde `csf.*.conf` op `0`.
- **Status**: OPEN
- **Next-step**: eigen sessie. Begin bij de medium (a): bind de verificatie aan de peer met een eenmalige server-nonce plus de `remoteip`-parameter van de siteverify-aanroep, en bied unblock alleen over HTTPS aan. Daarna (b) rate-limiting per bron-IP. De low-items zijn een aparte, kleinere ronde. Lees het run-unieke rapport voor de exploit-details; die staan bewust niet in dit register.
- **Vastgelegd in commit**: [hash, alleen bij FIXED]
<!-- known-issues-synced-with-commit: 406b462842b351fbbe41fb5af35b4470af53c76d -->
