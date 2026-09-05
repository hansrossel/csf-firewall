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
  - **2x medium**: (a) de unblock-token is niet gebonden aan de peer die de CAPTCHA oploste en reist over platte HTTP wanneer de HTML-messenger aanstaat, zodat een on-path partij hem kan onderscheppen en racen; (b) de anonieme verify-aanroep is ongelimiteerd. Codex' remedie voor (b) heeft vier delen: token-grammatica, token-lengtelimiet, rate-limiting per bron-IP, en connect- plus totaal-timeout. Alleen de twee timeouts zijn in deze release toegevoegd (commit 62fd918). Nagemeten op HEAD: de PHP-zijde controleert nog steeds alleen `isset` en `!empty` op `g-recaptcha-response` voor de curl-aanroep, dus grammatica en lengtelimiet ontbreken, net als de rate-limiting. De tokengrammatica die in de 16.30-backport zit geldt de Perl-zijde (v1-messenger, `Messenger.pm` regel 423), niet dit PHP-pad.
  - **2x low**: onder `DEBUG` belanden runtime-details in de HTTP-respons, en de door de client gekozen request-regel wordt verbatim gelogd (controltekens plus de CAPTCHA-token in het log).
  - **2x betterment**: `index.php` en `index.recaptcha.php` leiden een include-pad af uit `HTTP_ACCEPT_LANGUAGE`, en twee plekken in `Messenger.pm` behandelen csf-configwaarden als commandotekst. Beide vereisen een voorwaarde die op een correct opgezette host niet geldt.
- **Waarom niet nu opgelost**: (a) vraagt een ontwerpwijziging (server-side nonce plus `remoteip`-binding en HTTPS-only unblock), geen regelfix, en raakt het unblock-protocol zelf; de rest is bewust buiten de scope van een pariteitsrelease gehouden. Alles hierboven is bovendien alleen bereikbaar wanneer `MESSENGER` aanstaat, en die staat in elke meegeleverde `csf.*.conf` op `0`.
- **Status**: OPEN
- **Next-step**: eigen sessie. Begin bij de medium (a): bind de verificatie aan de peer met een eenmalige server-nonce plus de `remoteip`-parameter van de siteverify-aanroep, en bied unblock alleen over HTTPS aan. Daarna (b): token-grammatica plus lengtelimiet voor de curl-aanroep, en rate-limiting per bron-IP. De low-items zijn een aparte, kleinere ronde. Lees het run-unieke rapport voor de exploit-details; die staan bewust niet in dit register.
- **Vastgelegd in commit**: [hash, alleen bij FIXED]

## KI-003: Backport van cPanel CSF 16.26 is onvolledig - bestandsgeneratie in de messenger-home blijft pad-gebaseerd

- **Ontdekt**: 2026-09-04
- **Type**: vuln
- **Severity**: high
- **Bron**: volledige RPM-changelog van `cpanel-csf` op mesoc (16.00 t/m 16.31), nagelopen na TASK-001. De eerdere analyse las die changelog met `head -60` en stopte bij 16.24, waardoor de oudere security-releases buiten beeld bleven.
- **Component**: `csf/ConfigServer/Messenger.pm` (`messengerv2` en `messengerv3`)
- **Omschrijving**: cPanel 16.26 hardde de bestandsgeneratie in de home en document-root van de messenger tegen symlink-, hardlink-, FIFO-, lock- en uid-0-confused-deputy-aanvallen door `MESSENGER_USER`. Onze fork nam daarvan alleen de `recaptcha.php`-modus (0600) over; de symlink-kant van datzelfde bestand bleef open tot ze in TASK-001 alsnog werd gedicht (commit 62fd918, gevonden door de Codex-review, niet door de changelog). De ZUSTERBESTANDEN in dezelfde directory zijn nog wel pad-gebaseerd. Nagemeten op HEAD, alle door lfd als root uitgevoerd in een directory die `MESSENGER_USER` beheert: `.htaccess` via `open(">")` (regels 576 en 835), `index.php` en `en.php` via `system("cp",...)` (596/598/604 en 851/853/859), plus `mkdir`/`chown`/`chmod` op pad voor `public_html` en `$homedir` (557, 571-573, 830-832) en `chown`/`chmod` op pad voor elk van die bestanden. Elke `unless (-e ...)`-bewaking ervoor is zelf een TOCTOU: de test en de schrijfactie zijn gescheiden.
- **Impact**: dezelfde klasse als de bevinding die in 62fd918 werd gedicht - `MESSENGER_USER` wijst een van deze paden naar een root-schrijfbaar bestand en laat root het aanmaken, overschrijven, van eigenaar wisselen of van modus veranderen. Lokale privilege-escalatie naar root.
- **Bereikbaarheid**: alleen wanneer `MESSENGER` (v2 of v3) aanstaat. Die staat op `0` in elke meegeleverde `csf.*.conf`.
- **Twee losse punten uit dezelfde 16.26-release**: afgesplitst naar KI-005 (geen statusdoorgifte uit de installatiefase, rollback die niet herstelt, `csf --mregen` dat altijd succes meldt). Die zijn geen privilege-escalatie en vallen buiten de kritieke-security-scope van deze fix.
- **Status**: OPEN
- **Next-step**: gedeelde veilige-installatie-helper naast `writerecaptchaconf()` uit 62fd918, die dezelfde vorm aanhoudt (unlink, dan `sysopen` met `O_EXCL|O_NOFOLLOW`, dan eigenaar en modus via de descriptor) en die de `system("cp")`-aanroepen vervangt door een lees-en-schrijf via die helper. Twee metingen uit 2026-09-05 sturen die vorm bij: (a) `O_NOFOLLOW` dekt alleen het LAATSTE padcomponent, dus `MESSENGER_USER` kan `public_html` zelf verwisselen nadat het geverifieerd is - de sluitende vorm pint een geverifieerde directory-descriptor (`O_RDONLY|O_DIRECTORY|O_NOFOLLOW`) en werkt daarna via `chdir($DH)` op KALE bestandsnamen; (b) de bereikbare aanval is een DANGLING symlink, want bij een bestaand doel volgt `-e` de link en slaat de code de schrijfactie juist over. De twee losse 16.26-punten zitten nu in KI-005.
- **Vastgelegd in commit**: [hash, alleen bij FIXED]


## KI-004: Twee oudere cPanel-hardeningen niet overgenomen (PERL5LIB, web-UI-encoding)

- **Ontdekt**: 2026-09-04
- **Type**: vuln
- **Severity**: medium (hoogste in de bundel)
- **Bron**: volledige RPM-changelog van `cpanel-csf` op mesoc, nagelopen na TASK-001
- **Component**: `csf/csf.pl`, `csf/lfd.pl`, `csf/ConfigServer/DisplayUI.pm`
- **Omschrijving**: twee punten uit de 16.x-lijn die geen tegenhanger hebben in onze fork.
  - **medium, 16.09** ("Assure PERL5LIB does not influence /usr/sbin/csf"): `PERL5LIB`, `PERLLIB` en `PERL5OPT` komen nergens voor in onze code - nagemeten met grep over `csf.pl`, `lfd.pl` en alle modules. Beide scripts draaien als root met `use lib '/usr/local/csf/lib'`. Dat pad komt vooraan `@INC`, dus de eigen `ConfigServer::`-modules zijn beschermd, maar elke andere afhankelijkheid (`Net::CIDR::Lite`, `JSON::Tiny`, `IO::Socket::*`, `POSIX`) wordt daarna via `@INC` opgezocht, waar `PERL5LIB`-paden vóór de systeemmappen staan. Wie de omgeving van een root-aanroep kan zetten, kiest dus welke module geladen wordt. Op een host waar root csf zelf start levert dat niets op; het telt bij een sudo-regel of service-aanroep die de omgeving doorgeeft. Aparte plek om mee te nemen: `Messenger.pm` regel 439 doet `eval("no lib '/usr/local/csf/lib'")` en laat `@INC` daar bewust terugvallen.
  - **onbekend, 16.00**: die release meldt "Fixed security vulnerabilities: XSS in web UI modules, proper HTML encoding throughout" als onderdeel van cPanels bredere herschrijving. Onze Aetherinox-lijn heeft een eigen `Sanitize.pm` en escapet op veel plaatsen, maar in TASK-001 bleken twee render-paden in `DisplayUI.pm` toch ongeescaped (opgelost in efe1e45). Of dat de enige twee waren is NIET vastgesteld; `DisplayUI.pm` is 174 KB en is niet integraal op dit punt geaudit. Dit staat hier als onbevestigd, niet als bevinding.
- **Status**: OPEN
- **Next-step**: voor 16.09: scrub `PERL5LIB`/`PERLLIB`/`PERL5OPT` vroeg in `csf.pl` en `lfd.pl`, en bepaal apart wat de `no lib`-regel in `Messenger.pm` daar nog aan verandert. Voor 16.00: een gerichte audit van elke `print`-regel in `DisplayUI.pm` en `DisplayResellerUI.pm` die een variabele interpoleert die uit een bestand of uit `%FORM` komt - dat is de enige manier om de "throughout"-claim te toetsen in plaats van te geloven.
- **Vastgelegd in commit**: [hash, alleen bij FIXED]


## KI-005: Mislukte messenger-installatie blijft stil - geen status, geen echte rollback, `--mregen` meldt altijd succes

- **Ontdekt**: 2026-09-05
- **Type**: bug
- **Severity**: medium
- **Bron**: afgesplitst uit KI-003 (de twee losse punten uit de cPanel CSF 16.26-release), nagemeten op HEAD tijdens de KI-003-sessie. Bewust NIET meegefixt: de human beperkte die sessie tot het kritieke security-probleem.
- **Component**: `csf/ConfigServer/Messenger.pm` (`messengerv2`, `messengerv3`), `csf/csf.pl` (`domessengerv2`)
- **Omschrijving**: drie samenhangende defecten, alle drie met dezelfde wortel - de installatiefase geeft geen status terug.
  - **Statusdoorgifte ontbreekt**: `messengerv2` eindigt op `return;` (regel 800) en `messengerv3` op `return;` (regel 1117), ook nadat de configtest faalde. De ontvangende kant bestaat al: `start()` (regels 132-150) geeft `($status,$reason)` door en `lfd.pl` regel 9674/9698 logt `*MESSENGERVn* Error: $reason`. Die tak wordt na de installatiefase dus nooit bereikt.
  - **Rollback herstelt niet**: regel 775 kopieert de nieuwe configuratie over de werkende heen VOOR de `apachectl configtest`. Faalt die test, dan verwijdert regel 792 het bestand alleen; de eerder werkende configuratie is dan weg in plaats van teruggezet. `messengerv3` doet hetzelfde (regels 1092-1107), en met een lege `MESSENGERV3TEST` (regels 1113-1115) draait er helemaal geen validatie: dan wordt blind herstart en gelogd als "Restarted".
  - **`csf --mregen` meldt altijd succes**: `csf.pl` regel 6962 gooit de returnwaarde van `messengerv2()` weg, waarna regel 6963 onvoorwaardelijk `...Done.` print en met exit 0 afsluit - ook wanneer `messengerv2` al bij de `MESSENGER_USER`-controle afhaakte. Bijkomend: de melding op regel 6961 noemt `csf_messenger.conf` terwijl de code `csf.messenger.conf` schrijft.
- **Impact**: geen privilege-escalatie. Een beheerder krijgt "Done." en exit 0 terwijl de messenger niet draait, en een mislukte regeneratie laat de dienst zonder configuratie achter in plaats van op de vorige werkende versie. Stille faalmodus op een security-dienst.
- **Bereikbaarheid**: alleen wanneer `MESSENGER` (v2 of v3) aanstaat. Die staat op `0` in elke meegeleverde `csf.*.conf`.
- **Niet geverifieerd**: dat cPanels 16.26 deze punten precies zo oploste is niet vastgesteld - de KI-003-tekst is onze samenvatting van de RPM-changelog op mesoc, de 16.26-bron is hier niet ingezien. De drie defecten hierboven volgen wel uit onze eigen code en staan op eigen benen.
- **Status**: OPEN
- **Next-step**: eigen sessie. Statusdoorgifte eerst (dat is de wortel en vereist geen nieuwe plumbing), daarna de rollback als echte restore (bestaande conf opzij zetten voor de overschrijving, byte-identiek terugzetten bij falen) en tot slot `domessengerv2` de status laten opvangen met een niet-nul exit. Het v3-pad is lokaal echt testbaar omdat `MESSENGERV3TEST` en `MESSENGERV3LOCATION` configureerbaar zijn (stub-testcommando + tempdir); het v2-pad heeft `/usr/sbin/apachectl` hardgecodeerd en is daardoor zwakker te dekken.
- **Vastgelegd in commit**: [hash, alleen bij FIXED]

## KI-006: gekopieerde TLS-privesleutels van de messenger krijgen umask-permissies in plaats van 0600

- **Ontdekt**: 2026-09-05
- **Type**: vuln
- **Severity**: medium-high (blootstelling van TLS-privesleutels aan elk lokaal account dat de directory kan doorlopen; verlaagd door de bereikbaarheidsvoorwaarde hieronder)
- **Bron**: security-review van de messenger-aanvalsoppervlakte op HEAD, plus eigen hermeting in de code
- **Component**: `csf/ConfigServer/Messenger.pm` - directory-aanmaak op regel 121-124 en 652-656, kopieeracties op regel 678, 728, 931, 1464 en 1516
- **Omschrijving**: de messenger kopieert de TLS-certificaten en -sleutels die hij in de webserverconfiguratie vindt naar `/var/lib/csf/ssl/`. Gemeten op HEAD: die directory's worden aangemaakt met een kale `mkdir $ssldir."keys/"` zonder modus-argument, dus met `0777 & ~umask`, en de sleutels zelf gaan er met `File::Copy::copy()` in. `copy()` neemt de modus van de BRON niet over: het doelbestand krijgt de standaardmodus van het proces. Bij een gebruikelijke umask 022 landt een privesleutel daarmee als `0644` in een `0755`-directory, terwijl de bron doorgaans `0600` is. lfd draait als root, dus de umask is die van de daemon-omgeving en niet iets waar de beheerder per site controle over uitoefent.
- **Impact**: elk lokaal account op de host kan de gekopieerde privesleutels lezen wanneer de umask dat toelaat. Dat is een sleutel voor een echt servercertificaat, niet voor het zelfondertekende UI-certificaat; hij blijft bruikbaar tot het certificaat vervangen is. Geen privilege-escalatie op zich, wel volledige compromittering van de TLS-identiteit die de messenger presenteert.
- **Bereikbaarheid**: alleen wanneer `MESSENGER` aanstaat EN de HTTPS-messenger geconfigureerd is. `MESSENGER` staat op `0` in elke meegeleverde `csf.*.conf`.
- **Status**: OPEN
- **Next-step**: de directory's aanmaken met een expliciete `0700`, en de sleutelbestanden schrijven via een descriptor (`sysopen` met `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW`, daarna `chmod`/`chown` OP de descriptor) in plaats van via `File::Copy::copy()` op pad. Dezelfde vorm die `writerecaptchaconf()` al gebruikt. Certificaten mogen `0644` blijven; alleen de `keys/`-tak vereist `0600`. Verifieer met een test die de umask op 022 zet en de resulterende modus assert.
- **Vastgelegd in commit**: [hash, alleen bij FIXED]

## KI-007: de TLS-handshake van de v1 HTTPS-messenger blokkeert de enige acceptor, vóór de fork en vóór de alarm

- **Ontdekt**: 2026-09-05
- **Type**: vuln
- **Severity**: medium (ongeauthenticeerde denial of service op de deblokkeerdienst; verlaagd door de bereikbaarheidsvoorwaarde hieronder)
- **Bron**: security-review van de messenger-aanvalsoppervlakte op HEAD, plus eigen hermeting in de code
- **Component**: `csf/ConfigServer/Messenger.pm` - listener-constructie regel 245-268, `accept()` op regel 351, `fork` op regel 364, `alarm(10)` op regel 372
- **Omschrijving**: de HTTPS-messenger construeert zijn luisteraar als een `IO::Socket::SSL` (regel 245-268). De acceptlus doet `while (my $client = $server->accept())` op regel 351, en `IO::Socket::SSL::accept()` voltooit standaard de volledige TLS-handshake vóór hij teruggeeft. Die handshake gebeurt dus in het OUDERPROCES, vóór de `fork` op regel 364 en dus ook vóór de `alarm(10)` die het kind op regel 372 arm. Een client die de TCP-verbinding opzet en de handshake nooit afmaakt, houdt daarmee de enige acceptor bezig; er is op dat moment nog geen kind waarop een timeout staat.
- **Impact**: één ongeauthenticeerde verbinding legt de HTTPS-messenger stil voor alle andere geblokkeerde bezoekers. `MESSENGER_CHILDREN` (default 20) helpt hier niet tegen: die begrenst het aantal KINDEREN, en het probleem zit vóór de fork. Het effect is dat een aanvaller de deblokkeerroute kan dichtzetten, precies de dienst die een onterecht geblokkeerde bezoeker nodig heeft.
- **Bereikbaarheid**: alleen wanneer `MESSENGER` aanstaat EN `MESSENGER_HTTPS_IN` niet leeg is. `MESSENGER` staat op `0` in elke meegeleverde `csf.*.conf`. Het HTML-pad (poort 8888) heeft dit niet: dat is een gewone `IO::Socket::INET` zonder handshake.
- **Status**: OPEN
- **Next-step**: rauw TCP accepteren en pas in het KIND de TLS-handshake doen, onder een deadline: `IO::Socket::SSL->start_SSL($client, SSL_startHandshake => 0, ...)` na de fork, met de bestaande `alarm` al gearmd. Let op dat de listener dan als gewone `IO::Socket::INET` geconstrueerd moet worden en de SSL-parameters naar `start_SSL` verhuizen; de SNI-certificaatkeuze uit `%sslcerts`/`%sslkeys` moet daarbij behouden blijven. Verifieer met een client die verbindt en niets stuurt: de acceptlus moet daarna nog een tweede verbinding aannemen.
- **Vastgelegd in commit**: [hash, alleen bij FIXED]
<!-- known-issues-synced-with-commit: 9270c5661070568652d5e53fb24c293bdcaf3283 -->
