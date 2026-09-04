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
<!-- worklog-synced-with-commit: 406b462842b351fbbe41fb5af35b4470af53c76d -->
