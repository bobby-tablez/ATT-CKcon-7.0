# An Obfuscated Tale: From ATT&CK Origin to Detection Today

Supplemental materials for the ATT&CK Con 7.0 talk on MITRE ATT&CK **T1027.010 —
Command Obfuscation**: the STEEP#MAVERICK campaign that motivated the sub-technique's
creation, how the same obfuscation primitives show up in 2025–2026 campaigns
(GreenCharlie, MuddyWater-style ClickFix, ClearFake/Amatera), and how to actually
detect it with the right telemetry stack.

> "Detection engineering is only as viable as the fuel you give it."

## What's here

```
deck/         the slide deck (presentation.html), full speaker notes, and build notes
guides/       6 manuals: campaign deep-dive, technique reference, modern-campaign
              briefing, telemetry/detection guide, a character-masking + wildcard-IEX
              cheat sheet, and a one-week action checklist
detection/    4 Sigma rules mapped to T1027.010/T1027, a tuned Sysmon config, and the
              sample Event ID 4104 script block logs used in the live demo
tooling/      t1027010_hunter.py — a zero-dependency Python static analyzer that flags
              T1027.010 indicators in PowerShell source (wildcard alias/command
              resolution, character masking, encoded download cradles)
```

Open the deck directly in a browser: [`deck/presentation.html`](deck/presentation.html).

## Companion project

[**GlobWarden**](https://github.com/bobby-tablez/GlobWarden) is a separate, standalone
open-source tool that automates the other direction of this problem: point it at a
threat-intel report (URL, PDF, raw text, code, or a screenshot) and it uses an LLM —
cloud or fully local — to identify obfuscation techniques described in it and generate
validated detection content in five formats at once (regex, KQL, SPL, YARA-L, Sigma).

`tooling/t1027010_hunter.py` in this repo does the opposite: static analysis of
PowerShell scripts you already have in hand, no LLM involved.

## Updates

This repo tracks the deck as it evolves after the talk — if you're referencing this
later, check back for updates to `deck/`.
