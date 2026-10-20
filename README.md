# An Obfuscated Tale: From ATT&CK Origin to Detection Today

Supplemental materials for the ATT&CKcon 7.0 talk on MITRE ATT&CK **T1027.010 —
Command Obfuscation**: the STEEP#MAVERICK campaign that motivated the sub-technique's
creation, how the same obfuscation primitives show up in 2025–2026 campaigns
(GreenCharlie, MuddyWater-style ClickFix, ClearFake/Amatera/SectopRAT), and how to
actually detect it with the right telemetry stack.

> "Detection engineering is only as viable as the fuel you give it."

## The deck

| File | |
|---|---|
| [`deck/An-Obfuscated-Tale-ATTACKcon7.pdf`](deck/An-Obfuscated-Tale-ATTACKcon7.pdf) | The talk as presented — open this one. 29 slides, no PowerPoint needed. |
| [`deck/An-Obfuscated-Tale-ATTACKcon7.pptx`](deck/An-Obfuscated-Tale-ATTACKcon7.pptx) | The editable original, if you want to reuse a slide. |

## What's here

```
deck/         the talk, as PDF and PowerPoint
guides/       6 manuals: campaign deep-dive, technique reference, modern-campaign
              briefing, telemetry/detection guide, a character-masking + wildcard-IEX
              field card, and a one-week action checklist
detection/    5 Sigma rules mapped to T1027.010/T1027, a tuned Sysmon config, and the
              sample Event ID 4104 script block logs used in the talk
tooling/      t1027010_hunter.py — a zero-dependency Python static analyzer that flags
              T1027.010 indicators in PowerShell source (wildcard alias/command
              resolution, character masking, character harvesting, encoded download
              cradles)
```

### Start here

- **Want the one-page version?**
  [`guides/05-cheat-sheet-character-masking-wildcard-iex.md`](guides/05-cheat-sheet-character-masking-wildcard-iex.md)
  is the field card from the talk — three tables, built to be photographed.
- **Want to do something on Monday?**
  [`guides/06-one-week-action-checklist.md`](guides/06-one-week-action-checklist.md).
- **Want to scan your own scripts?** `python3 tooling/t1027010_hunter/t1027010_hunter.py <path>`
  — no dependencies, and it never executes or deobfuscates-and-runs what it reads.

## The "Same IEX, Infinite Disguises" slide

The obfuscation-zoo slide near the middle of the talk has a **"Full write-up ↗"**
pointer. It leads here:

- **Table 1/2/3** of the [field card](guides/05-cheat-sheet-character-masking-wildcard-iex.md)
  — every variant shown on that slide, plus what to match on instead.
- [`guides/02-t1027-010-technique.md`](guides/02-t1027-010-technique.md) **§5e** for
  format-string reconstruction and the index-reordering trap, and **§6d** for
  path-derived character harvesting (the "homemade IEX that bypasses AMSI" example).
- [`tooling/t1027010_hunter/samples/obfuscation_zoo.ps1`](tooling/t1027010_hunter/samples/obfuscation_zoo.ps1)
  — all four variants as a scannable sample.

Two of those four variants were **not** caught by this repo's own tool when it was first
written. Both are fixed, and the write-up explains exactly how each slipped through —
the `-f` format-operator check reconstructed fragments in argument order and ignored the
`{N}` placeholders, so `"{1}{0}" -f 'EX','I'` rebuilt as `EXI` instead of `IEX`. If
you're writing your own reconstruction logic, that one is worth checking.

## Companion project

[**GlobWarden**](https://github.com/bobby-tablez/GlobWarden) is a separate, standalone
open-source tool that automates the other direction of this problem: point it at a
threat-intel report (URL, PDF, raw text, code, or a screenshot) and it uses an LLM —
cloud or fully local — to identify obfuscation techniques described in it and generate
validated detection content in five formats at once (regex, KQL, SPL, YARA-L, Sigma).

`tooling/t1027010_hunter.py` in this repo does the opposite: static analysis of
PowerShell scripts you already have in hand, no LLM involved.

## A note on the examples

Every PowerShell sample in this repo is synthetic or derived from public vendor
reporting, written to teach detection. Placeholder domains, defanged indicators, no live
infrastructure, no real C2, no working weaponized payload. The Sigma rules and Sysmon
config are defensive content. The Python tool parses and reports — it never executes
what it scans.

## Updates

This repo tracks the material as it evolves after the talk — if you're referencing this
later, check back.
