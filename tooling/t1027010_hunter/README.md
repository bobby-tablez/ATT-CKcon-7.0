# t1027010_hunter

A small, real, zero-install Python 3 CLI that statically flags MITRE ATT&CK
**T1027.010 (Command Obfuscation)** indicators in PowerShell source or an
exported PowerShell Script Block Logging (Event ID 4104) text file.

Built as the take-home tool for the talk *"An Obfuscated Tale: From ATT&CK
Origin to Detection Today"* — the same wildcard-alias-resolution and
character-masking patterns covered in the STEEP#MAVERICK origin story and
T1027.010 sub-technique walkthrough.

## What it does

It reads PowerShell text (never executes it — see **Safety** below) and
looks for four families of obfuscation primitive, each mapped explicitly
to `T1027.010` and its parent `T1027`:

1. **Wildcard alias/command resolution feeding execution** — `Get-Alias` /
   `Get-Command` (or their `gal`/`gcm` aliases) invoked with a wildcard
   pattern (`i*x`, `*restm*`, etc.), either as a **literal token on the same
   line**, or **variable-indirect** (the pattern is assigned to a variable
   a few lines earlier, then the variable is passed to `Get-Alias`/
   `Get-Command`). The tool applies Python's `fnmatch` using the same
   `*`/`?` glob semantics PowerShell's wildcard resolution uses, against a
   list of dangerous targets (`iex`, `Invoke-Expression`, `irm`,
   `Invoke-RestMethod`, `iwr`, `Invoke-WebRequest`, `Invoke-Command`,
   download/decode methods). If the pattern in the script would actually
   match one of those names, that's a **statically provable** resolution
   path, not a guess — this is the novel STEEP#MAVERICK pattern that
   motivated the T1027.010 submission.
2. **Character masking** — six sub-patterns: backtick-split cmdlet names
   (`` I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n ``), case-randomized cmdlets
   (`InVoKe-ResTMethod`), string concatenation/reordering that reconstructs
   a cmdlet name (`'Inv' + 'oke-Exp' + 'ression'`), Unicode homoglyph
   substitution inside cmdlet-shaped identifiers (Cyrillic look-alikes for
   Latin letters), char-code array reconstruction (`[char]` cast over an
   array of character codes, joined), and `-f` format-operator
   reconstruction (`'{0}{1}' -f 'Inv','oke-Expression'`).
3. **Environment-variable-based obfuscation** — command strings assembled
   from `$env:` variables joined with `+`, or `${...}` curly-brace
   variable-splitting used to build a string piecewise.
4. **Encoded/download-cradle patterns** — `-EncodedCommand`/`-enc`,
   Base64 blobs (or `FromBase64String`) piped into `IEX`, and
   `Net.WebClient`/`Invoke-WebRequest`/`Invoke-RestMethod`
   download-and-execute chains.

Detection matching runs against a **comment-and-prose-blanked copy** of the
source — `#...` line comments, `<# ... #>` block comments, and
`@"..."@`/`@'...'@` here-string bodies are all excluded from matching
(though not from the `snippet` shown in output, which always comes from
the real, un-blanked line) — so plain-English text that merely *mentions*
a flag or cmdlet name while explaining or documenting it doesn't trigger
findings, whether that text lives in a comment or in a printed
handout/help-text string. See **What this tool will never catch** below
for what this lightweight approach still misses.

Every finding includes: the matched category, the offending line number and
snippet, a confidence label (`LOW`/`MEDIUM`/`HIGH`), a plain-English
rationale, and explicit ATT&CK tagging (`T1027.010` sub-technique, `T1027`
parent, with URLs).

## Safety — read this before you run it on anything real

**This tool never evaluates, executes, decodes-and-runs, or shells out to
PowerShell (or anything else) against the content it analyzes.** It does
not call `eval()`, `exec()`, `os.system()`, or `subprocess` on input data
anywhere in its source — this is a hard requirement, not a style choice.
It is pure text/regex analysis: read file, split into lines, apply
patterns, report matches. You can verify this yourself:

```bash
grep -nE '\beval\(|\bexec\(|subprocess|os\.system|os\.popen' t1027010_hunter.py
```

That should return nothing but this README's own description of the
guarantee.

## Install

None. Pure Python 3 standard library — no `pip install`, no virtualenv,
no external dependencies. If you have `python3` on the machine, you can run
this immediately.

Tested against Python 3.9+ (uses only `argparse`, `dataclasses`, `fnmatch`,
`json`, `os`, `pathlib`, `re`, `sys` from the standard library).

## Usage

```bash
python3 t1027010_hunter.py <file_or_directory> [--json] [--min-confidence {low,medium,high}]
```

- `<file_or_directory>` — a single `.ps1`/`.psm1`/`.psd1` file, a plain-text
  export of a 4104 script block log (`.txt`/`.log`), or a directory. Given a
  directory, the tool walks it recursively for files with those extensions.
- `--json` — emit machine-readable JSON (one object with `technique` metadata,
  `files_scanned`, and a `findings` array) instead of the text report.
- `--min-confidence {low,medium,high}` — only show findings at or above this
  level. Default `low` (show everything).

**Exit codes**: `0` if the scan completed with no `HIGH`-confidence
findings (or none at all), `1` if at least one `HIGH`-confidence finding is
present (useful for CI/pre-commit gating on obfuscated PowerShell landing in
a repo), `2` on a usage error (bad path, nothing to scan).

## Worked example (real output, captured by actually running the tool)

The `samples/` directory ships seven synthetic, defanged PowerShell files
used to build and validate this tool — including three regression files
added after two independent adversarial critiques (see **Round 2** and
**Round 3** below). Running the hunter against the whole directory:

```
$ python3 t1027010_hunter.py samples --min-confidence high

=== samples/character_masking.ps1 ===
  [HIGH] line 12 — Character masking: backtick-split cmdlet name  (T1027.010 / parent T1027)
    snippet : I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n "Write-Host 'cache warmed'"
    why     : Backtick-split identifier 'I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n' reconstructs (stripping backticks) to 'Invoke-Expression', which matches known dangerous target 'invoke-expression'.
  [HIGH] line 18 — Character masking: case-randomized cmdlet name  (T1027.010 / parent T1027)
    snippet : InVoKe-ResTMethod -Uri $url -Method Get | Out-Null
    why     : 'InVoKe-ResTMethod' is a case-randomized rendering of 'Invoke-RestMethod' (PowerShell resolves it identically; the irregular casing exists only to defeat case-sensitive literal-string signatures).
  [HIGH] line 21 — Character masking: string concatenation reconstructs cmdlet name  (T1027.010 / parent T1027)
    snippet : $name = 'Inv' + 'oke-Exp' + 'ression'
    why     : String fragments in ''Inv' + 'oke-Exp' + 'ression'' concatenate to 'Invoke-Expression', matching known dangerous target 'invoke-expression'.
  [HIGH] line 27 — Character masking: Unicode homoglyph substitution  (T1027.010 / parent T1027)
    snippet : Invоke-Command -ScriptBlock { Write-Host 'homoglyph path executed' }
    why     : Token 'Invоke-Command' mixes ASCII letters with non-Latin homoglyph character(s); Latinized reading is 'Invoke-Command'. Legitimate PowerShell source essentially never mixes scripts like this.

=== samples/env_and_download_cradle.ps1 ===
  [HIGH] line 26 — Base64-decoded payload piped into execution  (T1027.010 / parent T1027)
    snippet : [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64)) | IEX
    why     : Base64 blob and/or FromBase64String() decode combined with IEX/Invoke-Expression on the same line — classic decode-and-run chain.
  [HIGH] line 31 — Download-and-execute cradle  (T1027.010 / parent T1027)
    snippet : (New-Object Net.WebClient).DownloadString($src) | IEX
    why     : Net.WebClient / Invoke-WebRequest / Invoke-RestMethod download method combined with an execution sink (IEX/pipe) on the same line — fetches remote content and runs it without touching disk.
  [HIGH] line 39 — Encoded command invocation (-EncodedCommand/-enc)  (T1027.010 / parent T1027)
    snippet : $encArgs = "-NoP -W Hidden -Enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuA...
    why     : Use of -EncodedCommand/-enc smuggles a Base64/UTF-16LE encoded script past line-based content inspection; PowerShell decodes and runs it at process start.

=== samples/regression_new_evasions_caught.ps1 ===
  [HIGH] line 14 — Character masking: char-code array reconstructs cmdlet name  (T1027.010 / parent T1027)
    snippet : $codes = 73, 110, 118, 111, 107, 101, 45, 69, 120, 112, 114, 101, 115, 115, 105, 111, 110
    why     : Integer array '73, 110, 118, 111, 107, 101, 45, 69, 120, 112, 114, 101, 115, 115, 105, 111, 110' cast via [char] and joined nearby decodes to 'Invoke-Expression', matching known dangerous target 'invoke-expression'.
  [HIGH] line 20 — Character masking: -f format-operator reconstructs cmdlet name  (T1027.010 / parent T1027)
    snippet : $name2 = '{0}{1}{2}' -f 'Inv', 'oke-Expr', 'ession'
    why     : Format-operator expression ''{0}{1}{2}' -f 'Inv', 'oke-Expr', 'ession'' assembles 'Invoke-Expression', matching known dangerous target 'invoke-expression'.
  [HIGH] line 28 — Wildcard alias/command resolution feeding execution (variable-indirect)  (T1027.010 / parent T1027)
    snippet : $resolved = Get-Alias -Name $pattern
    why     : 'Get-Alias ... $pattern' resolves indirectly: $pattern was assigned the wildcard pattern 'i*x' on line 27, which statically resolves to a dangerous target via the same wildcard-semantics check used for literal patterns. Storing the pattern in a variable one line earlier does not defeat this check.

=== samples/wildcard_iex_pattern.ps1 ===
  [HIGH] line 15 — Wildcard alias/command resolution feeding execution  (T1027.010 / parent T1027)
    snippet : $resolved = Get-Alias -Name 'i*x' | Select-Object -First 1
    why     : 'Get-Alias' invoked with wildcard pattern 'i*x' — applying PowerShell's own wildcard semantics, this pattern statically resolves to a dangerous target (matches known alias/cmdlet in [...]). This is the STEEP#MAVERICK wildcard-IEX invocation pattern that motivated T1027.010.
  [HIGH] line 19 — Wildcard alias/command resolution feeding execution  (T1027.010 / parent T1027)
    snippet : $fetcher = (Get-Command '*restm*')[0]
    why     : 'Get-Command' invoked with wildcard pattern '*restm*' — applying PowerShell's own wildcard semantics, this pattern statically resolves to a dangerous target (matches known alias/cmdlet in [...]). This is the STEEP#MAVERICK wildcard-IEX invocation pattern that motivated T1027.010.

--- summary ---
files scanned : 7
findings      : 12  (HIGH=12 MEDIUM=0 LOW=0)
    2  Wildcard alias/command resolution feeding execution
    1  Character masking: backtick-split cmdlet name
    1  Character masking: case-randomized cmdlet name
    1  Character masking: string concatenation reconstructs cmdlet name
    1  Character masking: Unicode homoglyph substitution
    1  Base64-decoded payload piped into execution
    1  Download-and-execute cradle
    1  Encoded command invocation (-EncodedCommand/-enc)
    1  Character masking: char-code array reconstructs cmdlet name
    1  Character masking: -f format-operator reconstructs cmdlet name
    1  Wildcard alias/command resolution feeding execution (variable-indirect)

ATT&CK: T1027.010 (Command Obfuscation) — https://attack.mitre.org/techniques/T1027/010/
        parent T1027 (Obfuscated Files or Information) — https://attack.mitre.org/techniques/T1027/
```

(The truncated `[...]` in two rationale lines above is the same fixed
dangerous-target list shown in full when you run it yourself — trimmed
here only for README readability. Note `samples/clean_benign.ps1`,
`samples/regression_no_false_positives.ps1`, and
`samples/regression_herestring_no_false_positive.ps1` all produce zero
findings, so none of them appear in a `--min-confidence high` run — see
below.)

And the negative controls — `samples/clean_benign.ps1` (ordinary local
reporting script), `samples/regression_no_false_positives.ps1`
(comment-heavy deploy helper + common typo-cased cmdlets — see **Round 2**
below), and `samples/regression_herestring_no_false_positive.ps1`
(here-string cheat-sheet prose — see **Round 3** below) — all three
produce **zero findings**:

```
$ python3 t1027010_hunter.py samples/clean_benign.ps1
No T1027.010 indicators found at or above confidence 'low' across 1 file(s) scanned.
$ python3 t1027010_hunter.py samples/regression_no_false_positives.ps1
No T1027.010 indicators found at or above confidence 'low' across 1 file(s) scanned.
$ python3 t1027010_hunter.py samples/regression_herestring_no_false_positive.ps1
No T1027.010 indicators found at or above confidence 'low' across 1 file(s) scanned.
```

`--json` output (the new-evasions regression sample, machine-readable,
captured verbatim from a real run — exit code is `1` here because
HIGH-confidence findings are present):

```
$ python3 t1027010_hunter.py samples/regression_new_evasions_caught.ps1 --json
{
  "tool": "t1027010_hunter",
  "technique": {
    "id": "T1027.010",
    "name": "Command Obfuscation",
    "url": "https://attack.mitre.org/techniques/T1027/010/",
    "parent_id": "T1027",
    "parent_name": "Obfuscated Files or Information",
    "parent_url": "https://attack.mitre.org/techniques/T1027/"
  },
  "files_scanned": [
    "samples/regression_new_evasions_caught.ps1"
  ],
  "finding_count": 3,
  "findings": [
    {
      "file": "samples/regression_new_evasions_caught.ps1",
      "line": 14,
      "category": "character-masking-charcode",
      "label": "Character masking: char-code array reconstructs cmdlet name",
      "snippet": "$codes = 73, 110, 118, 111, 107, 101, 45, 69, 120, 112, 114, 101, 115, 115, 105, 111, 110",
      "confidence": "HIGH",
      "rationale": "Integer array '73, 110, 118, 111, 107, 101, 45, 69, 120, 112, 114, 101, 115, 115, 105, 111, 110' cast via [char] and joined nearby decodes to 'Invoke-Expression', matching known dangerous target 'invoke-expression'.",
      "technique_id": "T1027.010",
      "technique_name": "Command Obfuscation",
      "technique_url": "https://attack.mitre.org/techniques/T1027/010/",
      "parent_id": "T1027",
      "parent_name": "Obfuscated Files or Information",
      "parent_url": "https://attack.mitre.org/techniques/T1027/"
    },
    {
      "file": "samples/regression_new_evasions_caught.ps1",
      "line": 20,
      "category": "character-masking-format-op",
      "label": "Character masking: -f format-operator reconstructs cmdlet name",
      "snippet": "$name2 = '{0}{1}{2}' -f 'Inv', 'oke-Expr', 'ession'",
      "confidence": "HIGH",
      "rationale": "Format-operator expression ''{0}{1}{2}' -f 'Inv', 'oke-Expr', 'ession'' assembles 'Invoke-Expression', matching known dangerous target 'invoke-expression'.",
      "technique_id": "T1027.010",
      "technique_name": "Command Obfuscation",
      "technique_url": "https://attack.mitre.org/techniques/T1027/010/",
      "parent_id": "T1027",
      "parent_name": "Obfuscated Files or Information",
      "parent_url": "https://attack.mitre.org/techniques/T1027/"
    },
    {
      "file": "samples/regression_new_evasions_caught.ps1",
      "line": 28,
      "category": "wildcard-resolution",
      "label": "Wildcard alias/command resolution feeding execution (variable-indirect)",
      "snippet": "$resolved = Get-Alias -Name $pattern",
      "confidence": "HIGH",
      "rationale": "'Get-Alias ... $pattern' resolves indirectly: $pattern was assigned the wildcard pattern 'i*x' on line 27, which statically resolves to a dangerous target via the same wildcard-semantics check used for literal patterns. Storing the pattern in a variable one line earlier does not defeat this check.",
      "technique_id": "T1027.010",
      "technique_name": "Command Obfuscation",
      "technique_url": "https://attack.mitre.org/techniques/T1027/010/",
      "parent_id": "T1027",
      "parent_name": "Obfuscated Files or Information",
      "parent_url": "https://attack.mitre.org/techniques/T1027/"
    }
  ]
}
```

## Samples

| File | Demonstrates |
|---|---|
| `samples/clean_benign.ps1` | Negative control — ordinary disk-usage reporting script, no obfuscation. Should produce zero findings. |
| `samples/wildcard_iex_pattern.ps1` | Category 1 — `Get-Alias`/`Get-Command` wildcard resolution to `iex`/`Invoke-RestMethod` (the STEEP#MAVERICK pattern). |
| `samples/character_masking.ps1` | Category 2 — four character-masking sub-patterns: backtick split, case randomization, string concatenation, Unicode homoglyph. |
| `samples/env_and_download_cradle.ps1` | Categories 3 & 4 — `$env:`/`${...}` reconstruction, Base64→IEX, WebClient download cradle, `-EncodedCommand`. |
| `samples/regression_no_false_positives.ps1` | Negative control, round 2 — comment-heavy deploy script that *mentions* `-EncodedCommand`/`Invoke-Expression` in prose, plus common typo-cased cmdlets (`invoke-WebRequest`, `invoke-restmethod`). Locks in the round-1 critique's two false-positive fixes. Should produce zero findings. |
| `samples/regression_new_evasions_caught.ps1` | Two more character-masking sub-patterns (char-code array, `-f` format operator) plus the variable-indirect wildcard fix. Locks in the round-1 critique's three false-negative fixes. Should produce exactly 3 HIGH findings. |
| `samples/regression_herestring_no_false_positive.ps1` | Negative control, round 3 — a plausible "print a T1027.010 cheat sheet" helper script with reference prose (mentioning `-EncodedCommand`, `iex`, `$env:` reconstruction, backtick masking, case games) inside both here-string quote styles (`@"..."@` and `@'...'@`). Locks in the round-2 critique's here-string fix. Should produce zero findings. |
| `samples/obfuscation_zoo.ps1` | The "Same IEX, Infinite Disguises" variants from the talk — concatenation, **index-reordered** `-f` format operator, char-code array, and path-derived character harvesting. Added post-talk; see "Round 4" below. |

All samples are synthetic and defanged: placeholder domains
(`contoso-corp[.]test`), defanged scheme/dots (`hxxps`, `[.]`), and every
"payload" is a harmless `Write-Host` string. None of them contact any real
infrastructure, and the tool itself never executes them regardless.

## ATT&CK mapping rationale

| Detection category | Sub-technique element it maps to |
|---|---|
| Wildcard alias/command resolution | T1027.010 explicitly calls out obfuscating "command and script syntax" via aliases and wildcards so the literal cmdlet name never appears — this is the exact primitive documented after STEEP#MAVERICK's wildcard-IEX pattern. |
| Backtick split / case randomization / string concat / homoglyphs / char-code arrays / `-f` format operator | T1027.010 covers "special characters," case manipulation, and reordering used specifically to defeat literal pattern-matching / signature detection on command strings. |
| `$env:` / `${...}` reconstruction | T1027.010 covers building command strings from environment variables as a documented obfuscation vector. |
| `-EncodedCommand` / Base64→IEX / download cradle | These are the delivery/execution-sink mechanics most obfuscated command strings terminate in; T1027 (parent) covers "Obfuscated Files or Information" broadly, and T1027.010 is the command-level instance of it. Every finding is tagged with both IDs so detection content built from this tool's output rolls up correctly in ATT&CK-mapped coverage matrices. |

Every `Finding` in the tool's output (text or JSON) carries both
`technique_id`/`technique_name`/`technique_url` (T1027.010) and
`parent_id`/`parent_name`/`parent_url` (T1027) fields, so this maps
directly onto the Sigma rules in `../../detection/` without any manual
re-tagging.

## Round 2: fixes from an independent adversarial critique

This tool went through an independent adversarial critique after the first
build. (That critique report is internal orchestration material and is not
shipped here.) The critique wrote its own test cases — not reused from
this tool's own samples or HANDOFF.md — and found real bugs. Fixed, with
each verified by re-running the critic's exact reproduction script:

- **Comments/prose triggering findings.** A well-commented, realistic WinRM
  deploy script (legitimately using `-EncodedCommand`) lit up 2 of 3 HIGH
  findings on plain-English comment lines, flipping the advertised CI-gate
  exit code on clean code. Fixed by matching against a comment-blanked copy
  of the source (`#...` and `<# ... #>` are excluded from matching, not
  from the displayed snippet). While fixing this, also caught and fixed a
  real bug in the fix itself: the initial comment-stripping implementation
  silently no-op'd on any file with a trailing newline (i.e. almost every
  real file) due to a `str.split("\n")` vs. `str.splitlines()` line-count
  mismatch that tripped a defensive fallback. Both are covered by
  `samples/regression_no_false_positives.ps1`.
- **HIGH-confidence false positive on ordinary typo casing.**
  `invoke-WebRequest` (lowercase first letter, otherwise correct
  PascalCase — an extremely common human typo) scored as a HIGH
  case-randomization finding. Fixed: a single leading-letter case
  difference is no longer flagged at all; genuine case-randomization now
  requires the mismatch to extend beyond the first letter, with a higher
  bar (3+ mismatched positions and 3+ case transitions) for HIGH vs. a
  lighter (2+/2+) bar capped at MEDIUM.
- **Flagship wildcard-resolution detector defeated by a one-line variable
  indirection.** `$pattern = 'i*x'; Get-Alias -Name $pattern` produced zero
  findings because the original detector only looked for a literal
  wildcard token on the same line as `Get-Alias`/`Get-Command`. Fixed with
  a bounded (6-line) backward lookback for a simple `$var = '<pattern>'`
  assignment feeding the lookup call — see `find_variable_indirect_wildcard()`
  in the source.
- **Two entire character-masking techniques were undetected and
  undisclosed.** Char-code array reconstruction (`[char]` cast over an
  array of character codes, joined) and `-f` format-operator
  reconstruction were not implemented at all. Both are now detected
  (`find_charcode_reconstruction()`, `find_format_operator_reconstruction()`).
- **Code quality**: unbounded rationale text on pathological/repetitive
  input is now truncated consistently with `snippet` everywhere it's
  interpolated; the unused `field` import was removed.

**Deliberately not fixed** — the critique's fourth false-negative variant
(a multi-line download-and-run chain wrapped in a helper function using
`[scriptblock]::Create`, four lines removed from the network call, never
touching the literal string `IEX`) is real, reproduces, and is *not*
caught. This is the same class of gap already disclosed pre-critique
(same-line-only scope on Category 4 detectors) but the critic's variant is
more general than the one originally documented. Fixing it properly needs
actual data-flow/taint tracking across statements and function boundaries
— a fundamentally different (and much larger) piece of engineering than
the bounded few-line lookback/lookahead used for the other fixes above,
with real risk of introducing new false positives if done hastily. Left
as the top disclosed gap; see **What this tool will never catch** below
and `HANDOFF.md`.

## Round 3: independent round-2 critique confirmed the fixes, plus one more

A second, fresh independent critique
re-derived every round-1 reproduction from scratch — not from this tool's
own `samples/regression_*.ps1` files — and passed the tool: all 3 HIGH
fixes above confirmed genuine, safety/performance held up under new stress
tests, and the multi-line Category-4 gap was confirmed still honestly
disclosed. It also found one new, real false positive, flagged as a
nice-to-have rather than a blocker:

- **Here-string prose triggering findings.** A plausible "print a
  T1027.010 cheat sheet for my team" helper script — a very likely file
  for *this specific talk's* audience to write — printed reference text
  via a here-string (`@"..."@`) that named `-EncodedCommand`, `iex`, and
  `$env:` reconstruction for teaching purposes. Every line of that prose
  was scanned as live code, firing 2 HIGH + 1 MEDIUM and flipping the exit
  code. This was already the #1 item this file's own HANDOFF.md told the
  next critic to try (a comment-blindness fix that handles `#`/`<# #>`
  but not here-strings is an obvious next place to look), and the critic
  found it exactly as predicted. Fixed the same way block comments are
  handled: here-string bodies (`@"..."@` and `@'...'@`) are now blanked
  before matching too, not shown-but-scanned. Verified against the
  critic's exact reproduction (`training_notes.ps1`): 2 HIGH + 1 MEDIUM →
  zero findings. Regression-locked in `samples/regression_herestring_no_false_positive.ps1`,
  which includes both here-string quote styles and deliberately embeds
  trigger phrases from *other* detector categories (backtick masking,
  case randomization) inside the here-string body to confirm the blanking
  isn't accidentally scoped to just the Category-3/4 keywords from the
  critic's specific example.

Not attempted in this round: the critique's two other new findings
(splatting — `Get-Alias @lookupArgs` instead of a `$variable` — as a
fourth way to defeat the wildcard-resolution detector, and one level of
plain `$var2 = $var1` variable-to-variable copying in the wildcard
lookback) were logged as narrower nice-to-haves, not blockers, and are
tracked in `HANDOFF.md` rather than fixed here, to keep this round's
change scoped to the one item the coordinator asked for.

## Round 4: tested against the talk's own slides, post-conference

After the ATT&CKcon 7.0 deck was finalised, the tool was run against the four variants
shown on the "Same IEX, Infinite Disguises" slide. **It caught two of four.** Both
misses are now fixed and locked in by `samples/obfuscation_zoo.ps1`.

**Miss 1 — index-reordered format operator.** The `-f` check reconstructed fragments in
*argument* order and ignored the `{N}` placeholders, so:

```powershell
("{1}{0}" -f 'EX','I')     # rebuilt as 'EXI' -> no match
                           # actually resolves to 'IEX'
```

The reordering *is* the technique, so ignoring placeholder order missed the most common
form of it. The check now parses the `{N}` order and reassembles accordingly. This is
an easy bug to reproduce in your own tooling — worth checking yours.

**Miss 2 — path-derived character harvesting.** A new detector (`path-char-harvest`).
A wildcard `Resolve-Path` yields a filesystem path, then fixed character offsets are
indexed out of the resulting string and joined into the command name:

```powershell
.((rvpa "\???????\*2\*POO*\*river?\?6*").Path[4,15,34] -join '')
```

Neither the character-masking checks nor the wildcard-resolution checks saw this,
because the target characters come from outside the script entirely. The detector keys
on the stable shape — a multi-element integer index list into a string (often a
`.Path`/`.FullName`/`.Name` property), joined — and grades confidence by whether the
source is a resolved path and whether the result is actually invoked. Bare index slices
need 3+ indices before they are reported, so ordinary array work does not trip it.

All three negative-control samples still report zero findings after both changes.

See `guides/02-t1027-010-technique.md` §5e and §6d for the full write-up.

## What this tool will never catch (read this before trusting a clean scan)

This is a regex/text-pattern tool, not a PowerShell parser — no AST, no
tokenizer, no data-flow/taint tracking across statements. Known-undetected
obfuscation variants, verified by writing and running each one against the
current tool:

- **Any Category-4 (encoded/download-cradle) chain split across multiple
  lines or wrapped in a helper function.** All of `find_encoded_command`,
  `find_base64_execute_chain`, and `find_download_cradle` require the
  decode/download call and the execution sink on the **same line**. This
  is the single most exploitable gap — see **Round 2** above.
- **Char-code/format-operator/backtick/concatenation reconstruction where
  the result isn't checked against `DANGEROUS_TARGETS`/`CANONICAL_WATCHLIST`
  before being executed some other way** (e.g. built into a `[scriptblock]`
  or passed to `.Invoke()` several statements later) — same underlying
  data-flow limitation as above.
- **XOR / ROT13 / custom substitution-cipher obfuscation** of a command
  string — not a pattern this tool looks for at all.
- **.NET reflection-based invocation**
  (`[Type]::GetMethod(...).Invoke(...)`, `Add-Type` + P/Invoke tricks) used
  to reach an execution sink without ever naming a PowerShell cmdlet.
- **Attacker-defined custom aliases.** `Set-Alias -Name zz -Value
  Invoke-Expression` followed by wildcard-resolving `zz` is only caught at
  MEDIUM (via the "resolved handle is invoked nearby" heuristic), not HIGH
  — the dangerous-target list is fixed/hardcoded and doesn't track
  `Set-Alias` definitions made earlier in the same file.
- **Splatting instead of a `$variable` argument.** `$lookupArgs = @{ Name =
  'i*x' }; Get-Alias @lookupArgs` defeats both the literal and
  variable-indirect wildcard detectors — `find_variable_indirect_wildcard()`
  only recognizes a `$`-sigil variable argument, and splatting uses `@`
  instead. This is ordinary, idiomatic PowerShell style (recommended for
  cmdlets with several named parameters), not an exotic construction.
- **Variable-to-variable copies in the wildcard lookback.** `$raw = 'i*x';
  $pattern = $raw; Get-Alias -Name $pattern` is missed even though `$raw`'s
  assignment is well within the 6-line lookback window, because
  `find_variable_indirect_wildcard()` only recognizes a direct `$var =
  '<literal>'` assignment, not one variable copied from another.
- **Sparse backtick masking.** The backtick detector requires 3+
  consecutive backtick-split letters; a single backtick
  (`` I`nvoke-Expression ``) — arguably the *more* realistic amount of
  obfuscation an attacker would actually use — is invisible to it.
- **Case-randomization outside the ~12-cmdlet watchlist**, or
  **homoglyph substitution outside the specific Cyrillic-lookalike set**
  checked (`CANONICAL_WATCHLIST`, `_HOMOGLYPH_CHARS` in the source) — both
  are deliberately narrow to keep the false-positive rate near zero, at
  the cost of coverage outside that scope.
- **Anything split across two files** (e.g. a loader script and a separate
  payload script) — each file is scored independently, no cross-file
  correlation.
- **`.evtx`/`.xml`/`.csv` exports of 4104 logs in directory-scan mode** —
  the directory walker only picks up `.ps1 .psm1 .psd1 .txt .log` by
  extension; pass such a file directly instead.

See `HANDOFF.md` in this directory for the full, evidence-backed writeup —
every gap above (and a few narrower ones) with the actual reproduction
command and output, plus specific guidance on what to stress-test hardest.
Confidence labels throughout are a heuristic ordering (`HIGH > MEDIUM >
LOW`), not a statistically calibrated probability — this tool has been
validated against a couple dozen purpose-built samples, not a large
real-world corpus.
