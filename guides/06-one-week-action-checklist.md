# One-Week Action Checklist: From "We Have No Idea" to "We'd Catch This"

Start Monday. Each day is scoped to fit around a normal workload — none of these are
all-day projects. By end of week you should have Script Block Logging on, a tuned
Sysmon config deployed, and confirmed (not assumed) SIEM ingestion of both.

Do these in order — Day 4–5 validation is meaningless without Day 1–3 deployed first.

---

## Day 1 (Monday) — Enable PowerShell Script Block Logging

Goal: Event ID **4104** (deobfuscated script block content) flowing into the Windows
Event Log on every endpoint you care about.

### Option A — Group Policy (domain-joined fleet)

- [ ] Open **Group Policy Management Console** → edit (or create) a GPO linked to the
      OU containing your target endpoints.
- [ ] Navigate to:
      `Computer Configuration → Policies → Administrative Templates → Windows
      Components → Windows PowerShell`
- [ ] Set **"Turn on PowerShell Script Block Logging"** → **Enabled**.
      - [ ] Check **"Log script block invocation start / stop events"** only if you
            have log volume headroom — it roughly doubles event count and is
            optional; 4104 alone is sufficient for detection content.
- [ ] While you're in this GPO node, also set **"Turn on Module Logging"** →
      **Enabled**, Module Names = `*` (this is Event ID 4103 — required by the talk's
      log-source list alongside 4104; do it now, it's the same GPO).
- [ ] `gpupdate /force` on a test box, confirm with:
      ```powershell
      Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5 |
        Where-Object Id -in 4103,4104
      ```
- [ ] Roll the GPO to a pilot OU, confirm events land, then roll to the full fleet.

### Option B — Registry (no GPO / non-domain endpoints, e.g. via RMM/Intune script)

```powershell
# Script Block Logging (Event ID 4104)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Module Logging (Event ID 4103)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
  -Name "EnableModuleLogging" -Value 1 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
  -Name "*" -Value "*" -Type String
```

- [ ] Push via your RMM/Intune/config-management tool of choice.
- [ ] Increase the PowerShell Operational log size **before** you need it — 4104 is
      verbose and the default log rolls over fast:
      ```
      wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1073741824
      ```
      (1 GB shown; size to your retention needs.)
- [ ] Confirm PowerShell version ≥ 5.0 on target endpoints (`$PSVersionTable`) —
      Script Block Logging requires it; older hosts need a PowerShell upgrade first.

**End of Day 1 checkpoint:** 4104 and 4103 events are generating on at least one pilot
host. Do not proceed to Day 2 until this is true.

---

## Day 2–3 (Tue–Wed) — Deploy the tuned Sysmon config

Goal: Sysmon running everywhere with the T1027.010-tuned config, generating Event ID
**1** (process creation, full command line), **7** (image load), and **17** (pipe
created).

This talk's kit ships a ready-to-use config at `detection/sysmon-config-t1027010.xml`
— it's pre-tuned for the obfuscation and wildcard-resolution behaviors covered in the
cheat sheet (`guides/05-cheat-sheet-character-masking-wildcard-iex.md`). You do not
need to write Sysmon XML from scratch; deploy that file as-is, then tune from there.

- [ ] Download Sysmon from Microsoft Sysinternals (verify signature) onto a pilot
      host.
- [ ] Install with the kit's config:
      ```
      sysmon64.exe -accepteula -i detection\sysmon-config-t1027010.xml
      ```
- [ ] Confirm the service is running and bound to the expected config:
      ```powershell
      Get-Service Sysmon64
      sysmon64.exe -c          # dumps active config for diff/verification
      ```
- [ ] Confirm events 1, 7, and 17 are landing:
      ```powershell
      Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
        Where-Object Id -in 1,7,17
      ```
- [ ] **Updating an already-installed Sysmon** (pilot iteration, or rolling a config
      fix later in the week):
      ```
      sysmon64.exe -c detection\sysmon-config-t1027010.xml
      ```
      (`-c` hot-swaps the config without a reinstall/reboot.)
- [ ] Watch the pilot host for 12–24h. If noisy (high-volume line-of-business
      PowerShell, dev boxes, build servers), add targeted exclusions in a local copy
      of the config rather than disabling event types — talk to whoever owns the
      config before broad edits, since exclusions are the easiest way to blind
      yourself to the exact wildcard-resolution behavior this config exists to catch.
- [ ] Push to the full fleet via your standard software deployment channel (GPO
      startup script, Intune Win32 app, SCCM package, RMM script — whatever you
      already use for Sysmon today; the install/update commands above are identical
      regardless of delivery mechanism).
- [ ] Document the config version/hash you deployed somewhere your team will actually
      look (ticket, wiki, README) — you will need to know this during Day 4–5
      validation and again next time the config is revised.

**End of Day 3 checkpoint:** Sysmon 1/7/17 flowing from the full pilot group, config
version documented.

---

## Day 4–5 (Thu–Fri) — Validate SIEM ingestion

Goal: prove the logs from Day 1–3 are actually arriving and queryable in your SIEM —
not just present on the endpoint. "The GPO applied" is not the same claim as "my SIEM
can see it." Run these regardless of which backend you run.

### Microsoft Sentinel / Defender (KQL)

```kql
// PowerShell Script Block Logging ingestion — last 24h, by host
Event
| where EventLog == "Microsoft-Windows-PowerShell/Operational"
| where EventID in (4103, 4104)
| summarize EventCount = count(), LastSeen = max(TimeGenerated) by Computer, EventID
| order by LastSeen desc
```

```kql
// Sysmon ingestion — last 24h, event IDs 1 / 7 / 17, by host
Event
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID in (1, 7, 17)
| summarize EventCount = count(), LastSeen = max(TimeGenerated) by Computer, EventID
| order by LastSeen desc
```

- [ ] Zero rows for a pilot host = ingestion problem (AMA/DCR misconfigured, wrong
      table, agent not installed) — not a rule problem. Fix ingestion before you ever
      write or test a Sigma rule against this data.
- [ ] If you're on Defender for Endpoint proper, cross-check `DeviceProcessEvents`
      for the same pilot hosts over the same window to confirm process-creation
      telemetry independently of the Windows Event forwarding path.

### Splunk (SPL)

```spl
index=wineventlog EventCode IN (4103, 4104)
| stats count, latest(_time) as last_seen by host, EventCode
| convert ctime(last_seen)
```

```spl
index=sysmon EventCode IN (1, 7, 17)
| stats count, latest(_time) as last_seen by host, EventCode
| convert ctime(last_seen)
```
(Adjust `index=` to whatever your Windows Event / Sysmon TA writes to in your
environment — `wineventlog` and `sysmon` are the common defaults for the Splunk
Add-on for Microsoft Sysmon / Windows TA, confirm against your own props.conf.)

### Any other backend (Sigma-first shops)

- [ ] If you already maintain Sigma rules (including the T1027.010-mapped rules
      shipped elsewhere in this kit's `detection/` folder), don't hand-translate —
      compile them with `pySigma` / `sigma-cli` against your actual backend
      (`sigma convert -t <your_backend> ...`) and run the compiled query over the
      last 24h.
- [ ] **Zero hits from a compiled rule during pilot validation means ingestion is
      broken, not that the rule is wrong.** Confirm ingestion with a raw count query
      (equivalent to the KQL/SPL above in your platform's native language) *before*
      concluding a detection rule needs tuning.

**End of Day 5 checkpoint:** you have a query result, in your own SIEM, showing 4103,
4104, and Sysmon 1/7/17 events from the pilot host(s) within the last 24 hours.

---

## Day 6–7 (Sat/Mon-of-next-week or your team's next working days) — Prove it end-to-end

Goal: close the loop from "logs exist" to "we'd actually get paged."

- [ ] Replay a sample obfuscated command from the cheat sheet
      (`guides/05-cheat-sheet-character-masking-wildcard-iex.md`) or the kit's sample
      4104 excerpts (`detection/`) on the pilot host in an isolated lab — never
      production, never against real infrastructure.
- [ ] Confirm the resulting 4104/Sysmon events reach the SIEM (same queries as
      Day 4–5, scoped to the test host and time window).
- [ ] Run the T1027.010-mapped detection rule(s) against that traffic and confirm at
      least one fires.
- [ ] If nothing fires: work backward through Day 1 → 5 in order — logging enabled?
      Sysmon config deployed and current? Ingestion confirmed? Rule compiled for the
      right backend? Don't skip straight to "the rule is wrong."
- [ ] Write down what you just did (two paragraphs is enough) somewhere your team
      keeps runbooks. Future-you, at 2 a.m. during a real incident, will not remember
      the query syntax above.
- [ ] Put a recurring calendar reminder (quarterly is reasonable) to re-diff the
      deployed Sysmon config against `detection/sysmon-config-t1027010.xml` upstream
      — configs drift, exclusions accumulate, and this is the single most common way
      teams silently lose the visibility they stood up this week.

**End of week:** Script Block Logging on, tuned Sysmon deployed, SIEM ingestion
confirmed with your own queries, and at least one end-to-end detection fire against
replayed T1027.010 behavior. That's the whole talk, operationalized in five days.
