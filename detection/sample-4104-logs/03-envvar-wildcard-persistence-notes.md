# Analyst notes — `03-envvar-wildcard-persistence.log`

**Do not reveal until after the room has had a chance to read the raw log and
guess the pattern.** Paired live-demo raw log: `03-envvar-wildcard-persistence.log`.
Sigma rule this maps to: `../sigma-rules/sigma-t1027010-envvar-path-wildcard.yml`.

```
$t=(gi "$env:windir\Sys??m32\sch?ask?.exe").FullName;& $t /Create /SC ONLOGON /TN "WindowsUpdateHelper" /TR "powershell -nop -w hidden -enc <base64, decoded below>" /RL HIGHEST /F
```

- `gi` is the built-in alias for `Get-Item`. The FileSystem provider
  resolves wildcard characters (`?` = exactly one char) in the path, so
  `Sys??m32\sch?ask?.exe` resolves to `System32\schtasks.exe` at runtime.
  The literal string "schtasks.exe" never appears in the script text — the
  same masking primitive as the `$env:???t??r???\*2\??h???k?` pattern
  documented in STEEP#MAVERICK, applied here via `Get-Item` instead of
  direct `$env:` wildcard expansion, which is the other common variant of
  this trick.
- `& $t ...` then invokes the resolved path directly (the call operator),
  so the process that ultimately launches is `schtasks.exe`, not
  `powershell.exe` — this is exactly why Sysmon Event ID 1's
  `ParentImage`/`Image` pairing (powershell.exe -> schtasks.exe) matters:
  the 4104 event shows you *how* the binary was resolved, Sysmon shows you
  the resulting process launch regardless of how it was named in source.
- The `/TR` (task run) argument re-launches `powershell.exe` with a base64,
  UTF-16LE `-enc` payload on trigger (ONLOGON) — a classic obfuscated-
  persistence pairing: wildcard-masked resolution of the *tool used to
  persist*, stacked with encoding of the *payload that persists*.
- `-enc` payload decodes to:
  ```
  Write-Host 'placeholder-task-action-synthetic-lab-only'
  ```
  an inert placeholder, not a functional payload.

Used by: `guides/04-telemetry-detection-guide.md` Section 1.2 / Section 3.2.
