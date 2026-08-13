<#
    Regression-NewEvasionsCaught.ps1  (SYNTHETIC / DEFANGED)

    Added after an independent round-1 adversarial critique devised three
    evasion variants that slipped past the original detector set with zero
    findings. All three are now caught; this file locks that in as a
    regression test. Every "payload" below is a harmless Write-Host string
    -- no live infrastructure, no real weaponized behavior.
#>

# 1. Char-code array reconstruction: build "Invoke-Expression" from an
#    array of character codes cast via [char] and joined, instead of
#    typing the cmdlet name or concatenating literal string fragments.
$codes = 73, 110, 118, 111, 107, 101, 45, 69, 120, 112, 114, 101, 115, 115, 105, 111, 110
$name1 = ($codes | ForEach-Object { [char]$_ }) -join ''
& $name1 "Write-Host 'charcode path executed'"

# 2. -f format-operator reconstruction: assemble the cmdlet name via
#    PowerShell's format operator instead of +/-join concatenation.
$name2 = '{0}{1}{2}' -f 'Inv', 'oke-Expr', 'ession'
& $name2 "Write-Host 'format operator path executed'"

# 3. Variable-indirect wildcard resolution: the wildcard pattern is stored
#    in a variable one line before the Get-Alias/Get-Command call instead
#    of being a literal token on the same line -- defeats a purely
#    same-line detector with almost no attacker effort.
$pattern = 'i*x'
$resolved = Get-Alias -Name $pattern
& $resolved.Name "Write-Host 'variable-indirect wildcard path executed'"
