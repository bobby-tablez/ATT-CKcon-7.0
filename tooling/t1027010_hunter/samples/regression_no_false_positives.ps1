<#
    Regression-NoFalsePositives.ps1  (SYNTHETIC — negative control)

    Added after an independent round-1 adversarial critique found two real
    false-positive classes: (1) plain-English comments that merely mention
    an obfuscation-relevant flag/cmdlet name, and (2) ordinary human typo
    casing (lowercase first letter, otherwise correct PascalCase). Both are
    reproduced here deliberately, on plausible benign code, as a locked-in
    regression test. This file should produce ZERO findings at any
    confidence level. If it doesn't, that's a tool bug, not a problem with
    this script.

    This comment block itself mentions -EncodedCommand, Invoke-Expression,
    Get-Command, and wildcard resolution by name -- on purpose, to prove
    comment/prose text is excluded from matching, not just code.
#>

function Test-ServiceHealth {
    <#
        Ordinary health-check helper. Note the deliberate typo casing below
        (lowercase first letter) -- an extremely common way real engineers
        type this cmdlet after years of muscle memory. Not obfuscation.
    #>
    param([string]$Uri = "https://example.com/health")
    $resp = invoke-WebRequest -Uri $Uri -UseBasicParsing
    return $resp.StatusCode -eq 200
}

function Get-ConfigSummary {
    # invoke-restmethod (all lowercase) is also extremely common -- people
    # tab-complete and PowerShell is case-insensitive, so this behaves
    # identically to Invoke-RestMethod. Not a case-randomization attempt.
    $config = invoke-restmethod -Uri "https://example.com/config" -Method Get
    return $config
}

# Legitimate ops teams sometimes need -EncodedCommand to avoid quoting hell
# when passing multi-line script blocks over WinRM (this is Microsoft's own
# documented pattern) -- but this comment is prose *about* that pattern,
# not an invocation of it, so it must not fire.

Test-ServiceHealth
Get-ConfigSummary
