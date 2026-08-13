<#
    Regression-HereStringNoFalsePositive.ps1  (SYNTHETIC — negative control)

    Added after an independent round-2 adversarial critique found that a
    plausible "print a T1027.010 cheat sheet for my team" helper script --
    exactly the kind of file this talk's audience would write for
    themselves -- fired 2 HIGH + 1 MEDIUM findings because the reference
    prose lived inside a here-string (@"..."@), and here-strings weren't
    excluded from matching the way '#'/'<# #>' comments already were. This
    file should produce ZERO findings. If it doesn't, that's a tool bug.
#>

function Show-T1027010CheatSheet {
    $notes = @"
T1027.010 Command Obfuscation - quick reference for defenders

Watch for these patterns in Script Block Logging (4104):
  - Get-Alias / Get-Command with wildcards resolving to Invoke-Expression
  - -EncodedCommand smuggling a Base64 payload past line-based inspection
  - $env:UserName + $env:ComputerName style string reconstruction used to
    rebuild a command name piecewise instead of a plain log message
  - iex, irm, invoke-webrequest typed in odd casing to dodge literal
    signature matching

None of the above happens in this script - it is only printed as
reference text for the audience handout.
"@
    Write-Host $notes
}

# Single-quoted here-string variant (@'...'@) -- no backtick/variable
# expansion inside, but still needs the same treatment.
$plainNotes = @'
Reminder: I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n backtick-splitting and
InVoKe-ResTMethod case games are both covered in the character-masking
section of the handout. Neither is actually invoked here.
'@

Show-T1027010CheatSheet
Write-Host $plainNotes
