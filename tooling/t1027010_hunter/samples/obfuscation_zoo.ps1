<#
    ObfuscationZoo.ps1  (SYNTHETIC / DEFANGED)

    The "Same IEX, Infinite Disguises" variants shown in the ATT&CKcon 7.0 talk.
    Four ways to spell one three-character cmdlet alias without ever typing it.

    Two of these were added to the detector set after the talk deck was finalised:
    the index-reordered format operator, and path-derived character harvesting.
    The original -f check reconstructed fragments in argument order and so rebuilt
    "{1}{0}" -f 'EX','I' as 'EXI' rather than 'IEX' -- the reordering is the whole
    technique, and ignoring it missed the most common form.

    Every "payload" below is a harmless Write-Host string. No live infrastructure,
    no real weaponized behavior. Safe to scan; pointless to run.
#>

# 1. Plain concatenation -- the full literal never appears as one token.
$a = ('i' + 'e' + 'x')
& $a "Write-Host 'concat path executed'"

# 2. Format operator, INDEX-REORDERED. Reading the arguments left to right spells
#    'EXI'; the {1}{0} placeholders are what actually rebuild 'IEX'. Any
#    reconstruction that ignores placeholder order is blind to this.
$b = ("{1}{0}" -f 'EX', 'I')
& $b "Write-Host 'format-operator reorder path executed'"

# 3. Character codes cast and joined.
$c = [char[]](105, 101, 120) -join ''
& $c "Write-Host 'char-array path executed'"

# 4. Path-derived character harvesting. A wildcard Resolve-Path produces some
#    filesystem path, and specific character offsets are indexed out of the
#    resulting string and joined into the command name. Nothing in the script
#    spells the target and no alias table is queried, so neither literal matching
#    nor Get-Alias/Get-Command heuristics catch it.
#
#    The real-world form seen in the wild resolves a System32 path; the synthetic
#    stand-in below indexes a local string so the sample is inert and portable.
$src = (Resolve-Path ".").Path
# offsets chosen per-host in the wild -- shown here only to exercise the pattern
$d = $src[0, 1, 2] -join ''
Write-Host "harvested: $d"
