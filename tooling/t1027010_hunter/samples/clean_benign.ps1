<#
    Maintenance-Report.ps1  (SYNTHETIC — benign control sample)

    Ordinary local disk-usage reporting script. No obfuscation, no remote
    execution, no encoded commands. This exists as a negative control for
    t1027010_hunter.py — it should produce zero (or near-zero, low-confidence
    only) findings. If it lights up with HIGH-confidence findings, that's a
    false-positive bug in the tool, not a problem with this script.
#>

param(
    [string]$OutputPath = "C:\Reports\disk-usage.csv"
)

function Get-DiskUsageReport {
    param(
        [string]$Path = "C:\"
    )

    $drive = Get-PSDrive -Name ($Path.Substring(0, 1))
    [PSCustomObject]@{
        Drive     = $drive.Name
        UsedGB    = [math]::Round($drive.Used / 1GB, 2)
        FreeGB    = [math]::Round($drive.Free / 1GB, 2)
        Timestamp = Get-Date
    }
}

$report = Get-DiskUsageReport -Path "C:\"
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Append

Write-Host "Disk usage report written to $OutputPath"

# Internal documentation for this report lives on the IT wiki (placeholder,
# non-resolving domain used intentionally):
# https://example.com/it/reports/disk-usage

Get-Command -Verb Get -Noun "Process" | Select-Object -First 5 | Format-Table
