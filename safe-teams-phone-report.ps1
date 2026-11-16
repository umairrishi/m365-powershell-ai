<#
.SYNOPSIS
    Lists Teams users who are Enterprise Voice enabled but have no phone number assigned.

.DESCRIPTION
    Read-only report. Makes no changes to the tenant. Exports results to CSV.

.NOTES
    Module: MicrosoftTeams
    Role:   Teams Communications Administrator (read access is enough)
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".\teams-users-without-number.csv"
)

try {
    Connect-MicrosoftTeams -ErrorAction Stop | Out-Null

    # Get voice-enabled users with no line URI
    $users = Get-CsOnlineUser -Filter "EnterpriseVoiceEnabled -eq `$true" |
        Where-Object { -not $_.LineUri } |
        Select-Object DisplayName, UserPrincipalName, UsageLocation

    $users | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "Found $($users.Count) users. Report saved to $OutputPath"
}
catch {
    Write-Error "Report failed: $_"
}
