#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance, Microsoft.Graph.Groups, Microsoft.Graph.Users, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Generates a comprehensive report of all privileged Entra ID role assignments.

.DESCRIPTION
    Collects privileged role holdings from four angles:

      1. Active assignments   - unifiedRoleAssignmentScheduleInstances, split into:
                                  Assigned  = direct assignment (permanent or time-bound)
                                  Activated = PIM eligible role currently activated
      2. Eligible assignments - unifiedRoleEligibilityScheduleInstances (PIM eligible)
      3. PIM for Groups       - eligible and active member/owner schedules on any
                                group that itself holds a privileged role
      4. Standing membership  - permanent (non-PIM) members of any group that
                                holds a privileged role

    Design notes:
      - Active role data comes ONLY from roleAssignmentScheduleInstances. The
        roleAssignments API is deliberately not used, because activated eligible
        roles also appear there (looking permanent), which double counts and
        mislabels them.
      - MemberType 'Group' on a role-level row means the principal holds the role
        via a group. The same person may then also appear in section 3/4 rows.
        That is intentional: each row documents one distinct access path.
      - All Graph calls inside try blocks use -ErrorAction Stop so failures are
        surfaced as warnings instead of silently producing empty sections.
      - File is ASCII-only so it parses identically in Windows PowerShell 5.1
        (which assumes ANSI for BOM-less files) and PowerShell 7+.

    Output is exported to a CSV file for review.

.PARAMETER OutputPath
    Path for the CSV output file. Defaults to current directory with a timestamped filename.

.PARAMETER RoleFilter
    Optional. Array of role display names to filter on. If omitted, all privileged roles are included.

.EXAMPLE
    .\Entra_PrivilegedRole_Report.ps1

.EXAMPLE
    .\Entra_PrivilegedRole_Report.ps1 -OutputPath "C:\Reports\PrivRoles.csv"

.EXAMPLE
    .\Entra_PrivilegedRole_Report.ps1 -RoleFilter "Global Administrator","Privileged Role Administrator"

.NOTES
    Required Graph API permissions (delegated or application):
      - RoleManagement.Read.All                          (role definitions + role schedule instances)
      - PrivilegedEligibilitySchedule.Read.AzureADGroup  (PIM for Groups - eligibility)
      - PrivilegedAssignmentSchedule.Read.AzureADGroup   (PIM for Groups - assignments)
      - Group.Read.All                                   (group lookup + standing members)
      - User.Read.All                                    (user lookup incl. accountEnabled)
      - Directory.Read.All                               (service principal lookup)

    Delegated caveat: for PIM for Groups queries against role-assignable groups,
    the signed-in user must also hold Global Reader or Privileged Role
    Administrator (or be an owner/member of the group).

    PIM APIs require Microsoft Entra ID P2 / Governance licensing. If licensing
    or permissions are missing, the affected section emits a warning.
#>

[CmdletBinding()]
param (
    [string]$OutputPath = ".\PrivilegedRoleReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [string[]]$RoleFilter = @()
)

# ================================================================================
# Privileged role list - based on Microsoft's guidance. Extend as needed.
# ================================================================================
$PrivilegedRoleNames = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Hybrid Identity Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Conditional Access Administrator",
    "Authentication Administrator",
    "Privileged Authentication Administrator",
    "User Administrator",
    "Helpdesk Administrator",
    "Password Administrator",
    "Groups Administrator",
    "License Administrator",
    "Directory Writers",
    "Domain Name Administrator",
    "Azure AD Joined Device Local Administrator",
    "Intune Administrator",
    "Teams Administrator",
    "Billing Administrator",
    "Compliance Administrator",
    "Compliance Data Administrator",
    "Security Operator",
    "Security Reader",
    "Global Reader",
    "Identity Governance Administrator",
    "Lifecycle Workflows Administrator",
    "External Identity Provider Administrator",
    "B2C IEF Policy Administrator",
    "Authentication Policy Administrator",
    "Knowledge Manager",
    "Knowledge Administrator",
    "Attribute Assignment Administrator",
    "Attribute Definition Administrator",
    "Cloud Device Administrator",
    "Azure DevOps Administrator",
    "Azure Information Protection Administrator",
    "Customer LockBox Access Approver",
    "Desktop Analytics Administrator",
    "Microsoft Hardware Warranty Administrator",
    "Office Apps Administrator",
    "Power Platform Administrator",
    "Printer Administrator",
    "Reports Reader",
    "Search Administrator",
    "Service Support Administrator",
    "Teams Communications Administrator",
    "Teams Communications Support Engineer",
    "Teams Communications Support Specialist",
    "Teams Devices Administrator",
    "Windows 365 Administrator",
    "Yammer Administrator"
)

# If the caller passed a filter, use that instead
if ($RoleFilter.Count -gt 0) {
    $PrivilegedRoleNames = $RoleFilter
}

# ================================================================================
# Helpers
# ================================================================================

# Cache resolved principals - the same user/group often appears in many rows.
$script:PrincipalCache = @{}

function Resolve-Principal {
    param (
        [string]$PrincipalId,
        [string]$PrincipalType   # "user", "group", "servicePrincipal", or "" to probe all three
    )

    if ($script:PrincipalCache.ContainsKey($PrincipalId)) {
        return $script:PrincipalCache[$PrincipalId]
    }

    $result = [PSCustomObject]@{
        DisplayName    = "Unknown (possibly deleted)"
        UPN            = "N/A"
        PrincipalType  = $(if ($PrincipalType) { $PrincipalType } else { "Unknown" })
        AccountEnabled = "N/A"
    }

    # NOTE: -ErrorAction SilentlyContinue is intentional INSIDE this helper only.
    # When the type is unknown we probe user -> group -> servicePrincipal, and a
    # miss on one type is expected, not an error.
    $found = $false
    try {
        if (-not $found -and ($PrincipalType -eq "User" -or -not $PrincipalType)) {
            $user = Get-MgUser -UserId $PrincipalId -Property "DisplayName","UserPrincipalName","AccountEnabled" -ErrorAction SilentlyContinue
            if ($user) {
                $result.DisplayName    = $user.DisplayName
                $result.UPN            = $user.UserPrincipalName
                $result.PrincipalType  = "User"
                $result.AccountEnabled = $user.AccountEnabled
                $found = $true
            }
        }

        if (-not $found -and ($PrincipalType -eq "Group" -or -not $PrincipalType)) {
            $group = Get-MgGroup -GroupId $PrincipalId -Property "DisplayName" -ErrorAction SilentlyContinue
            if ($group) {
                $result.DisplayName   = $group.DisplayName
                $result.UPN           = "N/A (Group)"
                $result.PrincipalType = "Group"
                $found = $true
            }
        }

        if (-not $found -and ($PrincipalType -eq "ServicePrincipal" -or -not $PrincipalType)) {
            $sp = Get-MgServicePrincipal -ServicePrincipalId $PrincipalId -Property "DisplayName" -ErrorAction SilentlyContinue
            if ($sp) {
                $result.DisplayName   = $sp.DisplayName
                $result.UPN           = "N/A (ServicePrincipal)"
                $result.PrincipalType = "ServicePrincipal"
                $found = $true
            }
        }
    }
    catch {
        Write-Warning "Could not resolve principal $PrincipalId : $_"
    }

    $script:PrincipalCache[$PrincipalId] = $result
    return $result
}

function Format-DirectoryScope {
    param ([string]$DirectoryScopeId)
    if ($DirectoryScopeId -eq "/") { "Tenant-wide" } else { $DirectoryScopeId }
}

# Central row builder so every section emits an identical column set.
function Add-ReportRow {
    param (
        [string]$AssignmentSource,
        [string]$RoleName,
        [string]$RoleId,
        [string]$AssignmentType,
        $Principal,
        [string]$PrincipalId,
        [string]$MemberType = "N/A",
        [string]$AssignmentScope,
        $StartDateTime,
        $EndDateTime,
        [string]$GroupName = "N/A",
        [string]$GroupId = "N/A",
        [string]$MembershipType = "N/A"
    )

    $report.Add([PSCustomObject]@{
        AssignmentSource     = $AssignmentSource
        RoleName             = $RoleName
        RoleId               = $RoleId
        AssignmentType       = $AssignmentType
        PrincipalDisplayName = $Principal.DisplayName
        PrincipalUPN         = $Principal.UPN
        PrincipalType        = $Principal.PrincipalType
        PrincipalId          = $PrincipalId
        AccountEnabled       = $Principal.AccountEnabled
        MemberType           = $MemberType
        AssignmentScope      = $AssignmentScope
        StartDateTime        = $StartDateTime
        EndDateTime          = $EndDateTime
        GroupName            = $GroupName
        GroupId              = $GroupId
        MembershipType       = $MembershipType
    })
}

# ================================================================================
# Connect to Microsoft Graph
# ================================================================================
Write-Host "`n[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan

$requiredScopes = @(
    "RoleManagement.Read.All",
    "PrivilegedEligibilitySchedule.Read.AzureADGroup",
    "PrivilegedAssignmentSchedule.Read.AzureADGroup",
    "Group.Read.All",
    "User.Read.All",
    "Directory.Read.All"
)

try {
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
    $context = Get-MgContext
    Write-Host "[+] Connected as: $($context.Account) | Tenant: $($context.TenantId)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# ================================================================================
# Fetch role definitions and build a privileged-role lookup
# ================================================================================
Write-Host "`n[*] Fetching role definitions..." -ForegroundColor Cyan

try {
    $allRoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
}
catch {
    Write-Error "Failed to retrieve role definitions: $_"
    exit 1
}

$privilegedRoleDefs = $allRoleDefinitions | Where-Object { $_.DisplayName -in $PrivilegedRoleNames }

# Hashtable keyed by role definition Id -> display name. Used both as the
# client-side filter and to label rows.
$roleIdToName = @{}
foreach ($rd in $privilegedRoleDefs) {
    $roleIdToName[$rd.Id] = $rd.DisplayName
}

Write-Host "[+] Found $(@($privilegedRoleDefs).Count) privileged role definitions to check." -ForegroundColor Green

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

# ================================================================================
# SECTION 1 - ACTIVE role assignments (single source of truth)
# One bulk call instead of one call per role; instances are filtered client-side
# against the privileged role set. AssignmentType distinguishes:
#   Assigned  -> direct assignment (permanent if EndDateTime is null)
#   Activated -> a PIM eligible role that is currently activated
# ================================================================================
Write-Host "`n[*] Collecting ACTIVE role assignment instances (direct + PIM activated)..." -ForegroundColor Cyan

$activeInstances = @()
try {
    $activeInstances = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty "principal" -ErrorAction Stop |
        Where-Object { $roleIdToName.ContainsKey($_.RoleDefinitionId) }
}
catch {
    Write-Warning "Failed to retrieve active role assignment instances: $_"
    Write-Warning "Active assignment data will be MISSING. Verify RoleManagement.Read.All and Entra ID P2 licensing."
}

foreach ($a in $activeInstances) {
    $principalType = $a.Principal.AdditionalProperties.'@odata.type' -replace '#microsoft\.graph\.',''
    $principal     = Resolve-Principal -PrincipalId $a.PrincipalId -PrincipalType $principalType
    $isActivated   = ($a.AssignmentType -eq 'Activated')

    $row = @{
        AssignmentSource = $(if ($isActivated) { 'PIM Active (Activated)' } else { 'Direct Active' })
        RoleName         = $roleIdToName[$a.RoleDefinitionId]
        RoleId           = $a.RoleDefinitionId
        AssignmentType   = $(if ($isActivated) { 'Active (PIM Activated)' } else { 'Active (Assigned)' })
        Principal        = $principal
        PrincipalId      = $a.PrincipalId
        MemberType       = $(if ($a.MemberType) { $a.MemberType } else { 'Direct' })
        AssignmentScope  = Format-DirectoryScope $a.DirectoryScopeId
        StartDateTime    = $a.StartDateTime
        EndDateTime      = $(if ($a.EndDateTime) { $a.EndDateTime } else { 'Permanent (no expiry)' })
    }
    Add-ReportRow @row
}

$directCount    = @($report | Where-Object { $_.AssignmentSource -eq 'Direct Active' }).Count
$activatedCount = @($report | Where-Object { $_.AssignmentSource -eq 'PIM Active (Activated)' }).Count
Write-Host "[+] Active instances collected: $directCount assigned, $activatedCount PIM-activated." -ForegroundColor Green

# ================================================================================
# SECTION 2 - PIM ELIGIBLE role assignments
# ================================================================================
Write-Host "`n[*] Collecting PIM ELIGIBLE role assignment instances..." -ForegroundColor Cyan

$eligibleInstances = @()
try {
    $eligibleInstances = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty "principal" -ErrorAction Stop |
        Where-Object { $roleIdToName.ContainsKey($_.RoleDefinitionId) }
}
catch {
    Write-Warning "Failed to retrieve role eligibility instances: $_"
    Write-Warning "Eligible assignment data will be MISSING. Verify RoleManagement.Read.All and Entra ID P2 licensing."
}

foreach ($a in $eligibleInstances) {
    $principalType = $a.Principal.AdditionalProperties.'@odata.type' -replace '#microsoft\.graph\.',''
    $principal     = Resolve-Principal -PrincipalId $a.PrincipalId -PrincipalType $principalType

    $row = @{
        AssignmentSource = 'PIM Eligible'
        RoleName         = $roleIdToName[$a.RoleDefinitionId]
        RoleId           = $a.RoleDefinitionId
        AssignmentType   = 'Eligible'
        Principal        = $principal
        PrincipalId      = $a.PrincipalId
        MemberType       = $(if ($a.MemberType) { $a.MemberType } else { 'Direct' })
        AssignmentScope  = Format-DirectoryScope $a.DirectoryScopeId
        StartDateTime    = $a.StartDateTime
        EndDateTime      = $(if ($a.EndDateTime) { $a.EndDateTime } else { 'No expiry' })
    }
    Add-ReportRow @row
}

$eligibleCount = @($report | Where-Object { $_.AssignmentSource -eq 'PIM Eligible' }).Count
Write-Host "[+] PIM eligible instances collected: $eligibleCount" -ForegroundColor Green

# ================================================================================
# SECTION 3 - Groups holding privileged roles
# For every group that appears above as a principal:
#   3a. PIM for Groups eligibility schedules (who CAN activate membership/ownership)
#   3b. PIM for Groups assignment schedules  (PIM-assigned or currently activated)
#   3c. Standing (non-PIM) direct members    (permanent role inheritance)
# Role-assignable groups cannot be nested, so direct members are sufficient.
# ================================================================================
Write-Host "`n[*] Collecting group-based access (PIM for Groups + standing members)..." -ForegroundColor Cyan

$roleAssignedGroupIds = @(
    $report |
        Where-Object { $_.PrincipalType -eq 'Group' } |
        Select-Object -ExpandProperty PrincipalId -Unique
)

Write-Host "    Found $($roleAssignedGroupIds.Count) group(s) holding privileged roles." -ForegroundColor Yellow

foreach ($groupId in $roleAssignedGroupIds) {

    # One context entry per distinct role this group holds (a group can appear
    # multiple times, e.g. once eligible and once active, for the same role).
    $groupRoleContexts = @(
        $report |
            Where-Object { $_.PrincipalId -eq $groupId -and $_.PrincipalType -eq 'Group' } |
            Group-Object RoleId |
            ForEach-Object { $_.Group[0] }
    )
    $groupDisplayName = $groupRoleContexts[0].PrincipalDisplayName

    Write-Host "    Processing group: $groupDisplayName ($groupId)" -ForegroundColor Yellow

    # -- 3a. PIM for Groups: eligible members/owners ---------------------------
    $eligibleSchedules = @()
    try {
        $eligibleSchedules = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance -Filter "groupId eq '$groupId'" -All -ErrorAction Stop
    }
    catch {
        Write-Warning "PIM for Groups ELIGIBILITY query failed for '$groupDisplayName' ($groupId): $_"
        Write-Warning "Verify the PrivilegedEligibilitySchedule.Read.AzureADGroup scope was consented."
    }

    foreach ($schedule in $eligibleSchedules) {
        # Empty type lets Resolve-Principal probe; PIM for Groups principals are
        # users in practice, but this stays correct if that ever changes.
        $principal = Resolve-Principal -PrincipalId $schedule.PrincipalId -PrincipalType ""

        foreach ($ctx in $groupRoleContexts) {
            $row = @{
                AssignmentSource = 'PIM for Groups (Eligible)'
                RoleName         = $ctx.RoleName
                RoleId           = $ctx.RoleId
                AssignmentType   = 'Eligible (via Group)'
                Principal        = $principal
                PrincipalId      = $schedule.PrincipalId
                MemberType       = 'Group'
                AssignmentScope  = $ctx.AssignmentScope
                StartDateTime    = $schedule.StartDateTime
                EndDateTime      = $(if ($schedule.EndDateTime) { $schedule.EndDateTime } else { 'No expiry' })
                GroupName        = $groupDisplayName
                GroupId          = $groupId
                MembershipType   = $schedule.AccessId   # member | owner
            }
            Add-ReportRow @row
        }
    }

    # -- 3b. PIM for Groups: assigned / activated members-owners ---------------
    $activeSchedules = @()
    try {
        $activeSchedules = Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleInstance -Filter "groupId eq '$groupId'" -All -ErrorAction Stop
    }
    catch {
        Write-Warning "PIM for Groups ASSIGNMENT query failed for '$groupDisplayName' ($groupId): $_"
        Write-Warning "Verify the PrivilegedAssignmentSchedule.Read.AzureADGroup scope was consented."
    }

    foreach ($schedule in $activeSchedules) {
        $principal         = Resolve-Principal -PrincipalId $schedule.PrincipalId -PrincipalType ""
        $isActivatedMember = ($schedule.AssignmentType -eq 'Activated')

        foreach ($ctx in $groupRoleContexts) {
            $row = @{
                AssignmentSource = 'PIM for Groups (Active)'
                RoleName         = $ctx.RoleName
                RoleId           = $ctx.RoleId
                AssignmentType   = $(if ($isActivatedMember) { 'Activated (via Group)' } else { 'Assigned via PIM (via Group)' })
                Principal        = $principal
                PrincipalId      = $schedule.PrincipalId
                MemberType       = 'Group'
                AssignmentScope  = $ctx.AssignmentScope
                StartDateTime    = $schedule.StartDateTime
                EndDateTime      = $(if ($schedule.EndDateTime) { $schedule.EndDateTime } else { 'No expiry' })
                GroupName        = $groupDisplayName
                GroupId          = $groupId
                MembershipType   = $schedule.AccessId   # member | owner
            }
            Add-ReportRow @row
        }
    }

    # -- 3c. Standing (non-PIM) members -----------------------------------------
    # Activated PIM members are real directory members while activated, so skip
    # any member already represented by a PIM assignment schedule above.
    $pimManagedIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($s in $activeSchedules) {
        [void]$pimManagedIds.Add($s.PrincipalId)
    }

    $members = @()
    try {
        $members = Get-MgGroupMember -GroupId $groupId -All -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not enumerate members of '$groupDisplayName' ($groupId): $_"
    }

    foreach ($m in $members) {
        if ($pimManagedIds.Contains($m.Id)) { continue }

        $mType     = $m.AdditionalProperties.'@odata.type' -replace '#microsoft\.graph\.',''
        $principal = Resolve-Principal -PrincipalId $m.Id -PrincipalType $mType

        foreach ($ctx in $groupRoleContexts) {
            $row = @{
                AssignmentSource = 'Group Membership (Standing)'
                RoleName         = $ctx.RoleName
                RoleId           = $ctx.RoleId
                AssignmentType   = 'Standing Member (via Group)'
                Principal        = $principal
                PrincipalId      = $m.Id
                MemberType       = 'Group'
                AssignmentScope  = $ctx.AssignmentScope
                StartDateTime    = 'N/A'
                EndDateTime      = 'Permanent (standing membership)'
                GroupName        = $groupDisplayName
                GroupId          = $groupId
                MembershipType   = 'member'
            }
            Add-ReportRow @row
        }
    }
}

$pfgCount      = @($report | Where-Object { $_.AssignmentSource -like 'PIM for Groups*' }).Count
$standingCount = @($report | Where-Object { $_.AssignmentSource -eq 'Group Membership (Standing)' }).Count
Write-Host "[+] Group-based rows collected: $pfgCount PIM for Groups, $standingCount standing members." -ForegroundColor Green

# ================================================================================
# OUTPUT
# ================================================================================
Write-Host "`n[*] Exporting report..." -ForegroundColor Cyan

Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host "        PRIVILEGED ROLE REPORT SUMMARY" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green

$summarySources = @(
    'Direct Active',
    'PIM Active (Activated)',
    'PIM Eligible',
    'PIM for Groups (Eligible)',
    'PIM for Groups (Active)',
    'Group Membership (Standing)'
)
foreach ($source in $summarySources) {
    $count = @($report | Where-Object { $_.AssignmentSource -eq $source }).Count
    Write-Host ("  {0,-28}: {1}" -f $source, $count)
}
Write-Host ("  {0,-28}: {1}" -f 'Total rows', $report.Count)
Write-Host ""

if ($report.Count -eq 0) {
    Write-Warning "No assignments were collected - nothing to export. Review the warnings above."
}
else {
    $report |
        Sort-Object RoleName, AssignmentSource, PrincipalDisplayName |
        Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

    Write-Host "  Output file: $OutputPath" -ForegroundColor Cyan
    Write-Host ""
}

Disconnect-MgGraph | Out-Null
Write-Host "[*] Disconnected from Microsoft Graph.`n" -ForegroundColor Gray
