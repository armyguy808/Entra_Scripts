#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance, Microsoft.Graph.Groups, Microsoft.Graph.Users, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Generates a comprehensive report of all Entra ID directory role assignments.

.DESCRIPTION
    Collects directory role holdings (ALL assigned roles - built-in and custom -
    unless narrowed with -RoleFilter) from five angles:

      1. Active assignments   - unifiedRoleAssignmentScheduleInstances, split into:
                                  Assigned  = direct assignment (permanent or time-bound)
                                  Activated = PIM eligible role currently activated
      2. Eligible assignments - unifiedRoleEligibilityScheduleInstances (PIM eligible)
      3. PIM for Groups       - eligible and active member/owner schedules on any
                                group that itself holds a directory role
      4. Standing membership  - permanent (non-PIM) members of any group that
                                holds a directory role
      5. Standing ownership   - permanent (non-PIM) owners of any group that
                                holds a directory role. Owners do NOT inherit
                                the role, but owners of a role-assignable group
                                can be delegated membership management - i.e.
                                they can decide who gets the role.

    Design notes:
      - Active role data comes ONLY from roleAssignmentScheduleInstances. The
        roleAssignments API is deliberately not used, because activated eligible
        roles also appear there (looking permanent), which double counts and
        mislabels them.
      - MemberType 'Group' on a role-level row means the principal holds the role
        via a group. The same person may then also appear in section 3-5 rows.
        That is intentional: each row documents one distinct access path.
      - A principal who is BOTH eligible and currently activated for a role is
        reported ONCE, under 'PIM Active (Activated)'. Activation implies
        eligibility, so the duplicate eligible row is suppressed.
      - Owner rows always carry RoleHeld = 'No (owner only)'. Ownership of a
        role-holding group is an access path (owners can change who holds the
        role), never the role itself.
      - All Graph calls inside try blocks use -ErrorAction Stop so failures are
        surfaced as warnings instead of silently producing empty sections.
      - File is ASCII-only so it parses identically in Windows PowerShell 5.1
        (which assumes ANSI for BOM-less files) and PowerShell 7+.

    Output is exported to a CSV file for review.

.PARAMETER OutputPath
    Path for the CSV output file. Defaults to current directory with a timestamped filename.

.PARAMETER RoleFilter
    Optional. Array of role display names to narrow the report. If omitted, ALL
    directory roles (built-in and custom) with assignments are included. Filter
    entries that match no role definition produce a warning and are ignored.

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
      - Group.Read.All                                   (group lookup + standing members/owners)
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
    [string]$OutputPath = ".\EntraRoleReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [string[]]$RoleFilter = @()
)

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
        [string]$RoleHeld = 'Unknown',
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
        RoleHeld             = $RoleHeld
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
# Fetch role definitions and build the role lookup
# ================================================================================
Write-Host "`n[*] Fetching role definitions..." -ForegroundColor Cyan

try {
    $allRoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
}
catch {
    Write-Error "Failed to retrieve role definitions: $_"
    exit 1
}

# Lookup: role definition Id -> display name. Covers built-in AND custom roles.
$roleIdToName = @{}
foreach ($rd in $allRoleDefinitions) {
    $roleIdToName[$rd.Id] = $rd.DisplayName
}

# Optional narrowing via -RoleFilter. Default: ALL assigned roles are reported.
$filterActive    = ($RoleFilter.Count -gt 0)
$filteredRoleIds = [System.Collections.Generic.HashSet[string]]::new()

if ($filterActive) {
    foreach ($name in $RoleFilter) {
        $matched = @($allRoleDefinitions | Where-Object { $_.DisplayName -eq $name })
        if ($matched.Count -eq 0) {
            Write-Warning "RoleFilter entry '$name' matched no role definition (renamed or misspelled?) - it will be ignored."
        }
        foreach ($rd in $matched) { [void]$filteredRoleIds.Add($rd.Id) }
    }
    Write-Host "[+] Role filter active: $($filteredRoleIds.Count) matching role definition(s)." -ForegroundColor Green
}
else {
    Write-Host "[+] No role filter - reporting ALL assigned directory roles (built-in + custom)." -ForegroundColor Green
}

function Test-RoleInScope {
    param ([string]$RoleDefinitionId)
    if (-not $filterActive) { return $true }
    return $filteredRoleIds.Contains($RoleDefinitionId)
}

function Get-RoleName {
    param ([string]$RoleDefinitionId)
    if ($roleIdToName.ContainsKey($RoleDefinitionId)) { return $roleIdToName[$RoleDefinitionId] }
    return "Unknown role ($RoleDefinitionId)"
}

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

# ================================================================================
# SECTION 1 - ACTIVE role assignments (single source of truth)
# One bulk call instead of one call per role; instances are filtered client-side
# against the -RoleFilter set when one is provided. AssignmentType distinguishes:
#   Assigned  -> direct assignment (permanent if EndDateTime is null)
#   Activated -> a PIM eligible role that is currently activated
# ================================================================================
Write-Host "`n[*] Collecting ACTIVE role assignment instances (direct + PIM activated)..." -ForegroundColor Cyan

$activeInstances = @()
try {
    $activeInstances = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty "principal" -ErrorAction Stop |
        Where-Object { Test-RoleInScope $_.RoleDefinitionId }
}
catch {
    Write-Warning "Failed to retrieve active role assignment instances: $_"
    Write-Warning "Active assignment data will be MISSING. Verify RoleManagement.Read.All and Entra ID P2 licensing."
}

# Track currently-activated (role|principal|scope) combos so Section 2 can
# suppress the duplicate 'eligible' rows for the same people.
$activatedKeys = [System.Collections.Generic.HashSet[string]]::new()

foreach ($a in $activeInstances) {
    $principalType = $a.Principal.AdditionalProperties.'@odata.type' -replace '#microsoft\.graph\.',''
    $principal     = Resolve-Principal -PrincipalId $a.PrincipalId -PrincipalType $principalType
    $isActivated   = ($a.AssignmentType -eq 'Activated')

    if ($isActivated) {
        [void]$activatedKeys.Add("$($a.RoleDefinitionId)|$($a.PrincipalId)|$($a.DirectoryScopeId)")
    }

    $row = @{
        AssignmentSource = $(if ($isActivated) { 'PIM Active (Activated)' } else { 'Direct Active' })
        RoleName         = Get-RoleName $a.RoleDefinitionId
        RoleHeld         = 'Active'
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
        Where-Object { Test-RoleInScope $_.RoleDefinitionId }
}
catch {
    Write-Warning "Failed to retrieve role eligibility instances: $_"
    Write-Warning "Eligible assignment data will be MISSING. Verify RoleManagement.Read.All and Entra ID P2 licensing."
}

$suppressedEligible = 0
foreach ($a in $eligibleInstances) {
    # A principal whose eligibility is currently ACTIVATED for this role and
    # scope is already reported under 'PIM Active (Activated)' - skip the
    # duplicate eligible row (activation implies eligibility).
    if ($activatedKeys.Contains("$($a.RoleDefinitionId)|$($a.PrincipalId)|$($a.DirectoryScopeId)")) {
        $suppressedEligible++
        continue
    }

    $principalType = $a.Principal.AdditionalProperties.'@odata.type' -replace '#microsoft\.graph\.',''
    $principal     = Resolve-Principal -PrincipalId $a.PrincipalId -PrincipalType $principalType

    $row = @{
        AssignmentSource = 'PIM Eligible'
        RoleName         = Get-RoleName $a.RoleDefinitionId
        RoleHeld         = 'Eligible'
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
Write-Host "[+] PIM eligible instances collected: $eligibleCount ($suppressedEligible currently activated - reported under PIM Active)." -ForegroundColor Green

# ================================================================================
# SECTION 3 - Groups holding directory roles
# For every group that appears above as a principal:
#   3a. PIM for Groups eligibility schedules (who CAN activate membership/ownership)
#   3b. PIM for Groups assignment schedules  (PIM-assigned or currently activated)
#   3c. Standing (non-PIM) direct members    (permanent role inheritance)
#   3d. Standing (non-PIM) direct owners     (role NOT inherited - owners control
#                                             who holds the role via membership)
# Role-assignable groups cannot be nested, so direct members are sufficient.
# ================================================================================
Write-Host "`n[*] Collecting group-based access (PIM for Groups + standing members/owners)..." -ForegroundColor Cyan

$roleAssignedGroupIds = @(
    $report |
        Where-Object { $_.PrincipalType -eq 'Group' } |
        Select-Object -ExpandProperty PrincipalId -Unique
)

Write-Host "    Found $($roleAssignedGroupIds.Count) group(s) holding directory roles." -ForegroundColor Yellow

foreach ($groupId in $roleAssignedGroupIds) {

    # One context entry per distinct role this group holds. When the group is
    # both eligible AND active for the same role, prefer the ACTIVE context so
    # via-group rows inherit the strongest RoleHeld state.
    $groupRoleContexts = @(
        $report |
            Where-Object { $_.PrincipalId -eq $groupId -and $_.PrincipalType -eq 'Group' } |
            Group-Object RoleId |
            ForEach-Object {
                $activeCtx = $_.Group | Where-Object { $_.RoleHeld -eq 'Active' } | Select-Object -First 1
                if ($activeCtx) { $activeCtx } else { $_.Group[0] }
            }
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
        $isOwner   = ($schedule.AccessId -eq 'owner')

        foreach ($ctx in $groupRoleContexts) {
            $row = @{
                AssignmentSource = 'PIM for Groups (Eligible)'
                RoleName         = $ctx.RoleName
                RoleHeld         = $(if ($isOwner) { 'No (owner only)' } else { 'Eligible (via group)' })
                RoleId           = $ctx.RoleId
                AssignmentType   = $(if ($isOwner) { 'Eligible Owner (role NOT inherited)' } else { 'Eligible Member (via Group)' })
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
        $principal   = Resolve-Principal -PrincipalId $schedule.PrincipalId -PrincipalType ""
        $isActivated = ($schedule.AssignmentType -eq 'Activated')
        $isOwner     = ($schedule.AccessId -eq 'owner')

        $ownerLabel  = $(if ($isActivated) { 'Activated Owner (role NOT inherited)' } else { 'PIM-Assigned Owner (role NOT inherited)' })
        $memberLabel = $(if ($isActivated) { 'Activated Member (via Group)' } else { 'PIM-Assigned Member (via Group)' })

        foreach ($ctx in $groupRoleContexts) {
            # A member of this group holds the role only if the group's own role
            # assignment is active; otherwise the member is (at best) eligible.
            $memberRoleHeld = $(if ($ctx.RoleHeld -eq 'Active') { 'Active (via group)' } else { 'Eligible (via group)' })

            $row = @{
                AssignmentSource = 'PIM for Groups (Active)'
                RoleName         = $ctx.RoleName
                RoleHeld         = $(if ($isOwner) { 'No (owner only)' } else { $memberRoleHeld })
                RoleId           = $ctx.RoleId
                AssignmentType   = $(if ($isOwner) { $ownerLabel } else { $memberLabel })
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
    # Activated PIM members/owners are real directory members/owners while
    # activated, so track PIM-managed principal IDs per access type and skip
    # them when enumerating standing membership (3c) and ownership (3d).
    $pimMemberIds = [System.Collections.Generic.HashSet[string]]::new()
    $pimOwnerIds  = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($s in $activeSchedules) {
        if ($s.AccessId -eq 'owner') { [void]$pimOwnerIds.Add($s.PrincipalId) }
        else                         { [void]$pimMemberIds.Add($s.PrincipalId) }
    }

    $members = @()
    try {
        $members = Get-MgGroupMember -GroupId $groupId -All -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not enumerate members of '$groupDisplayName' ($groupId): $_"
    }

    foreach ($m in $members) {
        if ($pimMemberIds.Contains($m.Id)) { continue }

        $mType     = $m.AdditionalProperties.'@odata.type' -replace '#microsoft\.graph\.',''
        $principal = Resolve-Principal -PrincipalId $m.Id -PrincipalType $mType

        foreach ($ctx in $groupRoleContexts) {
            $row = @{
                AssignmentSource = 'Group Membership (Standing)'
                RoleName         = $ctx.RoleName
                RoleHeld         = $(if ($ctx.RoleHeld -eq 'Active') { 'Active (via group)' } else { 'Eligible (via group)' })
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

    # -- 3d. Standing (non-PIM) owners ------------------------------------------
    # Owners do NOT inherit the group's role, but owners of a role-assignable
    # group can be delegated membership management - i.e. they control who
    # holds the role. PIM-managed owners were already reported in 3a/3b.
    $owners = @()
    try {
        $owners = Get-MgGroupOwner -GroupId $groupId -All -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not enumerate owners of '$groupDisplayName' ($groupId): $_"
    }

    foreach ($o in $owners) {
        if ($pimOwnerIds.Contains($o.Id)) { continue }

        $oType     = $o.AdditionalProperties.'@odata.type' -replace '#microsoft\.graph\.',''
        $principal = Resolve-Principal -PrincipalId $o.Id -PrincipalType $oType

        foreach ($ctx in $groupRoleContexts) {
            $row = @{
                AssignmentSource = 'Group Ownership (Standing)'
                RoleName         = $ctx.RoleName
                RoleHeld         = 'No (owner only)'
                RoleId           = $ctx.RoleId
                AssignmentType   = 'Standing Owner (role NOT inherited)'
                Principal        = $principal
                PrincipalId      = $o.Id
                MemberType       = 'Group'
                AssignmentScope  = $ctx.AssignmentScope
                StartDateTime    = 'N/A'
                EndDateTime      = 'Permanent (standing ownership)'
                GroupName        = $groupDisplayName
                GroupId          = $groupId
                MembershipType   = 'owner'
            }
            Add-ReportRow @row
        }
    }
}

$pfgCount           = @($report | Where-Object { $_.AssignmentSource -like 'PIM for Groups*' }).Count
$standingCount      = @($report | Where-Object { $_.AssignmentSource -eq 'Group Membership (Standing)' }).Count
$standingOwnerCount = @($report | Where-Object { $_.AssignmentSource -eq 'Group Ownership (Standing)' }).Count
Write-Host "[+] Group-based rows collected: $pfgCount PIM for Groups, $standingCount standing members, $standingOwnerCount standing owners." -ForegroundColor Green

# ================================================================================
# OUTPUT
# ================================================================================
Write-Host "`n[*] Exporting report..." -ForegroundColor Cyan

Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host "      ENTRA DIRECTORY ROLE REPORT SUMMARY" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green

$summarySources = @(
    'Direct Active',
    'PIM Active (Activated)',
    'PIM Eligible',
    'PIM for Groups (Eligible)',
    'PIM for Groups (Active)',
    'Group Membership (Standing)',
    'Group Ownership (Standing)'
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
