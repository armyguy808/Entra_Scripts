#Requires -Version 5.1

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

    PART 2 - WORKLOAD (MICROSOFT 365) ROLES: after the Entra report, the script
    builds a second report of roles assigned INSIDE workloads, which the Entra
    directory role data cannot see:
      - Exchange Online : management role group members + direct user role
                          assignments (requires the ExchangeOnlineManagement
                          module; triggers its own sign-in)
      - Purview         : Security & Compliance role group members
                          (Connect-IPPSSession; triggers its own sign-in)
      - Intune          : RBAC role assignments via Graph v1.0, with each
                          admin group expanded to its individual members
      - Defender XDR    : unified RBAC role assignments (Graph beta; opt-in
                          via -IncludeDefender), groups expanded to members
      - Windows 365     : Cloud PC RBAC role assignments (Graph beta; opt-in
                          via -IncludeCloudPC), groups expanded to members
    Workloads whose admin rights come only from Entra directory roles (Teams,
    SharePoint, Power BI / Fabric) are already covered by Part 1 and have no
    separate in-app tenant RBAC to report.

    Every report is written as its own CSV into -OutputFolder (default C:\temp):
    one for Entra directory roles plus one per workload app that returned data.

.PARAMETER OutputFolder
    Folder that receives every CSV produced by this run (created if missing).
    Defaults to C:\temp. Filenames carry a shared timestamp, for example
    EntraRoleReport_20260720_090000.csv and
    ExchangeOnlineRoleReport_20260720_090000.csv.

.PARAMETER RoleFilter
    Optional. Array of role display names to narrow the report. If omitted, ALL
    directory roles (built-in and custom) with assignments are included. Filter
    entries that match no role definition produce a warning and are ignored.
    Applies to Part 1 (Entra roles) only.

.PARAMETER SkipExchangeOnline
    Skip the Exchange Online role group / role assignment collection.

.PARAMETER SkipPurview
    Skip the Purview (Security & Compliance) role group collection.

.PARAMETER SkipIntune
    Skip the Intune RBAC collection.

.PARAMETER IncludeDefender
    Opt in to the Microsoft Defender XDR unified RBAC collection (Graph beta).
    Off by default; requires unified RBAC to be active in the tenant.

.PARAMETER IncludeCloudPC
    Opt in to the Windows 365 (Cloud PC) RBAC collection (Graph beta). Off by
    default; only relevant to tenants licensed for Windows 365. Tenants using
    Azure Virtual Desktop instead have no Cloud PC RBAC to report.

.EXAMPLE
    .\Entra_PrivilegedRole_Report.ps1

.EXAMPLE
    .\Entra_PrivilegedRole_Report.ps1 -OutputFolder "D:\Reports"

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
      - DeviceManagementRBAC.Read.All                    (Intune RBAC - Part 2)
      - RoleManagement.Read.Defender                     (only with -IncludeDefender)
      - RoleManagement.Read.CloudPC                      (only with -IncludeCloudPC)

    Delegated caveat: for PIM for Groups queries against role-assignable groups,
    the signed-in user must also hold Global Reader or Privileged Role
    Administrator (or be an owner/member of the group).

    PIM APIs require Microsoft Entra ID P2 / Governance licensing. If licensing
    or permissions are missing, the affected section emits a warning.

    Part 2 workload requirements: Exchange Online and Purview sections need the
    ExchangeOnlineManagement module (Install-Module ExchangeOnlineManagement);
    Connect-ExchangeOnline and Connect-IPPSSession each trigger their own
    sign-in, and the account needs role-management visibility in each workload
    (for example View-Only Organization Management in Exchange Online and a
    Purview role group with role-management read access). If the module is
    missing, those sections are skipped with a warning. The Intune section
    requires an Intune-licensed tenant. Defender XDR and Windows 365 are
    OPT-IN sections on Graph BETA endpoints - enable them with
    -IncludeDefender / -IncludeCloudPC once the tenant is ready for them.
    Use the -Skip* switches to opt out of the default workloads.

    Windows PowerShell 5.1 notes: this script targets 5.1. It raises the 5.1
    function/variable caps before importing modules (the Graph SDK can
    otherwise exceed the 4096-function limit) and pre-loads
    ExchangeOnlineManagement ahead of the Graph modules to avoid the
    Microsoft.Identity.Client assembly conflicts that break
    Connect-ExchangeOnline. If a run still hits an auth or assembly error,
    start a FRESH 5.1 window and rerun - a session cannot be repaired once
    the wrong assembly loads. Keep both module families updated. When
    enabled, the opt-in beta sections prefer Microsoft.Graph.Beta cmdlets and
    otherwise fall back to Invoke-MgGraphRequest on the same signed-in
    session; a 400/403 there almost always means an inactive provider or
    missing licensing. Azure Virtual Desktop tenants: AVD admin rights are
    Azure RBAC (subscription / resource group roles), outside Microsoft Graph
    and outside this report.
#>

[CmdletBinding()]
param (
    [string]$OutputFolder = "C:\temp",

    [string[]]$RoleFilter = @(),

    [switch]$SkipExchangeOnline,

    [switch]$SkipPurview,

    [switch]$SkipIntune,

    [switch]$IncludeDefender,

    [switch]$IncludeCloudPC
)

# Every report from this run shares one timestamp and lands in $OutputFolder.
$reportTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not (Test-Path -Path $OutputFolder)) {
    try {
        New-Item -ItemType Directory -Path $OutputFolder -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error "Could not create output folder '$OutputFolder': $_"
        exit 1
    }
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
# Module bootstrap - Windows PowerShell 5.1 safe.
# 5.1 caps a session at 4096 functions; the Graph modules together can exceed
# that ('Function capacity 4096 has been exceeded...'). Raising the limits
# BEFORE any import avoids it, which is why modules are imported here instead
# of via #Requires -Modules. PowerShell 7 has no such cap.
# ================================================================================
if ($PSVersionTable.PSVersion.Major -le 5) {
    $MaximumFunctionCount = 32768
    $MaximumVariableCount = 32768
}

# ExchangeOnlineManagement loads FIRST when present and needed: loading it
# after the Graph SDK in one session is a common cause of
# Connect-ExchangeOnline auth failures on 5.1 (conflicting
# Microsoft.Identity.Client assembly versions).
$exoModulePresent = [bool](Get-Module -ListAvailable -Name ExchangeOnlineManagement)
if ($exoModulePresent -and -not ($SkipExchangeOnline -and $SkipPurview)) {
    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not pre-load ExchangeOnlineManagement: $_"
        $exoModulePresent = $false
    }
}

# Required Graph modules, imported explicitly after the limit fix above.
$requiredGraphModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.Governance',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.DeviceManagement.Administration'
)
$missingModules = @()
foreach ($moduleName in $requiredGraphModules) {
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        $missingModules += $moduleName
        continue
    }
    try {
        Import-Module $moduleName -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to import module '$moduleName': $_"
        exit 1
    }
}
if ($missingModules.Count -gt 0) {
    Write-Error "Missing required module(s): $($missingModules -join ', '). Install with: Install-Module $($missingModules -join ', ') -Scope CurrentUser"
    exit 1
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
    "Directory.Read.All",
    "DeviceManagementRBAC.Read.All"
)
if ($IncludeDefender) { $requiredScopes += "RoleManagement.Read.Defender" }
if ($IncludeCloudPC)  { $requiredScopes += "RoleManagement.Read.CloudPC" }

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
# PART 1 OUTPUT - Entra directory role report
# ================================================================================
Write-Host "`n[*] Exporting Part 1 (Entra directory roles)..." -ForegroundColor Cyan

Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host "   PART 1 - ENTRA DIRECTORY ROLE REPORT SUMMARY" -ForegroundColor Green
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
    $entraOutputPath = Join-Path -Path $OutputFolder -ChildPath "EntraRoleReport_$reportTimestamp.csv"
    $report |
        Sort-Object RoleName, AssignmentSource, PrincipalDisplayName |
        Export-Csv -Path $entraOutputPath -NoTypeInformation -Encoding UTF8

    Write-Host "  Output file: $entraOutputPath" -ForegroundColor Cyan
    Write-Host ""
}

# ================================================================================
# ================================================================================
# PART 2 - WORKLOAD (MICROSOFT 365) DIRECTLY ASSIGNED ROLES
# Workload RBAC systems are separate from Entra directory roles. Someone holding
# the Entra 'Exchange Administrator' role is covered by Part 1; someone added
# directly to an Exchange, Purview, or Intune role / role group is only visible
# here.
#   W1. Exchange Online - management role groups + members, plus roles assigned
#       directly to users              (ExchangeOnlineManagement module)
#   W2. Purview / Security & Compliance - role groups + members
#       (Connect-IPPSSession, same module, separate sign-in)
#   W3. Intune - RBAC role assignments via Graph v1.0; each admin group is
#       expanded to its members        (DeviceManagementRBAC.Read.All)
#   W4. Defender XDR - unified RBAC via Graph beta (OPT-IN: -IncludeDefender)
#   W5. Windows 365 / Cloud PC - RBAC via Graph beta (OPT-IN: -IncludeCloudPC)
# ================================================================================
# ================================================================================

$workloadReport = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-WorkloadRow {
    param (
        [string]$Workload,
        [string]$Role,
        [string]$AssignmentName = "N/A",
        [string]$MemberDisplayName = "Unknown",
        [string]$MemberIdentity = "N/A",
        [string]$MemberType = "Unknown",
        [string]$AssignedVia,
        [string]$Scope = "N/A",
        [string]$AccountEnabled = "N/A"
    )

    $workloadReport.Add([PSCustomObject]@{
        Workload          = $Workload
        Role              = $Role
        AssignmentName    = $AssignmentName
        MemberDisplayName = $MemberDisplayName
        MemberIdentity    = $MemberIdentity
        MemberType        = $MemberType
        AssignedVia       = $AssignedVia
        Scope             = $Scope
        AccountEnabled    = $AccountEnabled
    })
}

# Pages through a Graph collection URI and returns every item.
function Invoke-GraphGetAll {
    param ([string]$Uri)

    $items = [System.Collections.Generic.List[object]]::new()
    $next  = $Uri
    while ($next) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        if ($resp.value) {
            foreach ($v in $resp.value) { $items.Add($v) }
        }
        $next = $resp.'@odata.nextLink'
    }
    return ,$items
}

# EXO / Purview role group members are ReducedRecipient objects whose populated
# properties vary by recipient type, so probe a few candidates in order.
function Get-RecipientIdentity {
    param ($Member)

    foreach ($candidate in @($Member.PrimarySmtpAddress, $Member.WindowsLiveID, $Member.ExternalDirectoryObjectId, $Member.Name)) {
        if ($candidate) { return "$candidate" }
    }
    return "N/A"
}

# Returns a named property from either an SDK object or a REST hashtable,
# case-insensitively, or $null when absent. Lets one code path serve both the
# beta cmdlets and the Invoke-MgGraphRequest fallback.
function Get-PropValue {
    param ($InputObject, [string]$Name)

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ("$key" -ieq $Name) { return $InputObject[$key] }
        }
        return $null
    }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

# Reads role assignments from a Graph unified-RBAC beta provider (Defender XDR,
# Cloud PC) into the local report list. READ-ONLY throughout. Prefers the
# Microsoft.Graph.Beta cmdlets when installed; otherwise falls back to
# Invoke-MgGraphRequest - the Graph SDK's own REST cmdlet - on the same
# signed-in session. Assignments are always queried per role definition with a
# roleDefinitionId filter, because these providers can reject unfiltered list
# calls with 400 Bad Request.
function Read-UnifiedRbacProvider {
    param (
        [string]$Workload,
        [string]$Provider,
        [string]$DefinitionCmdlet,
        [string]$AssignmentCmdlet
    )

    $haveDefCmdlet = [bool](Get-Command -Name $DefinitionCmdlet -ErrorAction SilentlyContinue)
    $haveAsgCmdlet = [bool](Get-Command -Name $AssignmentCmdlet -ErrorAction SilentlyContinue)
    $useCmdlets    = ($haveDefCmdlet -and $haveAsgCmdlet)
    $baseUri       = "https://graph.microsoft.com/beta/roleManagement/$Provider"

    if (-not $useCmdlets) {
        Write-Host "    (Beta cmdlets not installed - using Invoke-MgGraphRequest on the same Graph session. 'Install-Module Microsoft.Graph.Beta' enables native cmdlets.)" -ForegroundColor Gray
    }

    $defs = @()
    if ($useCmdlets) {
        $defs = @(& $DefinitionCmdlet -All -ErrorAction Stop)
    }
    else {
        $defs = Invoke-GraphGetAll -Uri "$baseUri/roleDefinitions"
    }

    foreach ($def in $defs) {
        $defId   = "$(Get-PropValue -InputObject $def -Name 'id')"
        $defName = "$(Get-PropValue -InputObject $def -Name 'displayName')"
        if (-not $defId) { continue }
        if (-not $defName) { $defName = "Unknown role ($defId)" }

        $assignments = @()
        if ($useCmdlets) {
            $assignments = @(& $AssignmentCmdlet -Filter "roleDefinitionId eq '$defId'" -All -ErrorAction Stop)
        }
        else {
            $assignments = Invoke-GraphGetAll -Uri ("$baseUri/roleAssignments?`$filter=roleDefinitionId eq '$defId'")
        }

        foreach ($asg in $assignments) {
            $asgName = "$(Get-PropValue -InputObject $asg -Name 'displayName')"
            if (-not $asgName) { $asgName = 'Role Assignment' }

            $scopeParts = [System.Collections.Generic.List[string]]::new()
            foreach ($ds in @(Get-PropValue -InputObject $asg -Name 'directoryScopeIds')) {
                if ("$ds" -eq '/') { $scopeParts.Add('Tenant-wide') }
                elseif ($ds) { $scopeParts.Add("$ds") }
            }
            foreach ($aps in @(Get-PropValue -InputObject $asg -Name 'appScopeIds')) {
                if ($aps) { $scopeParts.Add("$aps") }
            }
            $scopeDesc = $(if ($scopeParts.Count -gt 0) { $scopeParts -join '; ' } else { 'N/A' })

            foreach ($prinId in @(Get-PropValue -InputObject $asg -Name 'principalIds')) {
                if (-not $prinId) { continue }
                $principal = Resolve-Principal -PrincipalId "$prinId" -PrincipalType ""

                $row = @{
                    Workload          = $Workload
                    Role              = $defName
                    AssignmentName    = $asgName
                    MemberDisplayName = $principal.DisplayName
                    MemberIdentity    = $(if ($principal.UPN -ne 'N/A') { $principal.UPN } else { "$prinId" })
                    MemberType        = $principal.PrincipalType
                    AssignedVia       = 'Direct Role Assignment'
                    Scope             = $scopeDesc
                    AccountEnabled    = "$($principal.AccountEnabled)"
                }
                Add-WorkloadRow @row

                # Assigned groups get expanded to members, mirroring the Intune section.
                if ($principal.PrincipalType -eq 'Group') {
                    $gMembers = @()
                    try {
                        $gMembers = @(Get-MgGroupMember -GroupId "$prinId" -All -ErrorAction Stop)
                    }
                    catch {
                        Write-Warning "Could not expand group '$($principal.DisplayName)' ($prinId) for $Workload : $_"
                    }

                    foreach ($gm in $gMembers) {
                        $gmType     = $gm.AdditionalProperties.'@odata.type' -replace '#microsoft\.graph\.',''
                        $gPrincipal = Resolve-Principal -PrincipalId $gm.Id -PrincipalType $gmType

                        $row = @{
                            Workload          = $Workload
                            Role              = $defName
                            AssignmentName    = $asgName
                            MemberDisplayName = $gPrincipal.DisplayName
                            MemberIdentity    = $(if ($gPrincipal.UPN -ne 'N/A') { $gPrincipal.UPN } else { "$($gm.Id)" })
                            MemberType        = $gPrincipal.PrincipalType
                            AssignedVia       = "Group Member (via $($principal.DisplayName))"
                            Scope             = $scopeDesc
                            AccountEnabled    = "$($gPrincipal.AccountEnabled)"
                        }
                        Add-WorkloadRow @row
                    }
                }
            }
        }
    }
}

if (-not $exoModulePresent -and -not ($SkipExchangeOnline -and $SkipPurview)) {
    Write-Warning "ExchangeOnlineManagement module not found - skipping the Exchange Online and Purview sections."
    Write-Warning "Run 'Install-Module ExchangeOnlineManagement' and rerun to include them."
}

# --------------------------------------------------------------------------------
# W1 - Exchange Online role groups and direct role assignments
# --------------------------------------------------------------------------------
if ($SkipExchangeOnline) {
    Write-Host "`n[*] Skipping Exchange Online (per -SkipExchangeOnline)." -ForegroundColor Gray
}
elseif ($exoModulePresent) {
    Write-Host "`n[*] Collecting Exchange Online role groups (a separate sign-in may appear)..." -ForegroundColor Cyan
    $exoConnected = $false
    try {
        $exoConnectParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($context -and $context.Account) { $exoConnectParams['UserPrincipalName'] = "$($context.Account)" }
        Connect-ExchangeOnline @exoConnectParams
        $exoConnected = $true

        $exoRoleGroups = @(Get-RoleGroup -ResultSize Unlimited -ErrorAction Stop)
        Write-Host "    Processing $($exoRoleGroups.Count) role group(s)..." -ForegroundColor Yellow

        foreach ($rg in $exoRoleGroups) {
            $rgName = $(if ($rg.DisplayName) { "$($rg.DisplayName)" } else { "$($rg.Name)" })
            $rgId   = $(if ($rg.ExchangeObjectId) { "$($rg.ExchangeObjectId)" } else { "$($rg.Identity)" })

            $rgMembers = @()
            try {
                $rgMembers = @(Get-RoleGroupMember -Identity $rgId -ResultSize Unlimited -ErrorAction Stop)
            }
            catch {
                Write-Warning "Could not enumerate members of Exchange role group '$rgName': $_"
            }

            foreach ($m in $rgMembers) {
                $row = @{
                    Workload          = 'Exchange Online'
                    Role              = $rgName
                    AssignmentName    = 'Role Group'
                    MemberDisplayName = $(if ($m.DisplayName) { "$($m.DisplayName)" } else { "$($m.Name)" })
                    MemberIdentity    = Get-RecipientIdentity -Member $m
                    MemberType        = "$($m.RecipientTypeDetails)"
                    AssignedVia       = 'Role Group Member'
                }
                Add-WorkloadRow @row
            }
        }

        # Roles assigned straight to a user, bypassing role groups entirely.
        $directAssignments = @()
        try {
            $directAssignments = @(Get-ManagementRoleAssignment -RoleAssigneeType User -Delegating:$false -ErrorAction Stop)
        }
        catch {
            Write-Warning "Could not enumerate direct Exchange role assignments: $_"
        }

        foreach ($ra in $directAssignments) {
            $row = @{
                Workload          = 'Exchange Online'
                Role              = "$($ra.Role)"
                AssignmentName    = "$($ra.Name)"
                MemberDisplayName = "$($ra.RoleAssigneeName)"
                MemberType        = 'User'
                AssignedVia       = 'Direct Role Assignment'
                Scope             = "$($ra.RecipientWriteScope)"
            }
            Add-WorkloadRow @row
        }
    }
    catch {
        $failMsg = "$_"
        Write-Warning "Exchange Online collection failed: $failMsg"
        if ($failMsg -match 'Microsoft\.Identity\.Client|Could not load file or assembly') {
            Write-Warning "This is the known Graph/EXO assembly conflict. Start a FRESH PowerShell 7 session, run 'Update-Module ExchangeOnlineManagement', and rerun."
        }
    }
    finally {
        if ($exoConnected) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        }
    }

    $exoCount = @($workloadReport | Where-Object { $_.Workload -eq 'Exchange Online' }).Count
    Write-Host "[+] Exchange Online rows collected: $exoCount" -ForegroundColor Green
}

# --------------------------------------------------------------------------------
# W2 - Purview / Security & Compliance role groups
# Same cmdlet names as Exchange but a different backend, so this runs in its own
# connect / collect / disconnect window to avoid cmdlet collisions.
# --------------------------------------------------------------------------------
if ($SkipPurview) {
    Write-Host "`n[*] Skipping Purview (per -SkipPurview)." -ForegroundColor Gray
}
elseif ($exoModulePresent) {
    Write-Host "`n[*] Collecting Purview role groups (a separate sign-in may appear)..." -ForegroundColor Cyan
    $ippsConnected = $false
    try {
        $ippsConnectParams = @{ ErrorAction = 'Stop' }
        if ($context -and $context.Account) { $ippsConnectParams['UserPrincipalName'] = "$($context.Account)" }
        Connect-IPPSSession @ippsConnectParams
        $ippsConnected = $true

        $scRoleGroups = @(Get-RoleGroup -ResultSize Unlimited -ErrorAction Stop)
        Write-Host "    Processing $($scRoleGroups.Count) role group(s)..." -ForegroundColor Yellow

        foreach ($rg in $scRoleGroups) {
            $rgName = $(if ($rg.DisplayName) { "$($rg.DisplayName)" } else { "$($rg.Name)" })
            $rgId   = $(if ($rg.ExchangeObjectId) { "$($rg.ExchangeObjectId)" } else { "$($rg.Identity)" })

            $rgMembers = @()
            try {
                $rgMembers = @(Get-RoleGroupMember -Identity $rgId -ResultSize Unlimited -ErrorAction Stop)
            }
            catch {
                Write-Warning "Could not enumerate members of Purview role group '$rgName': $_"
            }

            foreach ($m in $rgMembers) {
                $row = @{
                    Workload          = 'Purview (Security & Compliance)'
                    Role              = $rgName
                    AssignmentName    = 'Role Group'
                    MemberDisplayName = $(if ($m.DisplayName) { "$($m.DisplayName)" } else { "$($m.Name)" })
                    MemberIdentity    = Get-RecipientIdentity -Member $m
                    MemberType        = "$($m.RecipientTypeDetails)"
                    AssignedVia       = 'Role Group Member'
                }
                Add-WorkloadRow @row
            }
        }
    }
    catch {
        $failMsg = "$_"
        Write-Warning "Purview collection failed: $failMsg"
        if ($failMsg -match 'Microsoft\.Identity\.Client|Could not load file or assembly') {
            Write-Warning "This is the known Graph/EXO assembly conflict. Start a FRESH PowerShell 7 session, run 'Update-Module ExchangeOnlineManagement', and rerun."
        }
    }
    finally {
        if ($ippsConnected) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        }
    }

    $purviewCount = @($workloadReport | Where-Object { $_.Workload -eq 'Purview (Security & Compliance)' }).Count
    Write-Host "[+] Purview rows collected: $purviewCount" -ForegroundColor Green
}

# --------------------------------------------------------------------------------
# W3 - Intune RBAC role assignments (Graph v1.0)
# Intune assigns roles to Entra security groups; each admin group is listed and
# then expanded to its members so the individual admins are visible.
# --------------------------------------------------------------------------------
if ($SkipIntune) {
    Write-Host "`n[*] Skipping Intune (per -SkipIntune)." -ForegroundColor Gray
}
else {
    Write-Host "`n[*] Collecting Intune RBAC role assignments..." -ForegroundColor Cyan
    try {
        $intuneRoleDefs = @(Get-MgDeviceManagementRoleDefinition -All -ErrorAction Stop)
        Write-Host "    Processing $($intuneRoleDefs.Count) Intune role definition(s)..." -ForegroundColor Yellow

        foreach ($def in $intuneRoleDefs) {
            $assignmentRefs = @(Get-MgDeviceManagementRoleDefinitionRoleAssignment -RoleDefinitionId $def.Id -All -ErrorAction Stop)

            foreach ($ref in $assignmentRefs) {
                # The per-definition list returns summaries; fetch the full
                # deviceAndAppManagementRoleAssignment so Members (admin groups)
                # and ResourceScopes (scope groups) are populated.
                $asg = Get-MgDeviceManagementRoleAssignment -DeviceAndAppManagementRoleAssignmentId $ref.Id -ErrorAction Stop

                $scopeParts = [System.Collections.Generic.List[string]]::new()
                if ($asg.ScopeType) { $scopeParts.Add("$($asg.ScopeType)") }
                foreach ($rs in @($asg.ResourceScopes)) {
                    if ("$rs" -match '^[0-9a-fA-F\-]{36}$') {
                        $scopeParts.Add((Resolve-Principal -PrincipalId "$rs" -PrincipalType "Group").DisplayName)
                    }
                    elseif ($rs) {
                        $scopeParts.Add("$rs")
                    }
                }
                $scopeDesc = $(if ($scopeParts.Count -gt 0) { $scopeParts -join '; ' } else { 'N/A' })

                $memberGroupIds = @($asg.Members)
                if ($memberGroupIds.Count -eq 0 -and $asg.AdditionalProperties -and $asg.AdditionalProperties.ContainsKey('members')) {
                    $memberGroupIds = @($asg.AdditionalProperties['members'])
                }
                if ($memberGroupIds.Count -eq 0) {
                    $row = @{
                        Workload          = 'Intune'
                        Role              = "$($def.displayName)"
                        AssignmentName    = "$($asg.displayName)"
                        MemberDisplayName = '(no admin groups on this assignment)'
                        AssignedVia       = 'Intune Role Assignment'
                        Scope             = $scopeDesc
                    }
                    Add-WorkloadRow @row
                    continue
                }

                foreach ($gid in $memberGroupIds) {
                    $groupInfo = Resolve-Principal -PrincipalId "$gid" -PrincipalType "Group"

                    $row = @{
                        Workload          = 'Intune'
                        Role              = "$($def.displayName)"
                        AssignmentName    = "$($asg.displayName)"
                        MemberDisplayName = $groupInfo.DisplayName
                        MemberIdentity    = "$gid"
                        MemberType        = 'Group'
                        AssignedVia       = 'Intune Assignment Group'
                        Scope             = $scopeDesc
                    }
                    Add-WorkloadRow @row

                    # Expand the admin group to individual members.
                    $gMembers = @()
                    try {
                        $gMembers = @(Get-MgGroupMember -GroupId "$gid" -All -ErrorAction Stop)
                    }
                    catch {
                        Write-Warning "Could not expand Intune admin group '$($groupInfo.DisplayName)' ($gid): $_"
                    }

                    foreach ($gm in $gMembers) {
                        $gmType    = $gm.AdditionalProperties.'@odata.type' -replace '#microsoft\.graph\.',''
                        $principal = Resolve-Principal -PrincipalId $gm.Id -PrincipalType $gmType

                        $row = @{
                            Workload          = 'Intune'
                            Role              = "$($def.displayName)"
                            AssignmentName    = "$($asg.displayName)"
                            MemberDisplayName = $principal.DisplayName
                            MemberIdentity    = $(if ($principal.UPN -ne 'N/A') { $principal.UPN } else { "$($gm.Id)" })
                            MemberType        = $principal.PrincipalType
                            AssignedVia       = "Intune Group Member (via $($groupInfo.DisplayName))"
                            Scope             = $scopeDesc
                            AccountEnabled    = "$($principal.AccountEnabled)"
                        }
                        Add-WorkloadRow @row
                    }
                }
            }
        }

        $intuneCount = @($workloadReport | Where-Object { $_.Workload -eq 'Intune' }).Count
        Write-Host "[+] Intune rows collected: $intuneCount" -ForegroundColor Green
    }
    catch {
        Write-Warning "Intune RBAC collection failed: $_"
        Write-Warning "Verify the DeviceManagementRBAC.Read.All scope was consented and the tenant has Intune licensing."
    }
}

# --------------------------------------------------------------------------------
# W4 - Microsoft Defender XDR unified RBAC (Graph beta)
# Only returns data where Defender XDR unified RBAC is active in the tenant.
# --------------------------------------------------------------------------------
if (-not $IncludeDefender) {
    Write-Host "`n[*] Skipping Defender XDR (opt-in - pass -IncludeDefender to collect)." -ForegroundColor Gray
}
else {
    Write-Host "`n[*] Collecting Defender XDR role assignments (Graph beta)..." -ForegroundColor Cyan
    try {
        Read-UnifiedRbacProvider -Workload 'Defender XDR' -Provider 'defender' -DefinitionCmdlet 'Get-MgBetaRoleManagementDefenderRoleDefinition' -AssignmentCmdlet 'Get-MgBetaRoleManagementDefenderRoleAssignment'

        $defenderCount = @($workloadReport | Where-Object { $_.Workload -eq 'Defender XDR' }).Count
        Write-Host "[+] Defender XDR rows collected: $defenderCount" -ForegroundColor Green
    }
    catch {
        $failMsg = "$_"
        Write-Warning "Defender XDR collection failed: $failMsg"
        if ($failMsg -match '400|Bad Request') {
            Write-Warning "A 400 here usually means Defender XDR unified RBAC is not activated in this tenant - the provider rejects queries until workloads are migrated to unified RBAC. Section skipped."
        }
        elseif ($failMsg -match '403|Forbidden') {
            Write-Warning "A 403 means RoleManagement.Read.Defender was not consented or your account lacks a Defender XDR role."
        }
    }
}

# --------------------------------------------------------------------------------
# W5 - Windows 365 / Cloud PC RBAC (Graph beta)
# --------------------------------------------------------------------------------
if (-not $IncludeCloudPC) {
    Write-Host "`n[*] Skipping Windows 365 / Cloud PC (opt-in - pass -IncludeCloudPC to collect)." -ForegroundColor Gray
}
else {
    Write-Host "`n[*] Collecting Windows 365 (Cloud PC) role assignments (Graph beta)..." -ForegroundColor Cyan
    try {
        Read-UnifiedRbacProvider -Workload 'Windows 365 (Cloud PC)' -Provider 'cloudPC' -DefinitionCmdlet 'Get-MgBetaRoleManagementCloudPcRoleDefinition' -AssignmentCmdlet 'Get-MgBetaRoleManagementCloudPcRoleAssignment'

        $cloudPcCount = @($workloadReport | Where-Object { $_.Workload -eq 'Windows 365 (Cloud PC)' }).Count
        Write-Host "[+] Windows 365 rows collected: $cloudPcCount" -ForegroundColor Green
    }
    catch {
        $failMsg = "$_"
        Write-Warning "Windows 365 (Cloud PC) collection failed: $failMsg"
        if ($failMsg -match '403|Forbidden') {
            Write-Warning "A 403 here almost always means the tenant has no Windows 365 / Cloud PC licensing, the RoleManagement.Read.CloudPC scope was not consented, or your account lacks a Cloud PC role. Section skipped."
        }
        elseif ($failMsg -match '400|Bad Request') {
            Write-Warning "A 400 suggests the Cloud PC RBAC provider is not available in this tenant. Section skipped."
        }
    }
}

# ================================================================================
# PART 2 OUTPUT - one CSV per workload app
# ================================================================================
Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host "    PART 2 - WORKLOAD ROLE REPORTS SUMMARY" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green

# Workload display name -> filename token
$workloadFileTokens = [ordered]@{
    'Exchange Online'                 = 'ExchangeOnline'
    'Purview (Security & Compliance)' = 'Purview'
    'Intune'                          = 'Intune'
    'Defender XDR'                    = 'DefenderXDR'
    'Windows 365 (Cloud PC)'          = 'CloudPC'
}

foreach ($wl in $workloadFileTokens.Keys) {
    $rows = @($workloadReport | Where-Object { $_.Workload -eq $wl })
    Write-Host ("  {0,-32}: {1}" -f $wl, $rows.Count)

    if ($rows.Count -gt 0) {
        $wlPath = Join-Path -Path $OutputFolder -ChildPath "$($workloadFileTokens[$wl])RoleReport_$reportTimestamp.csv"
        $rows |
            Sort-Object Role, MemberDisplayName |
            Export-Csv -Path $wlPath -NoTypeInformation -Encoding UTF8
        Write-Host "      -> $wlPath" -ForegroundColor Cyan
    }
}
Write-Host ("  {0,-32}: {1}" -f 'Total rows', $workloadReport.Count)
Write-Host ""

if ($workloadReport.Count -eq 0) {
    Write-Warning "No workload role assignments were collected - no Part 2 files were written. Review the warnings above."
}

Disconnect-MgGraph | Out-Null
Write-Host "[*] Disconnected from Microsoft Graph.`n" -ForegroundColor Gray
