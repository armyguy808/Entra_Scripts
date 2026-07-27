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
                          (Connect-ExchangeOnline to the Compliance endpoint;
                          triggers its own sign-in)
      - Intune          : RBAC role assignments via Graph v1.0, with each
                          admin group expanded to its individual members
      - Defender XDR    : unified RBAC role assignments (Graph beta; opt-in
                          via -IncludeDefender), groups expanded to members
      - Windows 365     : Cloud PC RBAC role assignments (Graph beta; opt-in
                          via -IncludeCloudPC), groups expanded to members
      - Azure RBAC      : Azure subscription role assignments via the Az
                          modules (opt-in via -IncludeAzureRBAC), groups
                          expanded to members
    Workloads whose admin rights come only from Entra directory roles (Teams,
    SharePoint, Power BI / Fabric) are already covered by Part 1 and have no
    separate in-app tenant RBAC to report.

    Use -Reports to run an explicit subset (e.g. -Reports Intune,AzureRBAC);
    when -Reports is supplied it alone determines which reports run.

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

.PARAMETER Reports
    Optional list of specific reports to run. When supplied, ONLY the listed
    reports run and the -Skip* / -Include* switches are ignored. Valid values:
    Entra, ExchangeOnline, Purview, Intune, DefenderXDR, CloudPC, AzureRBAC.
    Default (empty) keeps the standard full run unchanged.

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

.PARAMETER IncludeAzureRBAC
    Opt in to the Azure subscription (Azure RBAC) role assignment report.
    Requires the Az.Accounts and Az.Resources modules and a separate Azure
    sign-in; the account needs Reader (or higher) on the subscriptions.

.PARAMETER ForceAzureLogin
    Force a fresh Connect-AzAccount for the Azure RBAC report even when a
    cached Azure context already exists. Use this to switch accounts. Without
    it, an existing Azure sign-in is reused (which is why no prompt appears
    when you are already signed in).

.PARAMETER UseAzureDeviceCode
    Use Azure device-code authentication instead of the interactive browser
    for the Azure RBAC sign-in. Useful in Windows PowerShell 5.1 or remote
    sessions where the browser cannot be launched. The script also falls back
    to device code automatically if the browser sign-in fails.

.EXAMPLE
    .\Entra_PrivilegedRole_Report.ps1

.EXAMPLE
    .\Entra_PrivilegedRole_Report.ps1 -OutputFolder "D:\Reports"

.EXAMPLE
    .\Entra_PrivilegedRole_Report.ps1 -RoleFilter "Global Administrator","Privileged Role Administrator"

.EXAMPLE
    .\Entra_PrivilegedRole_Report.ps1 -Reports Intune,AzureRBAC

.NOTES
    Authentication: DELEGATED INTERACTIVE only. The script signs in with
    Connect-MgGraph -Scopes, which prompts the operator; there is no app-only
    parameter set (no -ClientId / -CertificateThumbprint / managed identity),
    so it cannot run unattended as written.

    Required Graph API permissions (delegated):
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
    The Exchange Online and Purview sections each trigger their own
    Connect-ExchangeOnline sign-in (Purview targets the Security & Compliance
    endpoint), and the account needs role-management visibility in each workload
    (for example View-Only Organization Management in Exchange Online and a
    Purview role group with role-management read access). If the module is
    missing, those sections are skipped with a warning. The Intune section
    requires an Intune-licensed tenant. Defender XDR and Windows 365 are
    OPT-IN sections on Graph BETA endpoints - enable them with
    -IncludeDefender / -IncludeCloudPC once the tenant is ready for them.
    Use the -Skip* switches to opt out of the default workloads, or -Reports
    to run an explicit subset.

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
    missing licensing.

    Azure RBAC (opt-in): requires the Az.Accounts and Az.Resources modules
    (Install-Module Az.Accounts, Az.Resources) and a separate
    Connect-AzAccount sign-in; the account needs Reader or higher on each
    subscription. Enabled subscriptions are enumerated and assignments are
    collected at subscription scope and below - the Scope column shows where
    each one lives, including entries inherited from management groups. This
    is where Azure Virtual Desktop admin rights appear (AVD is Azure RBAC,
    not Microsoft Graph). The Azure sign-in is PINNED to the Microsoft Graph
    tenant, and subscriptions are enumerated for that tenant only - without
    this, an Azure sign-in landing on the account's home tenant returns another
    tenant's subscriptions (or none) and the report comes back silently empty.
    Assignments are collected twice per subscription - once for the subscription
    and below, once for what is effective AT the subscription so management
    group and tenant root inheritance is captured - and deduplicated on the
    assignment resource ID. Azure PowerShell caches sign-ins across sessions, so
    if you are already signed in no prompt appears and the existing context is
    reused; pass -ForceAzureLogin to sign in as a different account. If the
    interactive browser does not open (common in Windows PowerShell 5.1), pass
    -UseAzureDeviceCode - the script also falls back to device code on its own
    if the browser attempt fails.

    CSV hardening: exported values that begin with =, +, -, @ or a leading
    tab/CR/LF are prefixed with a single quote so spreadsheet software treats
    them as text rather than formulas. This is applied at export time only, so
    the sanitized character appears in the CSV but never affects the script's
    own comparisons or dedup logic.

    Group expansion depth: workload sections (Intune, Defender XDR, Cloud PC,
    Azure RBAC) expand assigned groups TRANSITIVELY and label members reached
    through a nested group as 'Nested Group Member'. Entra role-assignable
    groups cannot be nested, so Sections 3c/3d report direct membership.

    Session handling: Exchange and Purview sessions created by this run are
    disconnected by ConnectionId (ExchangeOnlineManagement 3.2.0+), so a
    session the operator already had open in the same window is left
    connected. On older module versions targeted disconnect does not exist;
    the script then announces that it is closing ALL sessions in the process.
    Even targeted disconnects also close LEGACY remote PowerShell (RPS)
    Exchange sessions in the same window - module behavior the script cannot
    prevent and warns about when such sessions exist. For complete isolation,
    run the script in its own dedicated powershell.exe process. The Azure
    section snapshots the active Azure context before running and restores it
    afterward. Purview fails closed when the session type cannot be proven to
    be Security & Compliance. A run whose data is DEGRADED (blocked identity
    lookups or unknown membership depth) exits with code 4. Exchange
    direct-assignee lookup failures are never cached and are counted in RUN
    STATUS. Azure cleanup disconnects only the account this run signed in as -
    and skips the disconnect entirely when the operator's original context
    depends on that same account, so its credentials survive - then restores
    the original context; a failed restore is reported as DEGRADED.

    Exchange effective users: the -GetEffectiveUsers pass expands
    SecurityGroup and RoleGroup assignees only. User assignees are already
    reported by the direct pass, and RoleAssignmentPolicy assignments are
    end-user self-management roles applied to every mailbox, whose expansion
    would flood the report with non-administrative rows.

    MemberIdentity semantics in the workload reports: users show their UPN or
    sign-in name; groups show their mail address when one exists, otherwise
    'GroupId: <guid>'; service principals show 'AppId: <guid>'; unresolved or
    orphaned principals show 'ObjectId: <guid>' - a bare GUID always states
    what kind of ID it is.

    Unresolvable principal IDs are additionally checked against the Entra
    deleted-items container: a display name of 'DELETED: <name> (deleted
    <date>)' means the object is soft-deleted and still restorable for about
    30 days, while 'Unknown (possibly deleted)' means it was hard-deleted or
    never existed. Role assignments pointing at such IDs are stale and safe
    to clean up.

    The Microsoft Graph sign-in is skipped automatically when no selected
    report needs it (for example -Reports Purview or -Reports ExchangeOnline,
    which use their own sessions). The Azure RBAC report does use Graph to
    resolve and expand assigned principals (and to detect soft-deleted
    objects), so selecting it establishes a Graph session in addition to the
    Azure sign-in.
#>

[CmdletBinding()]
param (
    [string]$OutputFolder = "C:\temp",

    [string[]]$RoleFilter = @(),

    [ValidateSet('Entra','ExchangeOnline','Purview','Intune','DefenderXDR','CloudPC','AzureRBAC')]
    [string[]]$Reports = @(),

    [switch]$SkipExchangeOnline,

    [switch]$SkipPurview,

    [switch]$SkipIntune,

    [switch]$IncludeDefender,

    [switch]$IncludeCloudPC,

    [switch]$IncludeAzureRBAC,

    [switch]$ForceAzureLogin,

    [switch]$UseAzureDeviceCode,

    [ValidateSet('Commercial','GCC','GCCHigh','DoD')]
    [string]$Cloud = 'DoD',

    # Endpoint overrides. Leave empty to inherit the correct values from -Cloud;
    # set any of them only to point at a non-standard endpoint. Nothing here
    # needs to be remembered for a normal run.
    [string]$GraphEnvironmentName = '',

    [string]$AzureEnvironmentName = '',

    [string]$ExchangeEnvironmentName = '',

    [string]$GraphBaseUriOverride = '',

    [string]$ComplianceConnectionUri = '',

    [string]$ComplianceAuthUri = ''
)

# ================================================================================
# Session cleanup and run-status tracking.
# Cleanup is callable from every failure path, because an 'exit 1' partway
# through would otherwise leave administrative sessions open. Status tracking
# exists so a partially failed run cannot be mistaken for a complete one.
# ================================================================================
$script:graphConnected        = $false
$script:exoRunConnectionIds   = @()
$script:sectionErrors         = @{}
$script:exportFailures        = @{}
$script:unresolvedLookupCount     = 0
$script:unresolvedPrincipalIds    = [System.Collections.Generic.HashSet[string]]::new()
$script:unknownDepthGroups        = 0
$script:unknownDepthGroupIds      = [System.Collections.Generic.HashSet[string]]::new()
$script:exoAssigneeLookupFailures = 0
$script:exoForeignPrincipalRows   = 0
$script:linkedGroupPlaceholders   = 0
$script:azRestoreFailures         = 0
$script:cleanupWarningMessages    = [System.Collections.Generic.HashSet[string]]::new()

# Returns the ConnectionId of every Exchange/Compliance REST connection open in
# this process. Empty on module versions before 3.2.0 (no
# Get-ConnectionInformation), which also means targeted disconnect is
# unavailable there.
function Get-ExoConnectionIds {
    if (Get-Command -Name Get-ConnectionInformation -ErrorAction SilentlyContinue) {
        try {
            return @((Get-ConnectionInformation -ErrorAction Stop) | ForEach-Object { "$($_.ConnectionId)" })
        }
        catch { }
    }
    return @()
}

# Records local-session cleanup failures without converting them into workload
# query failures. Cleanup warnings make the run DEGRADED because report data may
# be complete while administrative sessions or contexts remain open.
function Register-CleanupWarning {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not [string]::IsNullOrWhiteSpace($Message)) {
        $null = $script:cleanupWarningMessages.Add($Message)
        Write-Warning $Message
    }
}

# Disconnects the REST connections whose ConnectionIds were recorded by this
# run. It deliberately does NOT fall back to a bare Disconnect-ExchangeOnline:
# the bare command would close every Exchange/Purview REST connection in this
# process. Even a ConnectionId-targeted disconnect can also close legacy RPS
# Exchange sessions in the same Windows PowerShell window, so complete isolation
# still requires a dedicated powershell.exe process.
function Disconnect-ExoRunSessions {
    [OutputType([bool])]
    param (
        [string[]]$ConnectionIds,
        [switch]$SessionWasCreated,
        [switch]$FinalAttempt
    )

    if (-not $ConnectionIds -or $ConnectionIds.Count -eq 0) {
        if ($SessionWasCreated) {
            Register-CleanupWarning -Message "An Exchange/Purview connection was created, but its ConnectionId could not be determined. The script will not use an untargeted disconnect because that would close preexisting REST sessions. Close the session manually or run this report in a dedicated powershell.exe process."
            return $false
        }
        return $true
    }

    # Warn about RPS collateral only when a disconnect is actually about to be
    # attempted - a no-op call must not warn about closing sessions it never
    # touches.
    try {
        $legacyRps = @(
            Get-PSSession -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.ConfigurationName -eq 'Microsoft.Exchange' -and
                    "$($_.State)" -eq 'Opened'
                }
        )
        if ($legacyRps.Count -gt 0) {
            Write-Warning "Disconnecting Exchange sessions will ALSO close $($legacyRps.Count) legacy remote PowerShell Exchange session(s) open in this window (ExchangeOnlineManagement behavior). Run this script in a dedicated powershell.exe process to protect them."
        }
    }
    catch { }

    try {
        Disconnect-ExchangeOnline -ConnectionId $ConnectionIds -Confirm:$false -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        $message = "Targeted Exchange/Purview disconnect failed for ConnectionId(s) '$($ConnectionIds -join ', ')': $($_.Exception.Message)."
        if ($FinalAttempt) {
            Register-CleanupWarning -Message "$message The connection remains open."
        }
        else {
            Write-Warning "$message The connection IDs remain tracked for the final cleanup retry."
        }
        return $false
    }
}

function Invoke-ScriptCleanup {
    if ($script:graphConnected) {
        try {
            Disconnect-MgGraph -ErrorAction Stop | Out-Null
            $script:graphConnected = $false
        }
        catch {
            Register-CleanupWarning -Message "Microsoft Graph disconnect failed: $($_.Exception.Message)."
        }
    }

    # Exchange / Purview sessions normally disconnect inside their own finally
    # blocks. This is a final retry for any ConnectionIds that remained tracked
    # because an earlier targeted disconnect failed.
    if ($script:exoRunConnectionIds.Count -gt 0) {
        $cleanupSucceeded = Disconnect-ExoRunSessions -ConnectionIds $script:exoRunConnectionIds -FinalAttempt
        if ($cleanupSucceeded) {
            $script:exoRunConnectionIds = @()
        }
    }
}

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
# ONLY definitive outcomes are cached (Found / NotFound / Deleted). A permission
# denial, a throttling response, or a transient service error must NOT be cached,
# because caching it would turn one blip into a permanent wrong answer for the
# rest of the run - and would make a live principal look deleted.
$script:PrincipalCache = @{}

# Classifies a Graph error so a genuine "no such object" can be told apart from
# "we were not allowed to look" or "we were throttled".
function Get-GraphErrorClass {
    param ($ErrorRecord)

    $msg    = "$($ErrorRecord.Exception.Message)"
    $status = ''
    try { $status = "$($ErrorRecord.Exception.Response.StatusCode)" } catch { }

    if ($status -match '404' -or $msg -match 'Request_ResourceNotFound|ResourceNotFound|does not exist|NotFound|Resource .* not found') {
        return 'NotFound'
    }
    if ($status -match '403' -or $msg -match 'Authorization_RequestDenied|Forbidden|Insufficient privileges|Access denied|Accessdenied') {
        return 'AccessDenied'
    }
    if ($status -match '429' -or $msg -match 'TooManyRequests|throttl|Rate limit') {
        return 'Throttled'
    }
    if ($status -match '50[0-9]' -or $msg -match 'ServiceNotAvailable|Service unavailable|timed out|timeout|Gateway|temporarily') {
        return 'Transient'
    }
    return 'Unexpected'
}

function Resolve-Principal {
    param (
        [string]$PrincipalId,
        [string]$PrincipalType   # "User", "Group", "ServicePrincipal", or "" to probe all three
    )

    if (-not $PrincipalId) {
        return [PSCustomObject]@{
            DisplayName      = 'Unresolved (no principal id)'
            UPN              = 'N/A'
            Identity         = 'N/A'
            PrincipalType    = 'Unknown'
            AccountEnabled   = 'N/A'
            IsDeleted        = $false
            ResolutionStatus = 'NoId'
        }
    }

    if ($script:PrincipalCache.ContainsKey($PrincipalId)) {
        return $script:PrincipalCache[$PrincipalId]
    }

    # Normalize the caller-supplied type. It usually arrives from an
    # @odata.type value ('user', 'group', 'servicePrincipal'), so proper-case it
    # for consistent output on rows that never resolve.
    $normalizedType = switch ("$PrincipalType") {
        'user'             { 'User' }
        'group'            { 'Group' }
        'servicePrincipal' { 'ServicePrincipal' }
        default            { $(if ($PrincipalType) { "$PrincipalType" } else { 'Unknown' }) }
    }

    $result = [PSCustomObject]@{
        DisplayName      = "Unresolved (ObjectId: $PrincipalId)"
        UPN              = "N/A"
        Identity         = "ObjectId: $PrincipalId (unresolved)"
        PrincipalType    = $normalizedType
        AccountEnabled   = "N/A"
        IsDeleted        = $false
        ResolutionStatus = 'Unknown'
    }

    # Probe each candidate type with -ErrorAction Stop so the failure REASON is
    # visible. A NotFound while probing is expected and moves on to the next
    # type; anything else is a real problem and stops the probe.
    $found        = $false
    $blockedClass = $null

    foreach ($probe in @('User','Group','ServicePrincipal')) {
        if ($found -or $blockedClass) { break }
        if ($PrincipalType -and $PrincipalType -ne $probe) { continue }

        try {
            switch ($probe) {
                'User' {
                    $user = Get-MgUser -UserId $PrincipalId -Property "DisplayName","UserPrincipalName","AccountEnabled" -ErrorAction Stop
                    if ($user) {
                        $result.DisplayName    = $user.DisplayName
                        $result.UPN            = $user.UserPrincipalName
                        $result.Identity       = $user.UserPrincipalName
                        $result.PrincipalType  = 'User'
                        $result.AccountEnabled = $user.AccountEnabled
                        $found = $true
                    }
                }
                'Group' {
                    $group = Get-MgGroup -GroupId $PrincipalId -Property "DisplayName","Mail" -ErrorAction Stop
                    if ($group) {
                        $result.DisplayName   = $group.DisplayName
                        $result.UPN           = "N/A (Group)"
                        $result.Identity      = $(if ($group.Mail) { $group.Mail } else { "GroupId: $PrincipalId" })
                        $result.PrincipalType = 'Group'
                        $found = $true
                    }
                }
                'ServicePrincipal' {
                    $sp = Get-MgServicePrincipal -ServicePrincipalId $PrincipalId -Property "DisplayName","AppId" -ErrorAction Stop
                    if ($sp) {
                        $result.DisplayName   = $sp.DisplayName
                        $result.UPN           = "N/A (ServicePrincipal)"
                        $result.Identity      = $(if ($sp.AppId) { "AppId: $($sp.AppId)" } else { "ObjectId: $PrincipalId" })
                        $result.PrincipalType = 'ServicePrincipal'
                        $found = $true
                    }
                }
            }
        }
        catch {
            $class = Get-GraphErrorClass -ErrorRecord $_
            if ($class -ne 'NotFound') { $blockedClass = $class }
        }
    }

    if ($found) {
        $result.ResolutionStatus = 'Found'
        $script:PrincipalCache[$PrincipalId] = $result
        return $result
    }

    if ($blockedClass) {
        # NOT cached - a later call may succeed once the condition clears.
        $script:unresolvedLookupCount++
        [void]$script:unresolvedPrincipalIds.Add($PrincipalId)
        $result.ResolutionStatus = $blockedClass
        switch ($blockedClass) {
            'AccessDenied' { $result.DisplayName = "Unresolved - access denied (ObjectId: $PrincipalId)" }
            'Throttled'    { $result.DisplayName = "Unresolved - throttled (ObjectId: $PrincipalId)" }
            'Transient'    { $result.DisplayName = "Unresolved - transient service error (ObjectId: $PrincipalId)" }
            default        { $result.DisplayName = "Unresolved - lookup error (ObjectId: $PrincipalId)" }
        }
        Write-Warning "Principal $PrincipalId could not be resolved ($blockedClass). It is NOT being reported as deleted, and the result is not cached."
        return $result
    }

    # Every applicable lookup returned NotFound. Check the deleted-items
    # container so a dangling ID can be reported as the concrete object it WAS.
    # Soft-deleted objects remain readable there for about 30 days.
    try {
        $deleted = Invoke-MgGraphRequest -Method GET -Uri "$GraphBaseUri/v1.0/directory/deletedItems/$PrincipalId" -ErrorAction Stop
        if ($deleted) {
            $deletedType = "$($deleted.'@odata.type')" -replace '#microsoft\.graph\.',''
            $deletedName = "$($deleted.displayName)"
            $deletedDate = "$($deleted.deletedDateTime)"

            $result.DisplayName = $(if ($deletedName) { "DELETED: $deletedName" } else { "DELETED object" })
            if ($deletedDate) { $result.DisplayName = "$($result.DisplayName) (deleted $deletedDate)" }
            if ($deletedType) { $result.PrincipalType = $deletedType }
            $result.Identity         = "ObjectId: $PrincipalId (soft-deleted)"
            $result.IsDeleted        = $true
            $result.ResolutionStatus = 'Deleted'

            $script:PrincipalCache[$PrincipalId] = $result
            return $result
        }
    }
    catch {
        $delClass = Get-GraphErrorClass -ErrorRecord $_
        if ($delClass -ne 'NotFound') {
            # Could not confirm deletion either way - do not cache, do not claim.
            $script:unresolvedLookupCount++
            [void]$script:unresolvedPrincipalIds.Add($PrincipalId)
            $result.ResolutionStatus = $delClass
            $result.DisplayName      = "Unresolved - deleted-items check failed ($delClass) (ObjectId: $PrincipalId)"
            return $result
        }
    }

    # Confirmed absent from both the directory and the deleted-items container.
    $result.DisplayName      = "Not found (ObjectId: $PrincipalId)"
    $result.ResolutionStatus = 'NotFound'
    $script:PrincipalCache[$PrincipalId] = $result
    return $result
}

# Resolves the scope of a role assignment / eligibility instance. Graph exposes
# BOTH directoryScopeId and appScopeId on these resources (they inherit from
# unifiedRoleScheduleInstanceBase), and they are alternatives: an app-scoped
# assignment leaves directoryScopeId empty. Returning a normalized ScopeKey
# alongside the display string matters twice over:
#   - the active/eligible dedup must not collapse two assignments that share a
#     role and principal but differ by app scope
#   - an app-scoped row must not render with a blank AssignmentScope
# Note appScopeId itself uses '/' for a tenant-wide app scope.
function Get-ScopeInfo {
    param ($Instance)

    $dirScope = "$($Instance.DirectoryScopeId)"
    $appScope = "$($Instance.AppScopeId)"

    # Fall back to AdditionalProperties for SDK shapes that don't surface these
    # as first-class properties.
    if (-not $dirScope -and $Instance.AdditionalProperties -and $Instance.AdditionalProperties.ContainsKey('directoryScopeId')) {
        $dirScope = "$($Instance.AdditionalProperties['directoryScopeId'])"
    }
    if (-not $appScope -and $Instance.AdditionalProperties -and $Instance.AdditionalProperties.ContainsKey('appScopeId')) {
        $appScope = "$($Instance.AdditionalProperties['appScopeId'])"
    }

    if ($appScope) {
        return [PSCustomObject]@{
            ScopeType = 'App'
            ScopeKey  = "app:$appScope"
            Display   = $(if ($appScope -eq '/') { 'App scope: tenant-wide' } else { "App scope: $appScope" })
        }
    }

    if ($dirScope) {
        return [PSCustomObject]@{
            ScopeType = 'Directory'
            ScopeKey  = "dir:$dirScope"
            Display   = $(if ($dirScope -eq '/') { 'Tenant-wide' } else { $dirScope })
        }
    }

    return [PSCustomObject]@{
        ScopeType = 'Unknown'
        ScopeKey  = 'none:'
        Display   = 'Unknown (no scope returned)'
    }
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
        [string]$ResolutionStatus = '',
        [string]$ScopeType = 'Unknown',
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
        ResolutionStatus     = $(if ($ResolutionStatus) { $ResolutionStatus } else { $Principal.ResolutionStatus })
        MemberType           = $MemberType
        AssignmentScope      = $AssignmentScope
        ScopeType            = $ScopeType
        StartDateTime        = $StartDateTime
        EndDateTime          = $EndDateTime
        GroupName            = $GroupName
        GroupId              = $GroupId
        MembershipType       = $MembershipType
    })
}

# ================================================================================
# Report selection. When -Reports is given it fully determines what runs;
# otherwise defaults apply: Entra, Exchange Online, Purview, and Intune on
# (honoring -Skip*), Defender XDR / Cloud PC / Azure RBAC opt-in (honoring
# -Include*).
# ================================================================================
$reportsSpecified = ($Reports.Count -gt 0)

# ================================================================================
# CSV hardening. Values beginning with =, +, -, @ or a leading tab/CR/LF can be
# executed as formulas when a CSV is opened in spreadsheet software, and display
# names here are directory-controlled. Such values are sanitized IN PLACE by
# prefixing a single quote, which spreadsheet apps treat as "this is text".
# Sanitizing happens at export time only, so all internal comparisons and dedup
# keys still use the unmodified values.
# ================================================================================
function Protect-CsvValue {
    param ($Value)

    if ($null -eq $Value) { return $Value }

    # Leave non-strings (dates, booleans, numbers) untouched.
    if ($Value -isnot [string]) { return $Value }

    if ($Value -match "^[=+\-@`t`r`n]") { return "'$Value" }
    return $Value
}

function ConvertTo-SafeCsvRow {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )

    process {
        if ($null -eq $InputObject) { return }

        $safe = [ordered]@{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $safe[$prop.Name] = Protect-CsvValue $prop.Value
        }
        [PSCustomObject]$safe
    }
}

# ================================================================================
# Workload group expansion. Get-MgGroupMember returns DIRECT members only, so a
# user nested inside another group is silently missed. The ordinary security
# groups used by Intune, Defender, Cloud PC and Azure RBAC CAN be nested, so
# those sections expand transitively and flag which members are nested rather
# than direct. Entra role-assignable groups cannot contain nested groups, so
# Sections 3c/3d deliberately keep using direct membership.
# ================================================================================
function Get-GroupMemberWithNesting {
    param ([string]$GroupId)

    # Direct membership is fetched first so nested members can be distinguished.
    # If that call fails, members are reported without a nesting claim rather
    # than being wrongly labeled nested.
    $directIds   = @{}
    $directKnown = $false
    try {
        foreach ($dm in @(Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop)) {
            if ($dm.Id) { $directIds["$($dm.Id)"] = $true }
        }
        $directKnown = $true
    }
    catch {
        $script:unknownDepthGroups++
        [void]$script:unknownDepthGroupIds.Add($GroupId)
        Write-Warning "Could not read direct members of group $GroupId - nesting depth will not be reported: $_"
    }

    foreach ($tm in @(Get-MgGroupTransitiveMember -GroupId $GroupId -All -ErrorAction Stop)) {
        # Tri-state, not boolean. If the direct-member query failed, the depth is
        # genuinely UNKNOWN - reporting those members as 'Direct' would assert
        # something the script could not determine.
        $path = 'Unknown'
        if ($directKnown) {
            $path = $(if ($directIds.ContainsKey("$($tm.Id)")) { 'Direct' } else { 'Nested' })
        }

        [PSCustomObject]@{
            Member         = $tm
            MembershipPath = $path
        }
    }
}

# Membership entries that cannot hold an administrative role (devices, contacts,
# and anything else Graph returns from a transitive expansion) are not admins and
# must not be reported as such.
function Test-IsPrincipalMember {
    param ($Member)

    $t = "$($Member.AdditionalProperties.'@odata.type')" -replace '#microsoft\.graph\.',''
    return ($t -in @('user','group','servicePrincipal'))
}

function Get-MembershipViaLabel {
    param ([string]$Path, [string]$Prefix, [string]$GroupName)

    switch ($Path) {
        'Direct'  { return "$Prefix (via $GroupName)" }
        'Nested'  { return "$Prefix - NESTED (via $GroupName)" }
        default   { return "$Prefix - depth UNKNOWN, direct-member query failed (via $GroupName)" }
    }
}

function Test-ReportSelected {
    param ([string]$Name, [bool]$DefaultOn)
    if ($reportsSpecified) { return ($Reports -contains $Name) }
    return $DefaultOn
}

$runEntra     = Test-ReportSelected -Name 'Entra'          -DefaultOn $true
$runExchange  = Test-ReportSelected -Name 'ExchangeOnline' -DefaultOn (-not $SkipExchangeOnline)
$runPurview   = Test-ReportSelected -Name 'Purview'        -DefaultOn (-not $SkipPurview)
$runIntune    = Test-ReportSelected -Name 'Intune'         -DefaultOn (-not $SkipIntune)
$runDefender  = Test-ReportSelected -Name 'DefenderXDR'    -DefaultOn ([bool]$IncludeDefender)
$runCloudPC   = Test-ReportSelected -Name 'CloudPC'        -DefaultOn ([bool]$IncludeCloudPC)
$runAzureRbac = Test-ReportSelected -Name 'AzureRBAC'      -DefaultOn ([bool]$IncludeAzureRBAC)

# Reports that require a Microsoft Graph session. Azure RBAC is included
# because it resolves and expands assigned principals through Graph (which
# also detects soft-deleted objects). Exchange Online and Purview use their
# own sessions and need no Graph sign-in.
$needsGraph = ($runEntra -or $runIntune -or $runDefender -or $runCloudPC -or $runAzureRbac)

# ================================================================================
# Sovereign cloud endpoints. DoD / GCC High tenants live on .us domains with
# separate login and service URLs; every module must be pointed at the right
# cloud or it authenticates against the wrong endpoint. GCC uses commercial
# infrastructure for Graph/Az/EXO (only tenant config differs), so it maps to
# the commercial environment names. The GraphBaseUri here overrides the
# hardcoded graph.microsoft.com URLs used by the Intune/Defender/Cloud PC and
# deleted-items calls; the actual value is re-read from the live Graph context
# after connect so it always matches the SDK.
# ================================================================================
switch ($Cloud) {
    'Commercial' {
        $graphEnvName    = 'Global'
        $azEnvName       = 'AzureCloud'
        $exoEnvName      = $null            # default; parameter omitted
        $GraphBaseUri    = 'https://graph.microsoft.com'
        # Connect-IPPSSession defaults to the compliance endpoint, but
        # Connect-ExchangeOnline does NOT - without an explicit ConnectionUri it
        # connects to Exchange Online and Get-RoleGroup would return Exchange
        # role groups mislabeled as Purview. So the URI is always supplied.
        $complianceUri   = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
        $complianceAuth  = $null            # commercial default is correct
    }
    'GCC' {
        $graphEnvName    = 'Global'
        $azEnvName       = 'AzureCloud'
        $exoEnvName      = $null
        $GraphBaseUri    = 'https://graph.microsoft.com'
        $complianceUri   = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
        $complianceAuth  = $null            # GCC uses the commercial default
    }
    'GCCHigh' {
        $graphEnvName    = 'USGov'
        $azEnvName       = 'AzureUSGovernment'
        $exoEnvName      = 'O365USGovGCCHigh'
        $GraphBaseUri    = 'https://graph.microsoft.us'
        $complianceUri   = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
        $complianceAuth  = 'https://login.microsoftonline.us/organizations'
    }
    'DoD' {
        $graphEnvName    = 'USGovDoD'
        $azEnvName       = 'AzureUSGovernment'
        $exoEnvName      = 'O365USGovDoD'
        $GraphBaseUri    = 'https://dod-graph.microsoft.us'
        $complianceUri   = 'https://l5.ps.compliance.protection.office365.us/powershell-liveid/'
        $complianceAuth  = 'https://login.microsoftonline.us/organizations'
    }
}
# Explicit parameter values override the -Cloud defaults.
if ($GraphEnvironmentName)    { $graphEnvName = $GraphEnvironmentName }
if ($AzureEnvironmentName)    { $azEnvName    = $AzureEnvironmentName }
if ($PSBoundParameters.ContainsKey('ExchangeEnvironmentName') -and $ExchangeEnvironmentName) { $exoEnvName = $ExchangeEnvironmentName }
if ($GraphBaseUriOverride)    { $GraphBaseUri = $GraphBaseUriOverride.TrimEnd('/') }
if ($ComplianceConnectionUri) { $complianceUri = $ComplianceConnectionUri }
if ($ComplianceAuthUri)       { $complianceAuth = $ComplianceAuthUri }

Write-Host "[*] Target cloud: $Cloud (Graph env '$graphEnvName', Azure env '$azEnvName', Exchange env '$(if ($exoEnvName) { $exoEnvName } else { 'default' })')." -ForegroundColor Magenta

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
if ($exoModulePresent -and ($runExchange -or $runPurview)) {
    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not pre-load ExchangeOnlineManagement: $_"
        $exoModulePresent = $false
    }
}

# Surface pre-existing Exchange/Compliance sessions BEFORE any sign-in. This
# run's own disconnects are ConnectionId-targeted, but module behavior still
# closes legacy RPS sessions, and a crash between connect and cleanup shares
# process state. TRUE isolation is architectural: run this script in its own
# dedicated process, e.g.
#   powershell.exe -NoProfile -File .\Entra_PrivilegedRole_Report.ps1
if ($exoModulePresent -and ($runExchange -or $runPurview)) {
    $preexistingRest = @(Get-ExoConnectionIds)
    $preexistingRps  = @()
    try {
        $preexistingRps = @(Get-PSSession -ErrorAction SilentlyContinue | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' -and "$($_.State)" -eq 'Opened' })
    }
    catch { }

    if ($preexistingRest.Count -gt 0 -or $preexistingRps.Count -gt 0) {
        Write-Warning "This window already has $($preexistingRest.Count) Exchange/Compliance REST session(s) and $($preexistingRps.Count) legacy RPS session(s). The script disconnects only its own sessions, but for guaranteed isolation run it in a dedicated powershell.exe process."
    }
}

# Required Graph modules, imported explicitly after the limit fix above.
# Skipped entirely when no selected report needs Graph, and built from the
# SELECTED reports so an unrelated workload's module is never a hard dependency
# (for example -Reports AzureRBAC must not require the Intune module).
if ($needsGraph) {
$requiredGraphModules = @('Microsoft.Graph.Authentication')

# Anything that resolves or expands principals needs these.
if ($runEntra -or $runIntune -or $runDefender -or $runCloudPC -or $runAzureRbac) {
    $requiredGraphModules += @(
        'Microsoft.Graph.Groups',
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Applications'
    )
}
if ($runEntra)  { $requiredGraphModules += 'Microsoft.Graph.Identity.Governance' }
if ($runIntune) { $requiredGraphModules += 'Microsoft.Graph.DeviceManagement.Administration' }

$requiredGraphModules = @($requiredGraphModules | Select-Object -Unique)
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
}

# ================================================================================
# Connect to Microsoft Graph - only when a selected report needs it
# ================================================================================
$graphConnected = $false
$context        = $null

if ($needsGraph) {
    Write-Host "`n[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan

    # Scopes are requested per SELECTED report so the sign-in never asks for
    # more consent than the run actually needs. Over-requesting is a real
    # problem in tightly governed tenants.
    $requiredScopes = @()

    # Principal lookup / group expansion - needed by every Graph-backed report.
    $requiredScopes += @("Group.Read.All", "User.Read.All", "Directory.Read.All")

    if ($runEntra) {
        $requiredScopes += @(
            "RoleManagement.Read.All",
            "PrivilegedEligibilitySchedule.Read.AzureADGroup",
            "PrivilegedAssignmentSchedule.Read.AzureADGroup"
        )
    }
    if ($runIntune)   { $requiredScopes += "DeviceManagementRBAC.Read.All" }
    if ($runDefender) { $requiredScopes += "RoleManagement.Read.Defender" }
    if ($runCloudPC)  { $requiredScopes += "RoleManagement.Read.CloudPC" }

    $requiredScopes = @($requiredScopes | Select-Object -Unique)
    Write-Host "    Requesting $($requiredScopes.Count) scope(s) for the selected report(s)." -ForegroundColor Gray

    try {
        if ($graphEnvName -eq 'Global') {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
        }
        else {
            Connect-MgGraph -Scopes $requiredScopes -Environment $graphEnvName -NoWelcome -ErrorAction Stop
        }
        $context               = Get-MgContext
        $graphConnected        = $true
        $script:graphConnected = $true

        # Align the manual-URL base with the live context so the hardcoded
        # REST calls target the same cloud the SDK is using.
        if ($context -and $context.Environment) {
            $liveEnv = Get-MgEnvironment -Name $context.Environment -ErrorAction SilentlyContinue
            if ($liveEnv -and $liveEnv.GraphEndpoint) { $GraphBaseUri = $liveEnv.GraphEndpoint.TrimEnd('/') }
        }
        Write-Host "[+] Connected as: $($context.Account) | Tenant: $($context.TenantId) | Graph: $GraphBaseUri" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit 1
    }
}
else {
    Write-Host "`n[*] Microsoft Graph sign-in not required for the selected report(s) - skipping." -ForegroundColor Gray
}

# ================================================================================
# Fetch role definitions and build the role lookup
# ================================================================================
$allRoleDefinitions = @()
if ($runEntra) {
    Write-Host "`n[*] Fetching role definitions..." -ForegroundColor Cyan
    try {
        $allRoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to retrieve role definitions: $_"
        Invoke-ScriptCleanup
        exit 1
    }
}
else {
    Write-Host "`n[*] Skipping Part 1 - Entra directory roles (not selected)." -ForegroundColor Gray
}

# Lookup: role definition Id -> display name. Covers built-in AND custom roles.
$roleIdToName = @{}
foreach ($rd in $allRoleDefinitions) {
    $roleIdToName[$rd.Id] = $rd.DisplayName
}

# Optional narrowing via -RoleFilter. Default: ALL assigned roles are reported.
$filterActive    = ($RoleFilter.Count -gt 0)
$filteredRoleIds = [System.Collections.Generic.HashSet[string]]::new()

if ($runEntra) {
if ($filterActive) {
    foreach ($name in $RoleFilter) {
        $matched = @($allRoleDefinitions | Where-Object { $_.DisplayName -eq $name })
        if ($matched.Count -eq 0) {
            Write-Warning "RoleFilter entry '$name' matched no role definition (renamed or misspelled?) - it will be ignored."
        }
        foreach ($rd in $matched) { [void]$filteredRoleIds.Add($rd.Id) }
    }
    if ($filteredRoleIds.Count -eq 0) {
        # Every filter value failed to resolve. Continuing would exclude ALL
        # roles and emit an empty report that looks like a clean result, which
        # is the most dangerous possible outcome for an audit. Stop instead.
        Write-Error "None of the -RoleFilter values matched a role definition: $($RoleFilter -join ', '). Refusing to continue, because filtering would exclude every role and produce a misleadingly empty report. Correct the names or omit -RoleFilter to report all roles."
        Invoke-ScriptCleanup
        exit 1
    }
    Write-Host "[+] Role filter active: $($filteredRoleIds.Count) matching role definition(s)." -ForegroundColor Green
}
else {
    Write-Host "[+] No role filter - reporting ALL assigned directory roles (built-in + custom)." -ForegroundColor Green
}
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
$activeInstances = @()
if ($runEntra) {
    Write-Host "`n[*] Collecting ACTIVE role assignment instances (direct + PIM activated)..." -ForegroundColor Cyan
    try {
    $activeInstances = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty "principal" -ErrorAction Stop |
        Where-Object { Test-RoleInScope $_.RoleDefinitionId }
}
catch {
    Write-Warning "Failed to retrieve active role assignment instances: $_"
    $script:sectionErrors['Entra directory roles'] = $true
    Write-Warning "Active assignment data will be MISSING. Verify RoleManagement.Read.All and Entra ID P2 licensing."
    }
}

# Track currently-activated (role|principal|scope) combos so Section 2 can
# suppress the duplicate 'eligible' rows for the same people.
$activatedKeys = [System.Collections.Generic.HashSet[string]]::new()

foreach ($a in $activeInstances) {
    $principalType = $a.Principal.AdditionalProperties.'@odata.type' -replace '#microsoft\.graph\.',''
    $principal     = Resolve-Principal -PrincipalId $a.PrincipalId -PrincipalType $principalType
    $isActivated   = ($a.AssignmentType -eq 'Activated')
    $scope         = Get-ScopeInfo $a

    if ($isActivated) {
        [void]$activatedKeys.Add("$($a.RoleDefinitionId)|$($a.PrincipalId)|$($scope.ScopeKey)")
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
        AssignmentScope  = $scope.Display
        ScopeType        = $scope.ScopeType
        StartDateTime    = $a.StartDateTime
        EndDateTime      = $(if ($a.EndDateTime) { $a.EndDateTime } else { 'Permanent (no expiry)' })
    }
    Add-ReportRow @row
}

if ($runEntra) {
    $directCount    = @($report | Where-Object { $_.AssignmentSource -eq 'Direct Active' }).Count
    $activatedCount = @($report | Where-Object { $_.AssignmentSource -eq 'PIM Active (Activated)' }).Count
    Write-Host "[+] Active instances collected: $directCount assigned, $activatedCount PIM-activated." -ForegroundColor Green
}

# ================================================================================
# SECTION 2 - PIM ELIGIBLE role assignments
# ================================================================================
$eligibleInstances = @()
if ($runEntra) {
    Write-Host "`n[*] Collecting PIM ELIGIBLE role assignment instances..." -ForegroundColor Cyan
    try {
    $eligibleInstances = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty "principal" -ErrorAction Stop |
        Where-Object { Test-RoleInScope $_.RoleDefinitionId }
}
catch {
    Write-Warning "Failed to retrieve role eligibility instances: $_"
    $script:sectionErrors['Entra directory roles'] = $true
    Write-Warning "Eligible assignment data will be MISSING. Verify RoleManagement.Read.All and Entra ID P2 licensing."
    }
}

$suppressedEligible = 0
foreach ($a in $eligibleInstances) {
    $scope = Get-ScopeInfo $a

    # A principal whose eligibility is currently ACTIVATED for this role and
    # scope is already reported under 'PIM Active (Activated)' - skip the
    # duplicate eligible row (activation implies eligibility). The key includes
    # the normalized scope so two assignments differing only by app scope are
    # not treated as the same thing.
    if ($activatedKeys.Contains("$($a.RoleDefinitionId)|$($a.PrincipalId)|$($scope.ScopeKey)")) {
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
        AssignmentScope  = $scope.Display
        ScopeType        = $scope.ScopeType
        StartDateTime    = $a.StartDateTime
        EndDateTime      = $(if ($a.EndDateTime) { $a.EndDateTime } else { 'No expiry' })
    }
    Add-ReportRow @row
}

if ($runEntra) {
    $eligibleCount = @($report | Where-Object { $_.AssignmentSource -eq 'PIM Eligible' }).Count
    Write-Host "[+] PIM eligible instances collected: $eligibleCount ($suppressedEligible currently activated - reported under PIM Active)." -ForegroundColor Green
}

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
if ($runEntra) {
Write-Host "`n[*] Collecting group-based access (PIM for Groups + standing members/owners)..." -ForegroundColor Cyan

$roleAssignedGroupIds = @(
    $report |
        Where-Object { $_.PrincipalType -eq 'Group' } |
        Select-Object -ExpandProperty PrincipalId -Unique
)

Write-Host "    Found $($roleAssignedGroupIds.Count) group(s) holding directory roles." -ForegroundColor Yellow

foreach ($groupId in $roleAssignedGroupIds) {

    # One context per distinct (role, source, state, scope) the group holds.
    # AssignmentSource is in the key so a permanent active assignment and a
    # currently-activated PIM assignment for the same role and scope stay
    # separate grants rather than collapsing into one. Grouping on
    # RoleId alone collapsed genuinely different grants - the same role held both
    # active and eligible, or at two different scopes - into a single context, so
    # member rows inherited the wrong scope or state. Each distinct grant is a
    # distinct access path and gets its own set of member rows.
    $groupRoleContexts = @(
        $report |
            Where-Object { $_.PrincipalId -eq $groupId -and $_.PrincipalType -eq 'Group' } |
            Group-Object -Property RoleId, AssignmentSource, RoleHeld, ScopeType, AssignmentScope |
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
        $script:sectionErrors['Entra directory roles'] = $true
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
                ScopeType        = $ctx.ScopeType
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
        $script:sectionErrors['Entra directory roles'] = $true
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
                ScopeType        = $ctx.ScopeType
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

    # Direct membership is correct AND complete here: a group must be
    # role-assignable to hold a directory role, and role-assignable groups
    # cannot contain nested groups. Workload sections use
    # Get-GroupMemberWithNesting instead, because their groups can be nested.
    $members = @()
    try {
        $members = Get-MgGroupMember -GroupId $groupId -All -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not enumerate members of '$groupDisplayName' ($groupId): $_"
        $script:sectionErrors['Entra directory roles'] = $true
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
                ScopeType        = $ctx.ScopeType
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
        $script:sectionErrors['Entra directory roles'] = $true
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
                ScopeType        = $ctx.ScopeType
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
}

# ================================================================================
# PART 1 OUTPUT - Entra directory role report
# ================================================================================
if ($runEntra) {
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
    try {
        $report |
            Sort-Object RoleName, AssignmentSource, PrincipalDisplayName |
            ConvertTo-SafeCsvRow |
            Export-Csv -Path $entraOutputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

        Write-Host "  Output file: $entraOutputPath" -ForegroundColor Cyan
        Write-Host ""
    }
    catch {
        $script:exportFailures['Entra directory roles'] = "$($_.Exception.Message)"
        Write-Error "FAILED to export the Entra report to '$entraOutputPath': $($_.Exception.Message). The data was collected but NOT written."
    }
}
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
#       (Connect-ExchangeOnline to the Compliance endpoint, separate sign-in)
#   W3. Intune - RBAC role assignments via Graph v1.0; each admin group is
#       expanded to its members        (DeviceManagementRBAC.Read.All)
#   W4. Defender XDR - unified RBAC via Graph beta (OPT-IN: -IncludeDefender)
#   W5. Windows 365 / Cloud PC - RBAC via Graph beta (OPT-IN: -IncludeCloudPC)
#   W6. Azure RBAC - subscription role assignments via the Az modules
#                                      (OPT-IN: -IncludeAzureRBAC)
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
        [string]$ResolutionStatus = "N/A",
        [string]$Scope = "N/A",
        [string]$AccountEnabled = "N/A",
        [string]$IsExclusiveScope = "N/A",
        [string]$AssignmentEnabled = "N/A"
    )

    $workloadReport.Add([PSCustomObject]@{
        Workload          = $Workload
        Role              = $Role
        AssignmentName    = $AssignmentName
        MemberDisplayName = $MemberDisplayName
        MemberIdentity    = $MemberIdentity
        MemberType        = $MemberType
        AssignedVia       = $AssignedVia
        ResolutionStatus  = $ResolutionStatus
        Scope             = $Scope
        IsExclusiveScope  = $IsExclusiveScope
        AssignmentEnabled = $AssignmentEnabled
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

    if ($Member.UserPrincipalName) { return "$($Member.UserPrincipalName)" }
    if ($Member.PrimarySmtpAddress) { return "$($Member.PrimarySmtpAddress)" }
    if ($Member.WindowsEmailAddress) { return "$($Member.WindowsEmailAddress)" }
    if ($Member.WindowsLiveID) { return "$($Member.WindowsLiveID)" }
    if ($Member.ExternalDirectoryObjectId) { return "ObjectId: $($Member.ExternalDirectoryObjectId)" }
    if ($Member.Name) { return "$($Member.Name)" }
    return "N/A"
}

# Formats every populated scope facet of an Exchange management role assignment.
# Exchange scope is multi-dimensional; reporting only RecipientWriteScope made
# materially different assignments look identical. Exclusive scopes matter most:
# they restrict which OTHER admins can modify the in-scope objects and override
# any custom/OU/predefined scope. Used by BOTH the configuration pass and the
# effective-user pass so the two never diverge again.
function Get-ExoAssignmentScope {
    param ($Assignment)

    $scopeFacets = [System.Collections.Generic.List[string]]::new()
    $isExclusive = $false

    foreach ($facet in @(
        @{ Label = 'RecipientWrite';    Value = $Assignment.RecipientWriteScope },
        @{ Label = 'ConfigWrite';       Value = $Assignment.ConfigWriteScope },
        @{ Label = 'CustomRecipient';   Value = $Assignment.CustomRecipientWriteScope },
        @{ Label = 'CustomConfig';      Value = $Assignment.CustomConfigWriteScope },
        @{ Label = 'RecipientOU';       Value = $Assignment.RecipientOrganizationalUnitScope },
        @{ Label = 'RecipientAdminUnit';Value = $Assignment.RecipientAdministrativeUnitScope },
        @{ Label = 'RecipientGroup';    Value = $Assignment.RecipientGroupScope }
    )) {
        $v = "$($facet.Value)"
        if ($v) { $scopeFacets.Add("$($facet.Label)=$v") }
    }

    foreach ($exFacet in @(
        @{ Label = 'EXCLUSIVE-Recipient'; Value = $Assignment.ExclusiveRecipientWriteScope },
        @{ Label = 'EXCLUSIVE-Config';    Value = $Assignment.ExclusiveConfigWriteScope }
    )) {
        $v = "$($exFacet.Value)"
        if ($v) {
            $scopeFacets.Add("$($exFacet.Label)=$v")
            $isExclusive = $true
        }
    }

    return [PSCustomObject]@{
        Display     = $(if ($scopeFacets.Count -gt 0) { $scopeFacets -join '; ' } else { 'Implicit role scope' })
        IsExclusive = $isExclusive
    }
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
    $baseUri       = "$GraphBaseUri/beta/roleManagement/$Provider"

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
                    MemberIdentity    = $principal.Identity
                    MemberType        = $principal.PrincipalType
                    AssignedVia       = 'Direct Role Assignment'
                    ResolutionStatus  = $principal.ResolutionStatus
                    Scope             = $scopeDesc
                    AccountEnabled    = "$($principal.AccountEnabled)"
                }
                Add-WorkloadRow @row

                # Assigned groups get expanded to members, mirroring the Intune section.
                if ($principal.PrincipalType -eq 'Group' -and $principal.ResolutionStatus -eq 'Found') {
                    $gMembers = @()
                    try {
                        $gMembers = @(Get-GroupMemberWithNesting -GroupId "$prinId")
                    }
                    catch {
                        Write-Warning "Could not expand group '$($principal.DisplayName)' ($prinId) for $Workload : $_"
                        $script:sectionErrors[$Workload] = $true
                    }

                    foreach ($entry in $gMembers) {
                        $gm = $entry.Member
                        if (-not (Test-IsPrincipalMember -Member $gm)) { continue }

                        $gmType     = $gm.AdditionalProperties.'@odata.type' -replace '#microsoft\.graph\.',''
                        $gPrincipal = Resolve-Principal -PrincipalId $gm.Id -PrincipalType $gmType
                        $viaLabel   = Get-MembershipViaLabel -Path $entry.MembershipPath -Prefix 'Group Member' -GroupName "$($principal.DisplayName)"

                        $row = @{
                            Workload          = $Workload
                            Role              = $defName
                            AssignmentName    = $asgName
                            MemberDisplayName = $gPrincipal.DisplayName
                            MemberIdentity    = $gPrincipal.Identity
                            MemberType        = $gPrincipal.PrincipalType
                            AssignedVia       = $viaLabel
                            ResolutionStatus  = $gPrincipal.ResolutionStatus
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

if (-not $exoModulePresent -and ($runExchange -or $runPurview)) {
    Write-Warning "ExchangeOnlineManagement module not found - the Exchange Online and Purview sections CANNOT run."
    Write-Warning "Run 'Install-Module ExchangeOnlineManagement' and rerun to include them."
    # A selected report that cannot run because of a missing dependency is a
    # FAILURE, not an empty result. Registering it here stops the run status
    # from reporting 'No data' for a query that never executed.
    if ($runExchange) { $script:sectionErrors['Exchange Online'] = $true }
    if ($runPurview)  { $script:sectionErrors['Purview (Security & Compliance)'] = $true }
}

# --------------------------------------------------------------------------------
# W1 - Exchange Online role groups and direct role assignments
# --------------------------------------------------------------------------------
if (-not $runExchange) {
    Write-Host "`n[*] Skipping Exchange Online (not selected)." -ForegroundColor Gray
}
elseif ($exoModulePresent) {
    Write-Host "`n[*] Collecting Exchange Online role groups (a separate sign-in may appear)..." -ForegroundColor Cyan
    $exoConnected = $false
    try {
        $exoConnectParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($context -and $context.Account) { $exoConnectParams['UserPrincipalName'] = "$($context.Account)" }
        if ($exoEnvName) { $exoConnectParams['ExchangeEnvironmentName'] = $exoEnvName }
        $w1ConnIds  = @()
        $preConnIds = Get-ExoConnectionIds
        Connect-ExchangeOnline @exoConnectParams
        $exoConnected = $true
        $w1ConnIds    = @(Get-ExoConnectionIds | Where-Object { $_ -notin $preConnIds })
        $script:exoRunConnectionIds += $w1ConnIds

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
                $script:sectionErrors['Exchange Online'] = $true
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

        # Roles assigned outside of role groups. Three assignee types are queried:
        # querying only 'User' silently missed roles assigned directly to a
        # universal security group or a foreign security principal, which no
        # other pass covers (RoleGroup assignees are covered by Get-RoleGroup
        # above). Both regular and DELEGATING assignments are collected -
        # a delegating assignment grants the right to hand the role to someone
        # else, which is privilege worth auditing in its own right.
        $exoRecipientCache = @{}

        foreach ($assigneeType in @('User', 'SecurityGroup', 'ForeignSecurityPrincipal')) {
            foreach ($delegating in @($false, $true)) {

                $directAssignments = @()
                try {
                    $directAssignments = @(Get-ManagementRoleAssignment -RoleAssigneeType $assigneeType -Delegating:$delegating -ErrorAction Stop)
                }
                catch {
                    Write-Warning "Could not enumerate Exchange role assignments (assignee type '$assigneeType', delegating=$delegating): $_"
                    $script:sectionErrors['Exchange Online'] = $true
                    continue
                }

                foreach ($ra in $directAssignments) {
                    $assigneeName = "$($ra.RoleAssigneeName)"

                    # Resolve only by Exchange's RoleAssignee value and only with
                    # the cmdlet appropriate to the declared assignee type. A
                    # display-name retry is intentionally prohibited: names and
                    # aliases can be reused, so a fallback can attach a different
                    # recipient's identity to this role assignment.
                    #
                    # ForeignSecurityPrincipal is not a mail-recipient type. It is
                    # therefore not sent to Get-Recipient. The raw assignment
                    # identity is preserved and explicitly marked unresolved
                    # instead of guessing at a similarly named recipient.
                    $assigneeLookup           = "$($ra.RoleAssignee)"
                    $assigneeIdentity         = $null
                    $assigneeResolutionStatus = 'N/A'

                    if ($assigneeType -eq 'ForeignSecurityPrincipal') {
                        $script:exoForeignPrincipalRows++
                        if ($assigneeLookup) {
                            $assigneeIdentity = "RoleAssignee: $assigneeLookup"
                        }
                        elseif ($assigneeName) {
                            $assigneeIdentity = "Name: $assigneeName"
                        }
                        else {
                            $assigneeIdentity = 'Foreign security principal identity unavailable'
                        }
                        $assigneeResolutionStatus = 'RawForeignPrincipal'
                    }
                    elseif ($assigneeLookup) {
                        $cacheKey = "$assigneeType|$assigneeLookup"
                        if ($exoRecipientCache.ContainsKey($cacheKey)) {
                            $assigneeIdentity         = $exoRecipientCache[$cacheKey]
                            $assigneeResolutionStatus = 'Found'
                        }
                        else {
                            try {
                                $resolvedObj = $null
                                switch ($assigneeType) {
                                    'User' {
                                        $resolvedObj = Get-User -Identity $assigneeLookup -ErrorAction Stop
                                    }
                                    'SecurityGroup' {
                                        $resolvedObj = Get-Group -Identity $assigneeLookup -ErrorAction Stop
                                    }
                                    default {
                                        throw "Unsupported Exchange assignee type '$assigneeType'."
                                    }
                                }

                                $assigneeIdentity = Get-RecipientIdentity -Member $resolvedObj
                                $exoRecipientCache[$cacheKey] = $assigneeIdentity
                                $assigneeResolutionStatus = 'Found'
                            }
                            catch {
                                # Failures are deliberately NOT cached. The raw
                                # stable assignment value is retained so the row
                                # cannot be misidentified through a display name.
                                $script:exoAssigneeLookupFailures++
                                $assigneeIdentity = "RoleAssignee: $assigneeLookup (typed lookup failed; not cached)"
                                $assigneeResolutionStatus = 'Unresolved'
                            }
                        }
                    }
                    else {
                        $script:exoAssigneeLookupFailures++
                        $assigneeIdentity = $(if ($assigneeName) {
                            "Name: $assigneeName (no stable RoleAssignee value; display-name lookup intentionally skipped)"
                        } else {
                            'No stable Exchange assignee identity was returned'
                        })
                        $assigneeResolutionStatus = 'Unresolved'
                    }

                    $exoScope = Get-ExoAssignmentScope -Assignment $ra

                    # An assignment can exist but be DISABLED, in which case it
                    # grants nothing. Reporting it without that state would show
                    # inactive configuration as live privilege. This is a
                    # configuration report, so disabled rows are kept and marked.
                    # Type-safe: a string 'False' cast with [bool] evaluates to
                    # $true in PowerShell, so the property is only trusted when
                    # it is an actual boolean; a string is compared textually.
                    $isEnabled = $true
                    if ($ra.Enabled -is [bool]) { $isEnabled = $ra.Enabled }
                    elseif ("$($ra.Enabled)" -ieq 'False') { $isEnabled = $false }

                    $assignedVia = $(if ($delegating) { 'Delegating Role Assignment (can grant this role to others)' } else { 'Direct Role Assignment' })
                    if (-not $isEnabled) { $assignedVia = "DISABLED - $assignedVia (grants no access)" }

                    $row = @{
                        Workload          = 'Exchange Online'
                        Role              = "$($ra.Role)"
                        AssignmentName    = "$($ra.Name)"
                        MemberDisplayName = $(if ($assigneeName) { $assigneeName } else { 'Unknown assignee' })
                        MemberIdentity    = $assigneeIdentity
                        MemberType        = $assigneeType
                        AssignedVia       = $assignedVia
                        ResolutionStatus  = $assigneeResolutionStatus
                        Scope             = $exoScope.Display
                        IsExclusiveScope  = $(if ($exoScope.IsExclusive) { 'True' } else { 'False' })
                        AssignmentEnabled = $(if ($isEnabled) { 'True' } else { 'False' })
                    }
                    Add-WorkloadRow @row
                }
            }
        }

        # #5 - EFFECTIVE users. Everything above describes CONFIGURATION and does
        # not identify every effective administrator: a role assigned to a
        # universal security group, or a role group that contains a group, grants
        # access to users this script never enumerated. -GetEffectiveUsers has
        # Exchange perform that expansion itself, which is authoritative.
        # Scoped to SecurityGroup, RoleGroup, and LinkedRoleGroup assignees:
        # those are the paths where group nesting hides effective admins.
        # LinkedRoleGroup can yield Exchange's unenumerable
        # 'All Linked Group Members' placeholder. 'User' assignees are
        # excluded because their effective user is themselves (already reported
        # by the direct pass), and 'RoleAssignmentPolicy' is excluded because
        # those are end-user self-management roles (MyBaseOptions and friends)
        # applied to EVERY mailbox - expanding them would add a row per mailbox
        # per role and drown the report in non-administrative noise.
        #
        # Regular and DELEGATING assignments are queried separately: a
        # delegating-only assignee can GRANT the role but does not hold its
        # operational permissions, and blending the two would make a
        # delegation-only user look like a working administrator.
        foreach ($effType in @('SecurityGroup', 'RoleGroup', 'LinkedRoleGroup')) {
            foreach ($effDelegating in @($false, $true)) {

                $effBatch = @()
                try {
                    $effBatch = @(Get-ManagementRoleAssignment -GetEffectiveUsers -RoleAssigneeType $effType -Delegating:$effDelegating -ErrorAction Stop)
                }
                catch {
                    Write-Warning "Could not enumerate Exchange EFFECTIVE users (assignee type '$effType', delegating=$effDelegating): $_"
                    Write-Warning "Rows for that path describe configuration only - NOT full effective access."
                    $script:sectionErrors['Exchange Online'] = $true
                    continue
                }

                foreach ($ea in $effBatch) {
                    $eaEnabled = $true
                    if ($ea.Enabled -is [bool]) { $eaEnabled = $ea.Enabled }
                    elseif ("$($ea.Enabled)" -ieq 'False') { $eaEnabled = $false }

                    $eaUser = "$($ea.EffectiveUserName)"
                    if (-not $eaUser) { $eaUser = "$($ea.User)" }
                    if (-not $eaUser) { $eaUser = "$($ea.RoleAssigneeName)" }

                    # Linked (foreign) role groups cannot be enumerated here:
                    # Exchange returns the literal placeholder 'All Linked Group
                    # Members' instead of user identities. That row represents an
                    # unenumerable population and must not pose as a named user.
                    $isLinkedPlaceholder = ($eaUser -ieq 'All Linked Group Members')

                    $eaVia = $(if ($effDelegating) {
                        "Effective User of DELEGATING assignment - can GRANT this role; operational rights are not implied (expanded by Exchange from assignee '$($ea.RoleAssigneeName)' of type '$($ea.RoleAssigneeType)')"
                    } else {
                        "Effective User (expanded by Exchange from assignee '$($ea.RoleAssigneeName)' of type '$($ea.RoleAssigneeType)')"
                    })
                    if ($isLinkedPlaceholder) {
                        $script:linkedGroupPlaceholders++
                        $eaVia = "Linked role group placeholder - represents ALL members of a linked/foreign group that Exchange cannot enumerate here (assignee '$($ea.RoleAssigneeName)')"
                    }

                    $eaScope = Get-ExoAssignmentScope -Assignment $ea

                    $row = @{
                        Workload          = 'Exchange Online'
                        Role              = "$($ea.Role)"
                        AssignmentName    = "$($ea.Name)"
                        MemberDisplayName = $(if ($eaUser) { $eaUser } else { 'Unknown effective user' })
                        MemberIdentity    = $(if ($isLinkedPlaceholder) { 'N/A (unenumerable linked group)' } elseif ($ea.User) { "$($ea.User)" } else { 'N/A' })
                        MemberType        = $(if ($isLinkedPlaceholder) { 'LinkedGroupPlaceholder' } else { 'EffectiveUser' })
                        AssignedVia       = $eaVia
                        Scope             = $eaScope.Display
                        IsExclusiveScope  = $(if ($eaScope.IsExclusive) { 'True' } else { 'False' })
                        AssignmentEnabled = $(if ($eaEnabled) { 'True' } else { 'False' })
                    }
                    Add-WorkloadRow @row
                }
            }
        }
    }
    catch {
        $failMsg = "$_"
        Write-Warning "Exchange Online collection failed: $failMsg"
        $script:sectionErrors['Exchange Online'] = $true
        if ($failMsg -match 'Microsoft\.Identity\.Client|Could not load file or assembly') {
            $exoVer = "$((Get-Module -Name ExchangeOnlineManagement | Select-Object -First 1).Version)"
            $idVer  = "$((([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'Microsoft.Identity.Client' } | Select-Object -First 1).GetName()).Version)"
            Write-Warning "Assembly conflict detected. PowerShell $($PSVersionTable.PSVersion); ExchangeOnlineManagement $exoVer; loaded Microsoft.Identity.Client $idVer. A session cannot be repaired once the wrong assembly is loaded - start a FRESH PowerShell window and rerun. If it persists, run 'Update-Module ExchangeOnlineManagement' and compare the two versions above."
        }
    }
    finally {
        if ($exoConnected) {
            $disconnectSucceeded = Disconnect-ExoRunSessions -ConnectionIds $w1ConnIds -SessionWasCreated
            if ($disconnectSucceeded) {
                $script:exoRunConnectionIds = @(
                    $script:exoRunConnectionIds |
                        Where-Object { $_ -notin $w1ConnIds }
                )
            }
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
if (-not $runPurview) {
    Write-Host "`n[*] Skipping Purview (not selected)." -ForegroundColor Gray
}
elseif ($exoModulePresent) {
    Write-Host "`n[*] Collecting Purview role groups (a separate sign-in may appear)..." -ForegroundColor Cyan
    $ippsConnected = $false
    try {
        # Reach Security & Compliance (Purview) with Connect-ExchangeOnline
        # pointed at the Compliance endpoint. In sovereign clouds that means the
        # cloud-specific Compliance ConnectionUri + Entra auth URI (resolved from
        # -Cloud, overridable via -ComplianceConnectionUri / -ComplianceAuthUri).
        # The compliance ConnectionUri is supplied for EVERY cloud: without it,
        # Connect-ExchangeOnline targets Exchange Online, not Security &
        # Compliance. Runs in its own connect/collect/disconnect window, and the
        # session type is VERIFIED below via IsEopSession before any query runs.
        #
        # DELIBERATE CHOICE - DO NOT "FIX" THIS TO Connect-IPPSSession.
        # Microsoft documents Connect-IPPSSession for Security & Compliance, and
        # automated reviews flag this line as a defect for that reason. It is not:
        # Connect-ExchangeOnline reaches Compliance when given the Compliance
        # ConnectionUri, every parameter passed below is a documented
        # Connect-ExchangeOnline parameter, and this path is verified working in
        # the target DoD tenant. Connect-IPPSSession remains the documented
        # fallback if a future module version stops honoring ConnectionUri here.
        # Verification is MANDATORY: when the created session cannot be proven
        # to be Security & Compliance (IsEopSession), Purview fails closed
        # instead of risking Exchange data exported under a Purview label.
        $ippsConnectParams = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($context -and $context.Account) { $ippsConnectParams['UserPrincipalName'] = "$($context.Account)" }
        if ($complianceUri) {
            $ippsConnectParams['ConnectionUri'] = $complianceUri
            if ($complianceAuth) { $ippsConnectParams['AzureADAuthorizationEndpointUri'] = $complianceAuth }
        }
        $w2ConnIds  = @()
        $preConnIds = Get-ExoConnectionIds
        Connect-ExchangeOnline @ippsConnectParams
        $ippsConnected = $true
        $w2ConnIds     = @(Get-ExoConnectionIds | Where-Object { $_ -notin $preConnIds })
        $script:exoRunConnectionIds += $w2ConnIds

        # Trust-but-verify: Get-ConnectionInformation reports IsEopSession as
        # True only for Security & Compliance sessions (False for Exchange
        # Online). If the endpoint produced a plain Exchange session, querying
        # role groups would return EXCHANGE role groups mislabeled as Purview -
        # so a wrong session type is a hard failure, not a silent mislabel.
        if ($w2ConnIds.Count -gt 0) {
            $w2Info = @()
            try { $w2Info = @(Get-ConnectionInformation -ErrorAction Stop | Where-Object { "$($_.ConnectionId)" -in $w2ConnIds }) } catch { }

            $eopVerified = $false
            foreach ($ci in $w2Info) { if ($ci.IsEopSession) { $eopVerified = $true } }

            if ($w2Info.Count -gt 0 -and -not $eopVerified) {
                throw "The connection created for Purview is NOT a Security & Compliance session (IsEopSession=False). Endpoint '$complianceUri' produced an Exchange Online session; refusing to collect Exchange data under a Purview label. Verify -ComplianceConnectionUri."
            }
            if ($w2Info.Count -eq 0) {
                throw "Purview session type could not be verified (no connection information returned for the new connection). Refusing to query: an unproven session risks Exchange role groups being exported under a Purview label. Update ExchangeOnlineManagement and rerun, or use -SkipPurview."
            }
        }
        else {
            throw "Purview session type cannot be verified on this module version (connection tracking requires ExchangeOnlineManagement 3.2.0+). Refusing to query rather than risk mislabeling Exchange data as Purview. Update the module and rerun, or use -SkipPurview."
        }

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
                $script:sectionErrors['Purview (Security & Compliance)'] = $true
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
        $script:sectionErrors['Purview (Security & Compliance)'] = $true
        if ($failMsg -match 'Microsoft\.Identity\.Client|Could not load file or assembly') {
            $exoVer = "$((Get-Module -Name ExchangeOnlineManagement | Select-Object -First 1).Version)"
            $idVer  = "$((([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'Microsoft.Identity.Client' } | Select-Object -First 1).GetName()).Version)"
            Write-Warning "Assembly conflict detected. PowerShell $($PSVersionTable.PSVersion); ExchangeOnlineManagement $exoVer; loaded Microsoft.Identity.Client $idVer. A session cannot be repaired once the wrong assembly is loaded - start a FRESH PowerShell window and rerun. If it persists, run 'Update-Module ExchangeOnlineManagement' and compare the two versions above."
        }
    }
    finally {
        if ($ippsConnected) {
            $disconnectSucceeded = Disconnect-ExoRunSessions -ConnectionIds $w2ConnIds -SessionWasCreated
            if ($disconnectSucceeded) {
                $script:exoRunConnectionIds = @(
                    $script:exoRunConnectionIds |
                        Where-Object { $_ -notin $w2ConnIds }
                )
            }
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
if (-not $runIntune) {
    Write-Host "`n[*] Skipping Intune (not selected)." -ForegroundColor Gray
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

                # Scope handling. The v1.0 assignment object has no scopeType
                # property (beta only), and assignments scoped to the built-in
                # 'All Devices' / 'All Users' options can carry placeholder IDs
                # in ResourceScopes that are NOT real Entra groups. A scope ID
                # that fails group lookup is therefore labeled as a built-in
                # scope or deleted group - it never refers to an admin account.
                $scopeParts   = [System.Collections.Generic.List[string]]::new()
                $scopeTypeVal = "$($asg.ScopeType)"
                if (-not $scopeTypeVal -and $asg.AdditionalProperties -and $asg.AdditionalProperties.ContainsKey('scopeType')) {
                    $scopeTypeVal = "$($asg.AdditionalProperties['scopeType'])"
                }
                switch ($scopeTypeVal) {
                    'allDevices'                 { $scopeParts.Add('All Devices') }
                    'allLicensedUsers'           { $scopeParts.Add('All Users') }
                    'allDevicesAndLicensedUsers' { $scopeParts.Add('All Devices and All Users') }
                }
                if (-not $scopeTypeVal -or $scopeTypeVal -eq 'resourceScope') {
                    foreach ($rs in @($asg.ResourceScopes)) {
                        if ("$rs" -ieq 'AllDevices') { $scopeParts.Add('All Devices'); continue }
                        if ("$rs" -ieq 'AllLicensedUsers') { $scopeParts.Add('All Users'); continue }
                        if ("$rs" -match '^[0-9a-fA-F\-]{36}$') {
                            $scopeGroup = Resolve-Principal -PrincipalId "$rs" -PrincipalType "Group"
                            switch ($scopeGroup.ResolutionStatus) {
                                'Found'    { $scopeParts.Add($scopeGroup.DisplayName) }
                                'Deleted'  { $scopeParts.Add($scopeGroup.DisplayName) }
                                'NotFound' { $scopeParts.Add("Unresolved resource scope - built-in scope or deleted object ($rs)") }
                                default    {
                                    # Lookup did not succeed, so nothing is established
                                    # about this scope. Report the status, not a guess.
                                    $scopeParts.Add("Unresolved resource scope - lookup $($scopeGroup.ResolutionStatus) ($rs)")
                                }
                            }
                        }
                        elseif ($rs) {
                            $scopeParts.Add("$rs")
                        }
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
                        MemberIdentity    = $groupInfo.Identity
                        MemberType        = 'Group'
                        AssignedVia       = 'Intune Assignment Group'
                        ResolutionStatus  = $groupInfo.ResolutionStatus
                        Scope             = $scopeDesc
                    }
                    Add-WorkloadRow @row

                    # Only call an assignment stale when the group's absence is
                    # CONFIRMED. A denied or throttled lookup proves nothing, and
                    # must not produce a cleanup recommendation.
                    if ($groupInfo.ResolutionStatus -in @('Deleted','NotFound')) {
                        Write-Warning "Intune role '$($def.DisplayName)' assignment '$($asg.DisplayName)' references an admin group that no longer exists ($gid) - stale assignment worth cleaning up."
                        continue
                    }
                    if ($groupInfo.ResolutionStatus -ne 'Found') {
                        Write-Warning "Intune role '$($def.DisplayName)' assignment '$($asg.DisplayName)': admin group $gid could not be resolved ($($groupInfo.ResolutionStatus)). Membership is NOT expanded and no conclusion is drawn about the group existing."
                        continue
                    }

                    # Expand the admin group to individual members, including any
                    # nested through other groups.
                    $gMembers = @()
                    try {
                        $gMembers = @(Get-GroupMemberWithNesting -GroupId "$gid")
                    }
                    catch {
                        Write-Warning "Could not expand Intune admin group '$($groupInfo.DisplayName)' ($gid): $_"
                        $script:sectionErrors['Intune'] = $true
                    }

                    foreach ($entry in $gMembers) {
                        $gm = $entry.Member
                        if (-not (Test-IsPrincipalMember -Member $gm)) { continue }

                        $gmType = $gm.AdditionalProperties.'@odata.type' -replace '#microsoft\.graph\.',''

                        # Intune console access via this model applies to USERS.
                        # Service principals reached through group membership are
                        # not Intune administrators and are skipped; intermediate
                        # groups are kept as access-path records, not as admins.
                        # Nested users are marked CONDITIONAL because Intune
                        # licensing requirements can determine whether the role is
                        # effective for them - this script does not verify
                        # licensing.
                        if ($gmType -ieq 'servicePrincipal') { continue }

                        $principal = Resolve-Principal -PrincipalId $gm.Id -PrincipalType $gmType

                        if ($gmType -ieq 'group') {
                            $viaLabel = "Access Path - nested group inside '$($groupInfo.DisplayName)' (its members inherit through this group; not itself an administrator)"
                        }
                        else {
                            $viaLabel = switch ($entry.MembershipPath) {
                                'Direct' { "Intune Group Member (via $($groupInfo.DisplayName))" }
                                'Nested' { "Intune Group Member - NESTED, CONDITIONAL: effective only if Intune licensing requirements are met (via $($groupInfo.DisplayName))" }
                                default  { "Intune Group Member - depth UNKNOWN (direct-member query failed); if nested, effectiveness depends on Intune licensing (via $($groupInfo.DisplayName))" }
                            }
                        }

                        $row = @{
                            Workload          = 'Intune'
                            Role              = "$($def.displayName)"
                            AssignmentName    = "$($asg.displayName)"
                            MemberDisplayName = $principal.DisplayName
                            MemberIdentity    = $principal.Identity
                            MemberType        = $principal.PrincipalType
                            AssignedVia       = $viaLabel
                            ResolutionStatus  = $principal.ResolutionStatus
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
        $script:sectionErrors['Intune'] = $true
        Write-Warning "Verify the DeviceManagementRBAC.Read.All scope was consented and the tenant has Intune licensing."
    }
}

# --------------------------------------------------------------------------------
# W4 - Microsoft Defender XDR unified RBAC (Graph beta)
# Only returns data where Defender XDR unified RBAC is active in the tenant.
# --------------------------------------------------------------------------------
if (-not $runDefender) {
    Write-Host "`n[*] Skipping Defender XDR (not selected - use -IncludeDefender or -Reports DefenderXDR)." -ForegroundColor Gray
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
        $script:sectionErrors['Defender XDR'] = $true
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
if (-not $runCloudPC) {
    Write-Host "`n[*] Skipping Windows 365 / Cloud PC (not selected - use -IncludeCloudPC or -Reports CloudPC)." -ForegroundColor Gray
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
        $script:sectionErrors['Windows 365 (Cloud PC)'] = $true
        if ($failMsg -match '403|Forbidden') {
            Write-Warning "A 403 here almost always means the tenant has no Windows 365 / Cloud PC licensing, the RoleManagement.Read.CloudPC scope was not consented, or your account lacks a Cloud PC role. Section skipped."
        }
        elseif ($failMsg -match '400|Bad Request') {
            Write-Warning "A 400 suggests the Cloud PC RBAC provider is not available in this tenant. Section skipped."
        }
    }
}

# --------------------------------------------------------------------------------
# W6 - Azure RBAC (subscription role assignments) via the Az modules
# Separate Azure sign-in. Requires Az.Accounts + Az.Resources and Reader (or
# higher) on the subscriptions. Read-only: Get-* and context selection only.
# --------------------------------------------------------------------------------
if (-not $runAzureRbac) {
    Write-Host "`n[*] Skipping Azure RBAC (not selected - use -IncludeAzureRBAC or -Reports AzureRBAC)." -ForegroundColor Gray
}
else {
    Write-Host "`n[*] Collecting Azure RBAC subscription role assignments..." -ForegroundColor Cyan
    $azConnected = $false      # tracks whether THIS run signed in (controls disconnect)

    # Snapshot whatever Azure context is active before this section touches
    # anything, so it can be restored afterward - otherwise per-subscription
    # Set-AzContext calls (or this run's disconnect) leave the operator's
    # window pointed at a different subscription, or at nothing.
    $originalAzContext  = $null
    $originalAzContexts = @()
    try { $originalAzContext = Get-AzContext -ErrorAction SilentlyContinue } catch { }
    try { $originalAzContexts = @(Get-AzContext -ListAvailable -ErrorAction SilentlyContinue) } catch { }

    # Microsoft documents that Get-AzContext -ListAvailable can omit contexts
    # when more than the default population limit are available. A snapshot of
    # 25 or more contexts is therefore treated as potentially incomplete, and
    # the script will not disconnect an account based on that incomplete view.
    $azContextSnapshotMayBeIncomplete = ($originalAzContexts.Count -ge 25)

    # Preserve every account that already had a process context, not only the
    # account in the active context. Disconnect-AzAccount -Username removes all
    # process contexts for that account, including inactive contexts that existed
    # before this report started.
    $preexistingAzAccountIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($savedAzContext in $originalAzContexts) {
        if ($savedAzContext -and $savedAzContext.Account -and $savedAzContext.Account.Id) {
            $null = $preexistingAzAccountIds.Add("$($savedAzContext.Account.Id)")
        }
    }

    try {
            # Azure RBAC and Graph principal resolution MUST target the same
            # tenant. Without pinning, an Azure sign-in that lands on the
            # account's home tenant (very easy with commercial + DoD creds)
            # enumerates a different tenant's subscriptions - or none - and the
            # report silently comes back empty. This is the fix for the
            # "Azure RBAC returns zero results" case.
            $targetTenantId = "$($context.TenantId)"
            if (-not $targetTenantId) {
                throw 'The Microsoft Graph context did not contain a tenant ID, so the Azure sign-in cannot be pinned to the correct tenant.'
            }

            # Azure PowerShell caches contexts across sessions, so a prior
            # sign-in makes Connect-AzAccount return silently with no browser.
            # A cached context is reused ONLY when its environment AND tenant
            # both match what this run needs.
            $existingAz = $null
            try { $existingAz = Get-AzContext -ErrorAction SilentlyContinue } catch { }

            $existingAzEnv      = ''
            $existingAzTenantId = ''
            if ($existingAz) {
                $existingAzEnv = "$($existingAz.Environment.Name)"
                if ($existingAz.Tenant -and $existingAz.Tenant.Id) { $existingAzTenantId = "$($existingAz.Tenant.Id)" }
                elseif ($existingAz.Tenant)                        { $existingAzTenantId = "$($existingAz.Tenant)" }
            }

            $reuseAzContext = ($existingAz -and $existingAz.Account -and
                               ($existingAzEnv -eq $azEnvName) -and
                               ($existingAzTenantId -eq $targetTenantId) -and
                               (-not $ForceAzureLogin))

            if ($reuseAzContext) {
                Write-Host "    Reusing Azure sign-in: $($existingAz.Account.Id) | Tenant: $existingAzTenantId | Environment: $existingAzEnv (pass -ForceAzureLogin to switch accounts)." -ForegroundColor Yellow
            }
            else {
                if ($existingAz) {
                    Write-Warning "Existing Azure context (tenant '$existingAzTenantId' in '$existingAzEnv') does not match the target tenant '$targetTenantId' in '$azEnvName'. Re-authenticating for the correct tenant..."
                }

                # -Scope Process keeps this sign-in out of the persistent Azure
                # context cache, so the run cannot clobber the operator's saved
                # default subscription.
                $azConnectParams = @{
                    Environment = $azEnvName
                    Tenant      = $targetTenantId
                    Scope       = 'Process'
                    ErrorAction = 'Stop'
                }

                if ($UseAzureDeviceCode) {
                    Write-Host "    Signing in to Azure ($azEnvName, tenant $targetTenantId) via device code - follow the code/URL printed below..." -ForegroundColor Yellow
                    $azConnectParams['UseDeviceAuthentication'] = $true
                    $null = Connect-AzAccount @azConnectParams
                }
                else {
                    Write-Host "    Launching Azure sign-in for $azEnvName, tenant $targetTenantId (a browser window should open; if none appears, rerun with -UseAzureDeviceCode)..." -ForegroundColor Yellow
                    try {
                        $null = Connect-AzAccount @azConnectParams
                    }
                    catch {
                        Write-Warning "Interactive browser sign-in failed ($($_.Exception.Message)). Falling back to device-code authentication..."
                        $azConnectParams['UseDeviceAuthentication'] = $true
                        $null = Connect-AzAccount @azConnectParams
                    }
                }
                $azConnected = $true
            }

            # Identity of the account THIS run is operating as - used at
            # cleanup time to disconnect only that account, never the one
            # backing the operator's original context.
            $runAzAccountId = ''
            try {
                $curAzCtx = Get-AzContext -ErrorAction SilentlyContinue
                if ($curAzCtx -and $curAzCtx.Account) { $runAzAccountId = "$($curAzCtx.Account.Id)" }
            }
            catch { }

            $subscriptions = @(
                Get-AzSubscription -TenantId $targetTenantId -ErrorAction Stop |
                    Where-Object { "$($_.State)" -eq 'Enabled' }
            )

            if ($subscriptions.Count -eq 0) {
                # Fail loudly. Processing zero subscriptions previously produced a
                # clean-looking empty report, which is the worst outcome for an audit.
                $azAccountId = ''
                try {
                    $curAz = Get-AzContext -ErrorAction SilentlyContinue
                    if ($curAz -and $curAz.Account) { $azAccountId = "$($curAz.Account.Id)" }
                }
                catch { }
                throw "The Azure account has no enabled subscriptions in tenant '$targetTenantId' (account: '$azAccountId', environment: '$azEnvName'). Verify the account has at least Reader on the subscriptions in this tenant."
            }

            Write-Host "    Processing $($subscriptions.Count) enabled subscription(s) in tenant $targetTenantId..." -ForegroundColor Yellow
            $azSubFailures = 0

            foreach ($sub in $subscriptions) {
                $azAssignments = @()
                try {
                    # Passing the subscription OBJECT preserves its tenant
                    # association, so a same-named subscription in another tenant
                    # cannot be selected by accident.
                    $subContext = Set-AzContext -SubscriptionObject $sub -Scope Process -ErrorAction Stop

                    # Two queries are needed. Without -Scope, Get-AzRoleAssignment
                    # returns assignments made UNDER the subscription, which omits
                    # anything inherited from a management group or the tenant root
                    # - a common way to grant Azure access in a governed tenant, and
                    # a second reason this report could come back empty. The
                    # -Scope query returns assignments effective AT the subscription,
                    # including those inherited from above. The two overlap, so
                    # results are deduplicated on the assignment's resource ID.
                    $underSub = @(Get-AzRoleAssignment -DefaultProfile $subContext -ErrorAction Stop)
                    $atSub    = @(Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)" -DefaultProfile $subContext -ErrorAction Stop)

                    $seen = @{}
                    foreach ($cand in @($underSub + $atSub)) {
                        $key = "$($cand.RoleAssignmentId)"
                        if (-not $key) {
                            # Fallback for module versions that leave RoleAssignmentId empty.
                            $key = "$($cand.ObjectId)|$($cand.RoleDefinitionId)|$($cand.Scope)"
                        }
                        $seen[$key] = $cand
                    }
                    $azAssignments = @($seen.Values)

                    Write-Host "      $($sub.Name): $($azAssignments.Count) unique role assignment(s)." -ForegroundColor Gray
                }
                catch {
                    $azSubFailures++
                    $script:sectionErrors['Azure RBAC'] = $true
                    Write-Warning "Could not read Azure RBAC assignments for subscription '$($sub.Name)' ($($sub.Id)) in tenant '$targetTenantId': $($_.Exception.Message)"
                    continue
                }

                foreach ($ra in $azAssignments) {
                    # Reset per iteration. PowerShell variables persist across
                    # loop iterations, so without this an orphaned assignment or
                    # one carrying SignInName would inherit the PREVIOUS
                    # principal's resolved object - and with it that principal's
                    # AccountEnabled value.
                    $resolved = $null

                    # Orphaned assignments (deleted principals) come back with
                    # an empty DisplayName and ObjectType 'Unknown' - flag them
                    # instead of printing a bare GUID. Groups and service
                    # principals have no SignInName, so resolve a friendlier
                    # identity (group mail / AppId) through Graph.
                    $raType   = "$($ra.ObjectType)"
                    $isOrphan = (-not $ra.DisplayName) -and (($raType -eq 'Unknown') -or (-not $raType))

                    if ($isOrphan) {
                        $memberName = 'Orphaned assignment (deleted principal)'
                        $memberId   = "ObjectId: $($ra.ObjectId)"
                    }
                    elseif ($raType -eq 'User' -and $ra.SignInName) {
                        $memberName = "$($ra.DisplayName)"
                        $memberId   = "$($ra.SignInName)"
                    }
                    else {
                        $probeType  = $(if ($raType -in @('User','Group','ServicePrincipal')) { $raType } else { '' })
                        $resolved   = Resolve-Principal -PrincipalId "$($ra.ObjectId)" -PrincipalType $probeType
                        $memberName = $(if ($ra.DisplayName) { "$($ra.DisplayName)" } else { $resolved.DisplayName })
                        $memberId   = $resolved.Identity
                    }

                    $row = @{
                        Workload          = 'Azure RBAC'
                        Role              = "$($ra.RoleDefinitionName)"
                        AssignmentName    = "$($sub.Name)"
                        MemberDisplayName = $memberName
                        MemberIdentity    = $memberId
                        MemberType        = "$($ra.ObjectType)"
                        AssignedVia       = 'Direct Role Assignment'
                        ResolutionStatus  = $(if ($isOrphan) { 'Orphaned' } elseif ($resolved) { $resolved.ResolutionStatus } else { 'Found' })
                        Scope             = "$($ra.Scope)"
                        AccountEnabled    = $(if ($resolved) { "$($resolved.AccountEnabled)" } else { 'N/A' })
                    }
                    Add-WorkloadRow @row

                    # Groups get expanded to members via Graph (session already open).
                    if ("$raType" -eq 'Group' -and $ra.ObjectId -and $resolved -and $resolved.ResolutionStatus -eq 'Found') {
                        $gMembers = @()
                        try {
                            $gMembers = @(Get-GroupMemberWithNesting -GroupId "$($ra.ObjectId)")
                        }
                        catch {
                            Write-Warning "Could not expand Azure-assigned group '$memberName' ($($ra.ObjectId)): $_"
                            $script:sectionErrors['Azure RBAC'] = $true
                        }

                        foreach ($entry in $gMembers) {
                            $gm = $entry.Member
                            if (-not (Test-IsPrincipalMember -Member $gm)) { continue }

                            $gmType     = $gm.AdditionalProperties.'@odata.type' -replace '#microsoft\.graph\.',''
                            $gPrincipal = Resolve-Principal -PrincipalId $gm.Id -PrincipalType $gmType
                            $viaLabel   = Get-MembershipViaLabel -Path $entry.MembershipPath -Prefix 'Group Member' -GroupName "$memberName"

                            $row = @{
                                Workload          = 'Azure RBAC'
                                Role              = "$($ra.RoleDefinitionName)"
                                AssignmentName    = "$($sub.Name)"
                                MemberDisplayName = $gPrincipal.DisplayName
                                MemberIdentity    = $gPrincipal.Identity
                                MemberType        = $gPrincipal.PrincipalType
                                AssignedVia       = $viaLabel
                                ResolutionStatus  = $gPrincipal.ResolutionStatus
                                Scope             = "$($ra.Scope)"
                                AccountEnabled    = "$($gPrincipal.AccountEnabled)"
                            }
                            Add-WorkloadRow @row
                        }
                    }
                }
            }

            $azCount = @($workloadReport | Where-Object { $_.Workload -eq 'Azure RBAC' }).Count

            if ($azSubFailures -eq $subscriptions.Count) {
                throw "Azure RBAC collection failed for every one of the $($subscriptions.Count) enabled subscription(s) - no data was gathered. See the per-subscription warnings above."
            }
            elseif ($azSubFailures -gt 0) {
                Write-Warning "Azure RBAC is PARTIAL: $azSubFailures of $($subscriptions.Count) subscription(s) could not be read. $azCount row(s) collected from the rest."
            }
            else {
                Write-Host "[+] Azure RBAC rows collected: $azCount" -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "Azure RBAC collection failed: $_"
            $script:sectionErrors['Azure RBAC'] = $true
        }
        finally {
            # Cleanup ORDER matters: restoring a context is useless if the
            # disconnect first removed the credentials it depends on. So:
            #   1. If this run signed in with ANY account that already had a
            #      process context before the run, the sign-in is left in place.
            #      Disconnect-AzAccount -Username would otherwise remove all of
            #      that account's preexisting active and inactive contexts.
            #   2. If the pre-run context snapshot may be incomplete, no account
            #      is disconnected because an unobserved context could predate the run.
            #   3. Only a provably new account is disconnected by username.
            #   4. The original active context is restored last, and a failed restore
            #      is counted and surfaces as DEGRADED in RUN STATUS.
            if ($azConnected) {
                $runAccountPreexisted = $false
                if ($runAzAccountId) {
                    $runAccountPreexisted = $preexistingAzAccountIds.Contains($runAzAccountId)
                }

                if ($runAccountPreexisted) {
                    Write-Host "    Leaving the Azure sign-in in place: account '$runAzAccountId' already had one or more process contexts before this run." -ForegroundColor Gray
                }
                elseif ($azContextSnapshotMayBeIncomplete) {
                    Register-CleanupWarning -Message "The pre-run Azure context snapshot contained $($originalAzContexts.Count) contexts and may be incomplete. Account '$runAzAccountId' is left connected rather than risk removing an unobserved preexisting context."
                }
                elseif ($runAzAccountId) {
                    try {
                        $null = Disconnect-AzAccount -Username $runAzAccountId -Scope Process -ErrorAction Stop
                    }
                    catch {
                        Register-CleanupWarning -Message "Targeted Azure disconnect for '$runAzAccountId' failed: $($_.Exception.Message). The sign-in is left in place."
                    }
                }
                else {
                    Register-CleanupWarning -Message "The run's Azure account identity could not be determined. The sign-in is left in place rather than risking an untargeted disconnect."
                }
            }

            if ($originalAzContext) {
                try {
                    $null = Set-AzContext -Context $originalAzContext -Scope Process -ErrorAction Stop
                }
                catch {
                    $script:azRestoreFailures++
                    Write-Warning "Could not restore the original Azure context: $($_.Exception.Message). Re-select your subscription with Set-AzContext."
                }
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
    'Azure RBAC'                      = 'AzureRBAC'
}

foreach ($wl in $workloadFileTokens.Keys) {
    $rows = @($workloadReport | Where-Object { $_.Workload -eq $wl })
    Write-Host ("  {0,-32}: {1}" -f $wl, $rows.Count)

    if ($rows.Count -gt 0) {
        $wlPath = Join-Path -Path $OutputFolder -ChildPath "$($workloadFileTokens[$wl])RoleReport_$reportTimestamp.csv"
        try {
            $rows |
                Sort-Object Role, MemberDisplayName |
                ConvertTo-SafeCsvRow |
                Export-Csv -Path $wlPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Host "      -> $wlPath" -ForegroundColor Cyan
        }
        catch {
            $script:exportFailures[$wl] = "$($_.Exception.Message)"
            Write-Error "FAILED to export '$wl' to '$wlPath': $($_.Exception.Message). The data was collected but NOT written."
        }
    }
}
Write-Host ("  {0,-32}: {1}" -f 'Total rows', $workloadReport.Count)
Write-Host ""

$anyWorkloadSelected = ($runExchange -or $runPurview -or $runIntune -or $runDefender -or $runCloudPC -or $runAzureRbac)
if ($workloadReport.Count -eq 0 -and $anyWorkloadSelected) {
    Write-Warning "No workload role assignments were collected - no Part 2 files were written. Review the warnings above."
}
elseif ($workloadReport.Count -eq 0) {
    Write-Host "  (No workload reports were selected for this run.)" -ForegroundColor Gray
}

# Perform the final connection-cleanup retry BEFORE constructing RUN STATUS so
# cleanup failures are represented in the status artifact and exit code.
$wasGraphConnected = $script:graphConnected
Invoke-ScriptCleanup
if ($wasGraphConnected -and -not $script:graphConnected) {
    Write-Host "[*] Disconnected from Microsoft Graph.`n" -ForegroundColor Gray
}

# ================================================================================
# RUN STATUS - the authoritative statement of what this run actually produced.
# An audit artifact must never let a partial failure read as a clean result, so
# every report is classified explicitly rather than inferred from row counts.
# ================================================================================
$statusRows = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-StatusRow {
    param (
        [string]$Report,
        [bool]$Selected,
        [int]$Rows
    )

    $status = 'Succeeded'
    $detail = ''

    if (-not $Selected) {
        $status = 'Skipped'
        $detail = 'Not selected for this run'
    }
    elseif ($script:exportFailures.ContainsKey($Report)) {
        $status = 'EXPORT FAILED'
        $detail = "Data collected but not written: $($script:exportFailures[$Report])"
    }
    elseif ($script:sectionErrors.ContainsKey($Report) -and $Rows -gt 0) {
        $status = 'PARTIAL'
        $detail = 'Query errors occurred - rows may be incomplete'
    }
    elseif ($script:sectionErrors.ContainsKey($Report)) {
        $status = 'FAILED'
        $detail = 'Query failed - no data collected'
    }
    elseif ($Rows -eq 0) {
        $status = 'No data'
        $detail = 'Query succeeded but returned nothing'
    }

    $statusRows.Add([PSCustomObject]@{
        Report = $Report
        Rows   = $Rows
        Status = $status
        Detail = $detail
    })
}

Add-StatusRow -Report 'Entra directory roles' -Selected $runEntra -Rows $report.Count
foreach ($wl in $workloadFileTokens.Keys) {
    $wlSelected = switch ($wl) {
        'Exchange Online'                 { $runExchange }
        'Purview (Security & Compliance)' { $runPurview }
        'Intune'                          { $runIntune }
        'Defender XDR'                    { $runDefender }
        'Windows 365 (Cloud PC)'          { $runCloudPC }
        'Azure RBAC'                      { $runAzureRbac }
        default                           { $false }
    }
    $wlRows = @($workloadReport | Where-Object { $_.Workload -eq $wl }).Count
    Add-StatusRow -Report $wl -Selected $wlSelected -Rows $wlRows
}

# Cross-cutting fidelity: blocked identity lookups and unknown membership depth
# do not fail a report outright, but they mean rows exist whose identity or
# provenance is incomplete. They surface here as DEGRADED entries with counts
# so a clean-looking run cannot hide them.
if ($script:unresolvedLookupCount -gt 0) {
    $blockedStatusSet = @('AccessDenied','Throttled','Transient','Unexpected')
    $affectedRowCount = @($report | Where-Object { "$($_.ResolutionStatus)" -in $blockedStatusSet }).Count
    $affectedRowCount += @($workloadReport | Where-Object { "$($_.ResolutionStatus)" -in $blockedStatusSet }).Count

    $statusRows.Add([PSCustomObject]@{
        Report = '(identity resolution)'
        Rows   = $script:unresolvedPrincipalIds.Count
        Status = 'DEGRADED'
        Detail = "$($script:unresolvedPrincipalIds.Count) unique principal(s) unresolved across $($script:unresolvedLookupCount) blocked lookup attempt(s); $affectedRowCount report row(s) carry a blocked ResolutionStatus and are NOT confirmed deleted. Rerun after the condition clears."
    })
}
if ($script:unknownDepthGroups -gt 0) {
    $statusRows.Add([PSCustomObject]@{
        Report = '(membership depth)'
        Rows   = $script:unknownDepthGroupIds.Count
        Status = 'DEGRADED'
        Detail = "$($script:unknownDepthGroupIds.Count) unique group(s) had a failed direct-member query ($($script:unknownDepthGroups) attempt(s)); their members are labeled depth UNKNOWN rather than Direct."
    })
}
if ($script:exoAssigneeLookupFailures -gt 0) {
    $statusRows.Add([PSCustomObject]@{
        Report = '(exchange assignee resolution)'
        Rows   = $script:exoAssigneeLookupFailures
        Status = 'DEGRADED'
        Detail = 'Direct-assignment assignee identity lookups failed (transient or ambiguous). Failures were NOT cached; affected rows say so in MemberIdentity.'
    })
}
if ($script:exoForeignPrincipalRows -gt 0) {
    # INFO, not DEGRADED: preserving the raw RoleAssignee value for foreign
    # security principals is the intended design (a recipient lookup could bind
    # an unrelated object). The identity shown is accurate, so these rows do
    # not reduce fidelity and must not push the run to exit code 4.
    $statusRows.Add([PSCustomObject]@{
        Report = '(exchange foreign principals)'
        Rows   = $script:exoForeignPrincipalRows
        Status = 'INFO'
        Detail = 'ForeignSecurityPrincipal assignments were preserved using the raw RoleAssignee value. No display-name or recipient lookup was attempted because it could resolve an unrelated mail recipient. This is by design and does not reduce report fidelity.'
    })
}
if ($script:linkedGroupPlaceholders -gt 0) {
    $statusRows.Add([PSCustomObject]@{
        Report = '(linked role groups)'
        Rows   = $script:linkedGroupPlaceholders
        Status = 'DEGRADED'
        Detail = 'Effective rows represent ALL members of linked/foreign role groups, which Exchange cannot enumerate from the cloud side. Verify those memberships in the source (on-premises) directory.'
    })
}
if ($script:azRestoreFailures -gt 0) {
    $statusRows.Add([PSCustomObject]@{
        Report = '(azure context restore)'
        Rows   = $script:azRestoreFailures
        Status = 'DEGRADED'
        Detail = 'The Azure context active before this run could not be restored. Re-select your subscription with Set-AzContext.'
    })
}
if ($script:cleanupWarningMessages.Count -gt 0) {
    $statusRows.Add([PSCustomObject]@{
        Report = '(local session cleanup)'
        Rows   = $script:cleanupWarningMessages.Count
        Status = 'DEGRADED'
        Detail = (($script:cleanupWarningMessages | Sort-Object) -join ' | ')
    })
}

Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host "                    RUN STATUS" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
foreach ($sr in $statusRows) {
    $color = switch ($sr.Status) {
        'Succeeded'     { 'Green' }
        'Skipped'       { 'Gray' }
        'No data'       { 'Yellow' }
        'DEGRADED'      { 'Yellow' }
        'INFO'          { 'Gray' }
        default         { 'Red' }
    }
    Write-Host ("  {0,-32} {1,6}  {2}" -f $sr.Report, $sr.Rows, $sr.Status) -ForegroundColor $color
    if ($sr.Detail -and $sr.Status -notin @('Succeeded','Skipped')) {
        Write-Host ("      {0}" -f $sr.Detail) -ForegroundColor $color
    }
}
Write-Host ""

$badStatuses  = @($statusRows | Where-Object { $_.Status -in @('FAILED','PARTIAL','EXPORT FAILED') })
$noDataRows   = @($statusRows | Where-Object { $_.Status -eq 'No data' })
$statusExportFailed = $false

if ($badStatuses.Count -gt 0) {
    Write-Warning "THIS RUN IS NOT A COMPLETE INVENTORY. $($badStatuses.Count) report(s) failed, were partial, or could not be written - see RUN STATUS above. Do not treat the output as a full privileged-access inventory until those are resolved."
}
elseif ($noDataRows.Count -gt 0) {
    # A 'No data' report produced NO CSV, so claiming everything was written
    # would be false. The query succeeded, but the operator must confirm the
    # emptiness is real rather than a silent scoping or permission problem.
    Write-Warning "All selected reports completed without error, but $($noDataRows.Count) returned NO DATA and therefore produced NO FILE: $(($noDataRows | ForEach-Object { $_.Report }) -join ', '). Confirm that emptiness is expected for this tenant."
}
else {
    Write-Host "[+] All selected reports completed and were written successfully." -ForegroundColor Green
}

$degradedRows = @($statusRows | Where-Object { $_.Status -eq 'DEGRADED' })
if ($degradedRows.Count -gt 0) {
    Write-Warning "RUN COMPLETED WITH DEGRADED FIDELITY OR CLEANUP: $(($degradedRows | ForEach-Object { "$($_.Report) x$($_.Rows)" }) -join '; '). Review the DEGRADED rows in RUN STATUS before treating the result as a complete inventory."
}

# Write the status alongside the reports so the artifact is self-describing.
try {
    $statusPath = Join-Path -Path $OutputFolder -ChildPath "RunStatus_$reportTimestamp.csv"
    $statusRows | ConvertTo-SafeCsvRow | Export-Csv -Path $statusPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    Write-Host "  Run status: $statusPath" -ForegroundColor Cyan
    Write-Host ""
}
catch {
    $statusExportFailed = $true
    Write-Error "Could not write the run-status file: $($_.Exception.Message). The run cannot be self-documenting without it."
}

# ================================================================================
# EXIT CODE. Scheduled runs need to detect an incomplete audit without parsing
# console output, so anything short of a clean, fully written run exits non-zero.
#   0 = every selected report completed without error at full fidelity.
#       Reports that legitimately returned no rows produce no file and still
#       exit 0 (their 'No data' state is called out in RUN STATUS).
#   1 = startup failure before collection (output folder, module import,
#       Graph sign-in, or an entirely invalid -RoleFilter)
#   2 = a report failed, was partial, or could not be exported
#   3 = the run-status file itself could not be written
#   4 = completed, but DEGRADED: identity lookups were blocked, membership
#       depth could not be determined, or local session/context cleanup did
#       not fully succeed (see RUN STATUS) - the data is usable but the run
#       was not full fidelity, so scheduled runs can flag it
# ================================================================================
if ($statusExportFailed) {
    Write-Warning "Exiting with code 3 (run-status file could not be written)."
    exit 3
}
if ($badStatuses.Count -gt 0) {
    Write-Warning "Exiting with code 2 (incomplete run - see RUN STATUS above)."
    exit 2
}
if ($degradedRows.Count -gt 0) {
    Write-Warning "Exiting with code 4 (completed with DEGRADED fidelity - see RUN STATUS above)."
    exit 4
}
exit 0
