#requires -Version 5.1

<#
.SYNOPSIS
Creates a CSV report that matches disable.* Entra ID accounts to same-name
accounts whose UPN contains .SA@adm.

.DESCRIPTION
This read-only script:

1. Retrieves all Entra ID users through Microsoft Graph.
2. Selects source users whose userPrincipalName starts with "disable.".
3. Selects candidate accounts whose userPrincipalName contains ".SA@adm".
4. Matches source and candidate accounts by givenName and surname.
5. Enriches each matched SA account with its display name, last sign-in, and
   any activated Entra directory roles it holds.
6. Exports one row per source/SA pair.

The CSV contains six columns:

- UserPrincipalName    The disable.* account.
- SAUserPrincipalName  One matching .SA@adm account.
- SADisplayName        Display name of the SA account.
- SALastSignIn         Most recent interactive or non-interactive sign-in (UTC).
- SADaysSinceSignIn    Whole days since SALastSignIn.
- SADirectoryRoles     Semicolon-separated list of activated directory roles.

A source account with three matches produces three rows. Matching is by name
only and is deliberately approximate; treat multiple rows for one source
account as candidates for review, not as a definitive mapping.

Name and UPN comparisons are case-insensitive. Leading and trailing spaces in
givenName and surname are ignored.

The script does not change Entra ID. It only reads directory data and writes a
local CSV file.

.PARAMETER OutputPath
Path of the CSV file to create. Defaults to a timestamped file under C:\temp.
The parent directory is created if it does not exist.

.PARAMETER TenantId
Entra tenant ID or verified domain. When connecting, it is passed to
Connect-MgGraph. When used with -SkipConnect, a tenant GUID is validated
against the existing session so the report cannot silently run against the
wrong tenant.

.PARAMETER DisabledUpnPrefix
UPN prefix used to identify source accounts. The default is "disable.".

.PARAMETER SaUpnMarker
Text that a candidate account UPN must contain. The default is ".SA@adm".

.PARAMETER SkipConnect
Skips Connect-MgGraph and uses the current Graph session. The script verifies
that a session actually exists before continuing.

.PARAMETER Force
Overwrites OutputPath if it already exists. Without this switch, an existing
file causes the script to stop.

.PARAMETER PassThru
Returns the report rows to the pipeline after exporting the CSV. Without this
switch, the script returns a summary object.

.NOTES
Required delegated Graph scopes:

- User.ReadBasic.All          user lookup
- AuditLog.Read.All           signInActivity (also needs Entra ID P1/P2)
- RoleManagement.Read.Directory   directory role membership

The sign-in and role columns degrade gracefully. If either scope is missing,
the licence is absent, or the signed-in account lacks a reader role, those
columns report "(unavailable)" and the rest of the report still runs.

Only activated directory roles are enumerated. PIM-eligible assignments that
are not currently active will not appear.

.EXAMPLE
.\Export-EntraDisabledSaAccountReport.ps1

.EXAMPLE
.\Export-EntraDisabledSaAccountReport.ps1 `
    -TenantId 'contoso.onmicrosoft.com' `
    -Verbose

.EXAMPLE
$rows = .\Export-EntraDisabledSaAccountReport.ps1 -PassThru -Force
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param
(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (
        'C:\temp\disableSA_Report-{0}.csv' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    ),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DisabledUpnPrefix = 'disable.',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$SaUpnMarker = '.SA@adm',

    [Parameter()]
    [switch]$SkipConnect,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:UnavailableValue = '(unavailable)'
$script:NoneValue        = '(none)'
$script:NeverValue       = '(never)'

function Get-NormalizedNameKey
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [AllowNull()]
        [string]$GivenName,

        [Parameter()]
        [AllowNull()]
        [string]$Surname
    )

    if ([string]::IsNullOrWhiteSpace($GivenName) -or
        [string]::IsNullOrWhiteSpace($Surname))
    {
        return $null
    }

    # Use an uncommon separator to avoid collisions between name components.
    return (
        $GivenName.Trim().ToUpperInvariant() +
        [char]31 +
        $Surname.Trim().ToUpperInvariant()
    )
}

function Get-LatestSignInDate
{
    <#
        Returns the most recent of the interactive and non-interactive sign-in
        timestamps, or $null when neither is present. Every hop is null-checked
        because strict mode treats a property access on $null as an error.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [AllowNull()]
        $User
    )

    if ($null -eq $User)
    {
        return $null
    }

    if (-not $User.PSObject.Properties.Match('SignInActivity').Count)
    {
        return $null
    }

    $activity = $User.SignInActivity

    if ($null -eq $activity)
    {
        return $null
    }

    $timestamps = New-Object System.Collections.Generic.List[datetime]

    foreach ($propertyName in @(
            'LastSignInDateTime'
            'LastNonInteractiveSignInDateTime'
        ))
    {
        if (-not $activity.PSObject.Properties.Match($propertyName).Count)
        {
            continue
        }

        $value = $activity.$propertyName

        if ($value -is [datetime])
        {
            $timestamps.Add($value)
        }
    }

    if ($timestamps.Count -eq 0)
    {
        return $null
    }

    return (
        $timestamps |
            Sort-Object -Descending |
            Select-Object -First 1
    )
}

function Get-DirectoryRoleMembershipMap
{
    <#
        Builds a hashtable of user object ID -> list of activated directory
        role names. Role membership is small, so this is a handful of calls
        regardless of tenant size.
    #>
    [CmdletBinding()]
    param()

    $map = @{}
    $roles = @(Get-MgDirectoryRole -All -ErrorAction Stop)

    Write-Verbose (
        'Enumerating members of {0} activated directory role(s).' -f $roles.Count
    )

    foreach ($role in $roles)
    {
        $members = @(
            Get-MgDirectoryRoleMember `
                -DirectoryRoleId $role.Id `
                -All `
                -ErrorAction Stop
        )

        foreach ($member in $members)
        {
            if ([string]::IsNullOrWhiteSpace($member.Id))
            {
                continue
            }

            if (-not $map.ContainsKey($member.Id))
            {
                $map[$member.Id] = New-Object System.Collections.Generic.List[string]
            }

            [void]$map[$member.Id].Add($role.DisplayName)
        }
    }

    return $map
}

$script:ConnectedByScript = $false

try
{
    #region Dependency checks

    $requiredModules = @(
        'Microsoft.Graph.Authentication'
        'Microsoft.Graph.Users'
        'Microsoft.Graph.Identity.DirectoryManagement'
    )

    foreach ($moduleName in $requiredModules)
    {
        if (-not (Get-Module -ListAvailable -Name $moduleName))
        {
            throw (
                (
                    "Required module '{0}' is not installed. Install the Microsoft " +
                    "Graph PowerShell SDK before running this report."
                ) -f $moduleName
            )
        }

        Import-Module -Name $moduleName -ErrorAction Stop
    }

    #endregion Dependency checks

    #region Output-path validation

    # Resolve against the PowerShell location, not the process working
    # directory. [System.IO.Path]::GetFullPath would use the latter and
    # silently place the report somewhere else.
    try
    {
        $resolvedOutputPath =
            $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
                $OutputPath
            )
    }
    catch
    {
        throw ("OutputPath is invalid: '{0}'. {1}" -f $OutputPath, $_.Exception.Message)
    }

    if (Test-Path -LiteralPath $resolvedOutputPath -PathType Container)
    {
        throw (
            "OutputPath points at an existing directory: '{0}'." -f $resolvedOutputPath
        )
    }

    if ((Test-Path -LiteralPath $resolvedOutputPath -PathType Leaf) -and -not $Force)
    {
        throw (
            "The file already exists: '{0}'. Re-run with -Force to overwrite it." -f
            $resolvedOutputPath
        )
    }

    $outputDirectory = [System.IO.Path]::GetDirectoryName($resolvedOutputPath)

    if ([string]::IsNullOrWhiteSpace($outputDirectory))
    {
        throw ("Could not determine an output directory from '{0}'." -f $resolvedOutputPath)
    }

    if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container))
    {
        if ($PSCmdlet.ShouldProcess($outputDirectory, 'Create output directory'))
        {
            Write-Verbose ("Creating output directory '{0}'." -f $outputDirectory)

            [void](New-Item -Path $outputDirectory -ItemType Directory -Force -ErrorAction Stop)
        }
    }

    #endregion Output-path validation

    #region Microsoft Graph connection

    if ($SkipConnect)
    {
        $graphContext = Get-MgContext

        if ($null -eq $graphContext)
        {
            throw (
                'SkipConnect was specified but no Microsoft Graph session exists ' +
                'in this process. Run Connect-MgGraph first, or omit -SkipConnect.'
            )
        }
    }
    else
    {
        $connectParameters = @{
            Scopes      = @(
                'User.ReadBasic.All'
                'AuditLog.Read.All'
                'RoleManagement.Read.Directory'
            )
            ErrorAction = 'Stop'
        }

        if (-not [string]::IsNullOrWhiteSpace($TenantId))
        {
            $connectParameters['TenantId'] = $TenantId
        }

        Write-Verbose 'Connecting to Microsoft Graph.'
        Connect-MgGraph @connectParameters | Out-Null

        $script:ConnectedByScript = $true
        $graphContext = Get-MgContext
    }

    # Guard against reporting on the wrong tenant when a session is reused.
    $parsedTenantGuid = [guid]::Empty

    if (-not [string]::IsNullOrWhiteSpace($TenantId) -and
        [guid]::TryParse($TenantId, [ref]$parsedTenantGuid) -and
        $graphContext.TenantId -ne $parsedTenantGuid.ToString())
    {
        throw (
            (
                "The active Graph session is connected to tenant '{0}', not the " +
                "requested tenant '{1}'."
            ) -f $graphContext.TenantId, $TenantId
        )
    }

    Write-Verbose (
        "Connected to tenant '{0}' as '{1}'." -f
        $graphContext.TenantId,
        $graphContext.Account
    )

    #endregion Microsoft Graph connection

    #region Retrieve Entra ID users

    $getUserParameters = @{
        All         = $true
        Property    = @(
            'id'
            'displayName'
            'givenName'
            'surname'
            'userPrincipalName'
        )
        ErrorAction = 'Stop'
    }

    Write-Verbose 'Retrieving Entra ID users from Microsoft Graph.'

    try
    {
        $allUsers = @(Get-MgUser @getUserParameters)
    }
    catch
    {
        throw ("Microsoft Graph failed while retrieving users. {0}" -f $_.Exception.Message)
    }

    Write-Verbose ('Retrieved {0} user object(s).' -f $allUsers.Count)

    #endregion Retrieve Entra ID users

    #region Identify source users and SA candidates

    # Single pass over the collection instead of two Where-Object passes.
    $disabledUsers = New-Object System.Collections.Generic.List[object]
    $saCandidates  = New-Object System.Collections.Generic.List[object]

    foreach ($user in $allUsers)
    {
        if ([string]::IsNullOrWhiteSpace($user.UserPrincipalName))
        {
            continue
        }

        if ($user.UserPrincipalName.StartsWith(
                $DisabledUpnPrefix,
                [System.StringComparison]::OrdinalIgnoreCase))
        {
            $disabledUsers.Add($user)
        }

        if ($user.UserPrincipalName.IndexOf(
                $SaUpnMarker,
                [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        {
            $saCandidates.Add($user)
        }
    }

    Write-Verbose (
        "Found {0} source account(s) beginning with '{1}'." -f
        $disabledUsers.Count,
        $DisabledUpnPrefix
    )

    Write-Verbose (
        "Found {0} candidate account(s) containing '{1}'." -f
        $saCandidates.Count,
        $SaUpnMarker
    )

    #endregion Identify source users and SA candidates

    #region Index SA candidates by first and last name

    $candidateIndex        = @{}
    $skippedCandidateCount = 0

    foreach ($candidate in $saCandidates)
    {
        $candidateKey = Get-NormalizedNameKey `
            -GivenName $candidate.GivenName `
            -Surname $candidate.Surname

        if ($null -eq $candidateKey)
        {
            $skippedCandidateCount++

            Write-Verbose (
                "Ignoring candidate with an incomplete name: '{0}'." -f
                $candidate.UserPrincipalName
            )

            continue
        }

        if (-not $candidateIndex.ContainsKey($candidateKey))
        {
            $candidateIndex[$candidateKey] =
                New-Object System.Collections.Generic.List[object]
        }

        [void]$candidateIndex[$candidateKey].Add($candidate)
    }

    #endregion Index SA candidates by first and last name

    #region Match source accounts to SA accounts

    $pairs              = New-Object System.Collections.Generic.List[object]
    $skippedSourceCount = 0
    $matchedSourceCount = 0

    foreach ($disabledUser in $disabledUsers)
    {
        $sourceKey = Get-NormalizedNameKey `
            -GivenName $disabledUser.GivenName `
            -Surname $disabledUser.Surname

        if ($null -eq $sourceKey)
        {
            $skippedSourceCount++

            Write-Verbose (
                "Skipping source account with an incomplete name: '{0}'." -f
                $disabledUser.UserPrincipalName
            )

            continue
        }

        if (-not $candidateIndex.ContainsKey($sourceKey))
        {
            continue
        }

        $matchedCandidates = @(
            $candidateIndex[$sourceKey] |
                Where-Object {
                    # "Another account" excludes the source object itself.
                    $_.Id -ne $disabledUser.Id -and
                    -not [string]::IsNullOrWhiteSpace($_.UserPrincipalName)
                } |
                Sort-Object -Property UserPrincipalName
        )

        if ($matchedCandidates.Count -eq 0)
        {
            continue
        }

        $matchedSourceCount++

        foreach ($match in $matchedCandidates)
        {
            $pairs.Add(
                [pscustomobject]@{
                    SourceUpn = $disabledUser.UserPrincipalName
                    SaUser    = $match
                }
            )
        }
    }

    Write-Verbose (
        '{0} source account(s) matched, producing {1} report row(s).' -f
        $matchedSourceCount,
        $pairs.Count
    )

    #endregion Match source accounts to SA accounts

    #region Enrich matched SA accounts

    $signInCache        = @{}
    $signInAvailable    = $true
    $signInFailureCause = $null
    $roleMap            = @{}
    $rolesAvailable     = $true
    $roleFailureCause   = $null

    if ($pairs.Count -gt 0)
    {
        try
        {
            $roleMap = Get-DirectoryRoleMembershipMap
        }
        catch
        {
            $rolesAvailable   = $false
            $roleFailureCause = $_.Exception.Message

            Write-Warning (
                (
                    'Directory role membership could not be read, so SADirectoryRoles ' +
                    'will report "{0}". {1}'
                ) -f $script:UnavailableValue, $roleFailureCause
            )
        }

        $uniqueSaIds = @(
            $pairs |
                ForEach-Object { $_.SaUser.Id } |
                Sort-Object -Unique
        )

        Write-Verbose (
            'Reading sign-in activity for {0} SA account(s).' -f $uniqueSaIds.Count
        )

        foreach ($saId in $uniqueSaIds)
        {
            if (-not $signInAvailable)
            {
                break
            }

            try
            {
                $saDetail = Get-MgUser `
                    -UserId $saId `
                    -Property @('id', 'signInActivity') `
                    -ErrorAction Stop

                $signInCache[$saId] = Get-LatestSignInDate -User $saDetail
            }
            catch
            {
                # A missing scope, licence, or reader role fails identically for
                # every account, so stop after the first failure.
                $signInAvailable    = $false
                $signInFailureCause = $_.Exception.Message

                Write-Warning (
                    (
                        'Sign-in activity could not be read, so SALastSignIn will ' +
                        'report "{0}". This usually means the AuditLog.Read.All scope, ' +
                        'an Entra ID P1/P2 licence, or a directory reader role is ' +
                        'missing. {1}'
                    ) -f $script:UnavailableValue, $signInFailureCause
                )
            }
        }
    }

    #endregion Enrich matched SA accounts

    #region Build report

    $now = (Get-Date).ToUniversalTime()

    $report = @(
        foreach ($pair in $pairs)
        {
            $saUser = $pair.SaUser

            $lastSignIn      = $null
            $lastSignInText  = $script:UnavailableValue
            $daysSinceSignIn = $null

            if ($signInAvailable)
            {
                if ($signInCache.ContainsKey($saUser.Id))
                {
                    $lastSignIn = $signInCache[$saUser.Id]
                }

                if ($null -eq $lastSignIn)
                {
                    $lastSignInText = $script:NeverValue
                }
                else
                {
                    $lastSignInUtc  = $lastSignIn.ToUniversalTime()
                    $lastSignInText = $lastSignInUtc.ToString('yyyy-MM-dd HH:mm:ss') + 'Z'

                    $daysSinceSignIn = [int][math]::Floor(
                        ($now - $lastSignInUtc).TotalDays
                    )
                }
            }

            $roleText = $script:UnavailableValue

            if ($rolesAvailable)
            {
                if ($roleMap.ContainsKey($saUser.Id))
                {
                    $roleText = (
                        $roleMap[$saUser.Id] |
                            Sort-Object -Unique
                    ) -join '; '
                }
                else
                {
                    $roleText = $script:NoneValue
                }
            }

            [pscustomobject][ordered]@{
                UserPrincipalName   = $pair.SourceUpn
                SAUserPrincipalName = $saUser.UserPrincipalName
                SADisplayName       = $saUser.DisplayName
                SALastSignIn        = $lastSignInText
                SADaysSinceSignIn   = $daysSinceSignIn
                SADirectoryRoles    = $roleText
            }
        }
    )

    $report = @(
        $report |
            Sort-Object -Property UserPrincipalName, SAUserPrincipalName
    )

    #endregion Build report

    #region Export report

    if ($PSCmdlet.ShouldProcess($resolvedOutputPath, 'Write CSV report'))
    {
        try
        {
            if ($report.Count -gt 0)
            {
                $report |
                    Export-Csv `
                        -LiteralPath $resolvedOutputPath `
                        -NoTypeInformation `
                        -Encoding UTF8
            }
            else
            {
                # Write a header-only CSV when no matching pairs are found.
                $emptyRow = [pscustomobject][ordered]@{
                    UserPrincipalName   = $null
                    SAUserPrincipalName = $null
                    SADisplayName       = $null
                    SALastSignIn        = $null
                    SADaysSinceSignIn   = $null
                    SADirectoryRoles    = $null
                }

                $csvHeader = @($emptyRow | ConvertTo-Csv -NoTypeInformation)[0]

                Set-Content `
                    -LiteralPath $resolvedOutputPath `
                    -Value $csvHeader `
                    -Encoding UTF8
            }
        }
        catch
        {
            throw (
                "The report could not be written to '{0}'. {1}" -f
                $resolvedOutputPath,
                $_.Exception.Message
            )
        }
    }

    #endregion Export report

    #region Return results

    $summary = [pscustomobject][ordered]@{
        OutputPath              = $resolvedOutputPath
        TenantId                = $graphContext.TenantId
        Account                 = $graphContext.Account
        TotalUsersRetrieved     = $allUsers.Count
        DisabledAccountsFound   = $disabledUsers.Count
        SACandidatesFound       = $saCandidates.Count
        MatchedDisabledAccounts = $matchedSourceCount
        ReportRowCount          = $report.Count
        SkippedIncompleteNames  = $skippedSourceCount + $skippedCandidateCount
        SignInDataAvailable     = $signInAvailable
        DirectoryRolesAvailable = $rolesAvailable
    }

    if ($PassThru)
    {
        $report
    }
    else
    {
        $summary
    }

    #endregion Return results
}
finally
{
    if ($script:ConnectedByScript)
    {
        Write-Verbose 'Disconnecting from Microsoft Graph.'

        try
        {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch
        {
            Write-Verbose 'Disconnect-MgGraph reported an error and was ignored.'
        }
    }
}
