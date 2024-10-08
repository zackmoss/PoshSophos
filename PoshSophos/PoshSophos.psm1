
#region Core Functions

function Get-SophosCentralCredential {

    try {

        Write-Verbose -Message 'Retrieving Sophos API Credentials'

        if (!$Global:sophosClientID) {

            $Global:sophosClientID = Read-Host 'Enter Sophos Client ID (push ctrl + c to exit)'
        }

        if (!$Global:sophosClientSecret) {

            $Global:sophosClientSecret = Read-Host 'Enter Sophos Client Secret (push ctrl + c to exit)'
        }

        @{
            'ClientID'     = $Global:sophosClientID
            'ClientSecret' = $Global:sophosClientSecret
        }

        Write-Verbose -Message 'Retrieved API Credentials'
    }
    catch {

        Write-Error -Message 'Problem getting Sophos credential variables'
    }
}

function Connect-SophosCentral {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory, HelpMessage = 'The client ID from the Sophos Central API credential/service principal')]
        [String] $ClientID,

        [Parameter(HelpMessage = 'The client secret from the Sophos Central API credential/service principal')]
        [String] $ClientSecret
    )

    $currentProtocol = [Net.ServicePointManager]::SecurityProtocol

    if ($currentProtocol.ToString().Split(',').Trim() -notcontains 'Tls12') {

        [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
    }

    if ($null -eq $ClientSecret) {

        $ClientSecret = Read-Host -AsSecureString -Prompt 'Client Secret: '
    }

    $loginUri = 'https://id.sophos.com/api/v2/oauth2/token'

    $body = @{

        grant_type    = 'client_credentials'
        client_id     = $ClientID
        client_secret = $ClientSecret
        scope         = 'token'
    }

    try {

        $response = Invoke-WebRequest -Uri $loginUri -Body $body -ContentType 'application/x-www-form-urlencoded' -Method Post -UseBasicParsing
    }
    catch {

        throw 'Error requesting access token: {0}' -f $_
    }

    if ($response.Content) {

        $authDetails = $response.Content | ConvertFrom-Json
        $expiresAt = (Get-Date).AddSeconds($authDetails.expires_in - 60)


        $authDetails | Add-Member -MemberType NoteProperty -Name expires_at -Value $expiresAt
        $authDetails.access_token = $authDetails.access_token | ConvertTo-SecureString -AsPlainText -Force
        $Script:SophosCentral = $authDetails
    }

    $Script:SophosCentral
}

function New-SophosCentralHeaders {

    $sophosCredentials = Get-SophosCentralCredential

    $null = Connect-SophosCentral -ClientID $sophosCredentials.ClientID -ClientSecret $sophosCredentials.ClientSecret

    $Script:sophosHeaders = @{

        Authorization = 'Bearer ' + (Unprotect-Secret -Secret $Script:SophosCentral.access_token)
    }

    $tenantUri = 'https://api.central.sophos.com/whoami/v1'

    $tenantInfo = Invoke-RestMethod -Uri $tenantUri -Headers $Script:sophosHeaders -Method Get -UseBasicParsing

    $Script:SophosCentral | Add-Member -MemberType NoteProperty -Name GlobalEndpoint -Value $tenantInfo.apiHosts.global
    $Script:SophosCentral | Add-Member -MemberType NoteProperty -Name RegionEndpoint -Value $tenantInfo.apiHosts.dataRegion
    $Script:SophosCentral | Add-Member -MemberType NoteProperty -Name TenantID -Value $tenantInfo.id
    $Script:SophosCentral | Add-Member -MemberType NoteProperty -Name IDType -Value $tenantInfo.idType

    $Script:sophosHeaders.Add('X-Tenant-ID', $Script:SophosCentral.TenantID)
}

function Invoke-SophosCentralWebRequest {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [System.URI] $Uri,

        [ValidateSet('Get', 'Post', 'Put', 'Delete')]
        [string] $Method = 'Get',

        [System.Collections.Hashtable] $Body
    )

    $requestParams = @{
        Uri             = $uri
        Headers         = $Script:sophosHeaders
        UseBasicParsing = $true
        Method          = $Method
    }

    if ((!$Body) -and ($Method -in ('Post', 'Put'))) {

        $bodyTemp = @{} | ConvertTo-Json

        $requestParams.Add('Body', $bodyTemp)
    }
    elseif (($Body) -and ($Method -eq 'Get')) {

        $requestParams.Add('Body', $Body)
    }
    elseif ($Body) {

        $requestParams.Add('Body', ($Body | ConvertTo-Json -Depth 5))
    }

    if ($Method -notin ('Delete', 'Get')) {

        $requestParams.Add('ContentType', 'application/json')
    }

    try {

        $response = Invoke-RestMethod @requestParams

        if ($response.items) {

            $response.items
        }
        else {

            $response
        }
    }
    catch {

        $errorDetails = ConvertFrom-Json -InputObject $_.ErrorDetails.Message

        throw $errorDetails.message
    }


    $finished = $false

    do {
        if ($response.pages.nextKey) {

            if ($uri.AbsoluteUri -like '*`?*') {

                $requestParams['Uri'] = $uri.AbsoluteUri + '&pageFromKey=' + $response.pages.nextKey
            }
            else {

                $requestParams['Uri'] = $uri.AbsoluteUri + '?pageFromKey=' + $response.pages.nextKey
            }

            $response = Invoke-RestMethod @requestParams

            $response.items
        }
        elseif ($response.has_more) {

            if ($uri.AbsoluteUri -like '*`?*') {

                $requestParams['Uri'] = $uri.AbsoluteUri + '&cursor=' + $response.next_cursor
            }
            else {

                $requestParams['Uri'] = $uri.AbsoluteUri + '?cursor=' + $response.next_cursor
            }

            $response = Invoke-RestMethod @requestParams

            $response.items
        }
        else {

            $finished = $true
        }
    } while ($finished -eq $false)
}


#endregion

#region Helper Functions


function Invoke-UriBuilder {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [System.Uri] $Uri,

        [hashtable] $OriginalPsBoundParameters,

        [array] $FilteredParameters
    )

    New-SophosCentralHeaders

    $regionEndpoint = $Script:SophosCentral.RegionEndpoint

    $Uri = $regionEndpoint + $Uri

    $uriBuilder = [System.UriBuilder]::New($Uri.AbsoluteUri)

    $blockedParams = 'Verbose', 'Force', 'Debug', 'WhatIf' + $FilteredParameters

    $keys = $OriginalPsBoundParameters.Keys | Where-Object { $blockedParams -notcontains $_ }

    foreach ($param in $keys) {

        if (($OriginalPsBoundParameters[$param]) -and ($param)) {

            $paramToLower = $param.ToString()[0].ToString().ToLower() + $param.ToString().Substring(1)

            if ($OriginalPsBoundParameters[$param] -is [array]) {

                $queryBuilder = $paramToLower + '=' + ($OriginalPsBoundParameters[$param] -join ',')
            }
            else {

                if ($OriginalPsBoundParameters[$param].GetType().Name -eq 'DateTime') {

                    $OriginalPsBoundParameters[$param] = $OriginalPsBoundParameters[$param].ToUniversalTime().ToString('u').Replace(' ', 'T')
                }

                $queryBuilder = $paramToLower + '=' + $OriginalPsBoundParameters[$param]
            }
            if (($null -eq $uriBuilder.Query) -or ($uriBuilder.Query.Length -le 1 )) {

                $uriBuilder.Query = $queryBuilder
            }
            else {

                $uriBuilder.Query = $uriBuilder.Query.Substring(1) + '&' + $queryBuilder
            }
        }
    }

    [System.Uri]::New($uriBuilder.Uri)
}

function Unprotect-Secret {

    [CmdletBinding()]
    [OutputType([System.String])]
    param (

        [Parameter(Mandatory, HelpMessage = 'The Secure String to convert to plain text')]
        [SecureString] $Secret
    )

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
}


#endregion

#region Endpoint Functions


function Get-SophosCentralEndpoint {

    [CmdletBinding()]
    param (

        [ValidateSet('bad', 'good', 'suspicious', 'unknown')]
        [string[]] $HealthStatus,

        [ValidateSet('computer', 'server', 'securityVm')]
        [string[]] $Type,

        [System.Boolean] $TamperProtectionEnabled,

        [ValidateSet('creatingWhitelist', 'installing', 'locked', 'notInstalled', 'registering', 'starting', 'stopping', 'unavailable', 'uninstalled', 'unlocked')]
        [string[]] $LockdownStatus,

        [ValidateSet('isolated', 'notIsolated')]
        [string] $IsolationStatus,

        [ValidateSet('basic', 'summary', 'full')]
        [string] $View,

        [string] $HostnameContains,

        [string] $IpAddresses,

        [string] $MacAddresses,

        [string] $Search,

        [ValidateSet('hostname', 'groupName', 'associatedPersonName', 'ipAddress', 'osName')]
        [string] $SearchField = 'hostname',

        [datetime] $LastSeenBefore,

        [datetime] $LastSeenAfter,

        [ValidateScript({
                if ($false -eq [System.Guid]::TryParse($_, $([ref][guid]::Empty))) {
                    throw 'Not a valid GUID'
                }
                else {
                    return $true
                }
            })]
        [string[]] $ID
    )

    if ($ID.count -gt 0) {

        $PsBoundParameters.Add('ids', $PsBoundParameters['ID'])

        $null = $PsBoundParameters.Remove('ID')
    }

    $uriEndpoint = '/endpoint/v1/endpoints'

    $uri = Invoke-UriBuilder -Uri $uriEndpoint -OriginalPsBoundParameters $PsBoundParameters

    Invoke-SophosCentralWebRequest -Uri $uri
}

function Get-SophosCentralEndpointDetail {

    [CmdletBinding()]
    param (

        [ValidateSet('basic', 'summary', 'full')]
        [string] $View,

        [ValidateScript({
                if ($false -eq [System.Guid]::TryParse($_, $([ref][guid]::Empty))) {
                    throw 'Not a valid GUID'
                }
                else {
                    return $true
                }
            })]
        [string[]] $ID
    )

    if ($ID.count -gt 0) {

        $PsBoundParameters.Add('ids', $PsBoundParameters['ID'])

        $null = $PsBoundParameters.Remove('ID')
    }

    $uriEndpoint = ('/endpoint/v1/endpoints/{0}' -f $ID)

    $uri = Invoke-UriBuilder -Uri $uriEndpoint -OriginalPsBoundParameters $PsBoundParameters

    Invoke-SophosCentralWebRequest -Uri $uri
}

function Remove-SophosCentralEndpoint {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory, ValueFromPipelineByPropertyName = $True)]
        [Alias('ID')]
        [string[]] $EndpointId
    )

    begin {

    }

    process {

        foreach ($endpoint in $EndpointId) {

            $uriEndpoint = '/endpoint/v1/endpoints/{0}' -f $endpoint

            $uri = Invoke-UriBuilder -Uri $uriEndpoint

            Invoke-SophosCentralWebRequest -Uri $uri -Method Delete
        }
    }

    end {

    }
}


#endregion

#regoin SIEM Integration Functions


function Get-SophosCentralSiemEvents {

    [CmdletBinding()]
    param (

        # The starting date from which alerts will be retrieved defined as Unix timestamp in UTC. Ignored if cursor is set. Must be within last 24 hours.
        [datetime] $FromDate,

        [string] $ExcludedTypes,

        # The maximum number of items to return (per page), default is 200, max is 1000.
        [int] $Limit
    )

    $params = @{}

    if ($FromDate) {

        $params = @{

            from_date = $FromDate
        }
    }

    if ($ExcludedTypes) {

        $params += @{

            excluded_types = $ExcludedTypes
        }
    }

    $uriEndpoint = '/siem/v1/events'

    $uri = Invoke-UriBuilder -Uri $uriEndpoint -OriginalPsBoundParameters $params

    $response = Invoke-SophosCentralWebRequest -Uri $uri

    if ($response.created_at) {

        $response
    }
    else {

        Write-Host -Object 'No events found at this time'
    }
}

function Get-SophosCentralSiemAlerts {

    [CmdletBinding()]
    param (

        # The starting date from which alerts will be retrieved defined as Unix timestamp in UTC. Ignored if cursor is set. Must be within last 24 hours.
        [datetime] $FromDate,

        # The maximum number of items to return (per page), default is 200, max is 1000.
        [int] $Limit
    )

    $params = @{}

    if ($FromDate) {

        $params = @{

            from_date = $FromDate
        }
    }

    $uriEndpoint = '/siem/v1/alerts'

    $uri = Invoke-UriBuilder -Uri $uriEndpoint -OriginalPsBoundParameters $params

    $response = Invoke-SophosCentralWebRequest -Uri $uri

    if ($response.created_at) {

        $response
    }
    else {

        Write-Host -Object 'No alerts found at this time'
    }
}

#endregion
