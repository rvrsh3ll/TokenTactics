# Helper Functions
function Get-TenantID
{
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Domain',Mandatory=$True)]
        [String]$domain
    )
    Process
    {
        $openIdConfig=Invoke-RestMethod "https://login.microsoftonline.com/$domain/.well-known/openid-configuration"
        $TenantId = $OpenIdConfig.authorization_endpoint.Split("/")[3]
        return $TenantId
    }
}


function Invoke-ParseJWTtoken {
    <#
    .DESCRIPTION
        Parse JWTtoken code from https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
    .EXAMPLE
        Invoke-ParseJWTtoken -Token ey....
    #>
    [cmdletbinding()]
    param([Parameter(Mandatory=$true)][string]$token)
 
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }

    $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/')

    while ($tokenheader.Length % 4) { 
		$tokenheader += "=" 
	}
    [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json | fl | Out-Default
 
    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
	
    while ($tokenPayload.Length % 4) { 
		$tokenPayload += "=" 
	}

    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)

    $tokobj = $tokenArray | ConvertFrom-Json
    return $tokobj
}
