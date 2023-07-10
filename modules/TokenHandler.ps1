function Get-AzureToken {
    
    <#
    .DESCRIPTION
        Generate a device code to be used at https://www.microsoft.com/devicelogin. Once a user has successfully authenticated, you will be presented with a JSON Web Token JWT in the variable $response.
    .EXAMPLE
        Get-AzureToken -Client Substrate
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String[]]
        [ValidateSet("Yammer","Outlook","MSTeams","Graph","AzureCoreManagement","AzureManagement","MSGraph","DODMSGraph","Custom","Substrate")]
        $Client,
        [Parameter(Mandatory=$False)]
        [String]
        $ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",    
        [Parameter(Mandatory=$False)]
        [String]
        $Resource = "https://graph.microsoft.com/",
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser,
        [Parameter(Mandatory=$False)]
        [String]
        $CaptureCode,
        [Parameter(Mandatory=$False)]
        [String]
        $LogFile = "TokenLog.log"
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    if($Client -eq "Outlook") {

        $body=@{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" =  "https://outlook.office365.com/"
        }
    }
    elseif ($Client -eq "Substrate") {

        $body=@{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" =  "https://substrate.office.com/"
        }
    }
    elseif ($Client -eq "Yammer") {

        $body=@{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" =  "https://www.yammer.com/"
        }
    }        
    elseif ($Client -eq "Custom") {

        $body=@{
            "client_id" = $ClientID
            "resource" =  $Resource
        }
    }
    elseif ($Client -eq "MSTeams") {
        
        $body = @{
            "client_id" =     "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" =      "https://api.spaces.skype.com/"   
        }
    }
    elseif ($Client -eq "Graph") {
        
        $body = @{
            "client_id" =     "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" =      "https://graph.windows.net/"  
        }
    }
    elseif ($Client -eq "MSGraph") {
        
        $body = @{
            "client_id" =     "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" =      "https://graph.microsoft.com/"  
        }
    }
    elseif ($Client -eq "DODMSGraph") {
        
        $body = @{
            "client_id" =     "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" =      "https://dod-graph.microsoft.us"  
        }
    }   
    elseif ($Client -eq "AzureCoreManagement") {
        
        $body = @{
            "client_id" =     "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" =      "https://management.core.windows.net/"
        }
    }
    elseif ($Client -eq "AzureManagement") {
        
        $body = @{
            "client_id" =     "84070985-06ea-473d-82fe-eb82b4011c9d"
            "resource" =      "https://management.azure.com/"
        }
    }     
    if ($client -match "DOD") {
        # DOD Login Process
        $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.us/common/oauth2/devicecode?api-version=1.0" -Headers $Headers -Body $body
        write-output $authResponse
        $continue = $true
        $interval = $authResponse.interval
        $expires =  $authResponse.expires_in
        if ($CaptureCode){
            $body=@{
                "client_id" =  $ClientID
                "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
                "code" =       $CaptureCode
            } 
        } else {
            $body=@{
                "client_id" =  $ClientID
                "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
                "code" =       $authResponse.device_code
            }
        }
        while($continue)
        {
            Start-Sleep -Seconds $interval
            $total += $interval

            if($total -gt $expires)
            {
                Write-Error "Timeout occurred"
                return
            }          
            # Try to get the response. Will give 40x while pending so we need to try&catch
            try
            {
                $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.us/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $body -ErrorAction SilentlyContinue
            }
            catch
            {
                # This is normal flow, always returns 40x unless successful
                $details=$_.ErrorDetails.Message | ConvertFrom-Json
                $continue = $details.error -eq "authorization_pending"
                Write-Output $details.error

                if(!$continue)
                {
                    # Not pending so this is a real error
                    Write-Error $details.error_description
                    return
                }
            }

            # If we got response, all okay!
            if($response)
            {
                write-output $response
                $jwt = $response.access_token
                
                $output = Invoke-ParseJWTtoken -token $jwt
                $global:upn = $output.upn
                write-output $upn
                "------- Tokens -------" |Out-File -Append $LogFile
                $response.access_token |Out-File -Append $LogFile
                $response.refresh_token |Out-File -Append $LogFile
                break
            }
        }
    }

    else {
        # Login Process
        $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" -Headers $Headers -Body $body -ErrorAction SilentlyContinue
        write-output $authResponse
        $continue = $true
        $interval = $authResponse.interval
        $expires =  $authResponse.expires_in
        if ($CaptureCode){
            $body=@{
                "client_id" =  $ClientID
                "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
                "code" =       $CaptureCode
            } 
        }
        else {
            $body=@{
                "client_id" =  $ClientID
                "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
                "code" =       $authResponse.device_code
            }
        }
        
        while($continue)
        {
            Start-Sleep -Seconds $interval
            $total += $interval

            if($total -gt $expires)
            {
                Write-Error "Timeout occurred"
                return
            }          
            # Try to get the response. Will give 40x while pending so we need to try&catch
            try
            {
                $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" -Headers $Headers -Body $body -ErrorAction SilentlyContinue
            }
            catch
            {
                # This is normal flow, always returns 40x unless successful
                $details=$_.ErrorDetails.Message | ConvertFrom-Json
                $continue = $details.error -eq "authorization_pending"
                Write-Output $details.error

                if(!$continue)
                {
                    # Not pending so this is a real error
                    Write-Error $details.error_description
                    return
                }
            }

            # If we got response, all okay!
            if($response)
            {
                write-output $response
                $jwt = $response.access_token
                
                $output = Invoke-ParseJWTtoken -token $jwt
                $global:upn = $output.upn
                write-output $upn
                "------- Tokens -------" |Out-File -Append $LogFile
                $response.access_token |Out-File -Append $LogFile
                $response.refresh_token |Out-File -Append $LogFile
                break
            }
        }
    }
}
function Get-AzureTokenFromESTSCookie { 

    <#
    .DESCRIPTION
        Authenticate to an application (default graph.microsoft.com) using Authorization Code flow.
        Authenticates to MSGraph as Teams FOCI client by default.

        NOTE: This may require user interaction and may not work this way. 
            In that case, use device code flow or `roadtx interactiveauth`

    .EXAMPLE
        Get-AzureTokenFromESTSCookie -Client MSTeams -estsAuthCookie "0.AbcAp.."
    #>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String[]]
        [ValidateSet("MSTeams","MSEdge","AzurePowershell")]
        $Client = "MSTeams",
        [Parameter(Mandatory=$True)]
        [String[]]
        $estsAuthCookie,
        [Parameter(Mandatory=$False)]
        [String]
        $Resource = "https://graph.microsoft.com/",
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )

    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}


   if($Client -eq "MSTeams") {
        $client_id = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    }
    elseif ($Client -eq "MSEdge") {
        $client_id = "ecd6b820-32c2-49b6-98a6-444530e5a77a"
    }
    elseif ($Client -eq "AzurePowershell") {
        $client_id = "1950a258-227b-4e31-a9cf-717495945fc2"
    }
    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent

    $cookie = "ESTSAUTHPERSISTENT=$($estsAuthCookie)"
    $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $cookie = [System.Net.Cookie]::new("ESTSAUTHPERSISTENT", "$($estsAuthCookie)")
    $session.Cookies.Add('https://login.microsoftonline.com/', $cookie)

    $state = [System.Guid]::NewGuid().ToString()
    $redirect_uri = ([System.Uri]::EscapeDataString("https://login.microsoftonline.com/common/oauth2/nativeclient"))

	if ($PSVersionTable.PSVersion.Major -lt 7) { 
		$sts_response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=$($client_id)&resource=$($Resource)&redirect_uri=$($redirect_uri)&state=$($state)" -Headers $Headers
	}
	
	else {
		$sts_response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=$($client_id)&resource=$($Resource)&redirect_uri=$($redirect_uri)&state=$($state)" -Headers $Headers
	} 

    if ($sts_response.StatusCode -eq 302) {

		if ($PSVersionTable.PSVersion.Major -lt 7) {
			$uri = [System.Uri]$sts_response.Headers.Location
		}
		
		else { $uri = [System.Uri]$sts_response.Headers.Location[0] }

        $query = $uri.Query.TrimStart('?')

        $queryParams = @{}
        $paramPairs = $query.Split('&')

        foreach ($pair in $paramPairs) {
            $parts = $pair.Split('=')
            $key = $parts[0]
            $value = $parts[1]
            $queryParams[$key] = $value
        }

        if ($queryParams.ContainsKey('code')) {
            $refreshToken = $queryParams['code']
        } else {
            Write-Host "[-] Code not found in redirected URL path"
            Write-Host "    Requested URL: https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=$($client_id)&resource=$($Resource)&redirect_uri=$($redirect_uri)&state=$($state)"
            Write-Host "    Response Code: $($sts_response.StatusCode)"
            Write-Host "    Response URI: $($sts_response.Headers.Location)"
            return
        }

    } else {
            Write-Host "[-] Expected 302 redirect but received other status"
            Write-Host "    Requested URL: https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=$($client_id)&resource=$($Resource)&redirect_uri=$($redirect_uri)&state=$($state)"
            Write-Host "    Response Code: $($sts_response.StatusCode)"
            Write-Host "[-] The request may require user interation to complete, or the provided cookie is invalid"
            return
    }

    if ($refreshToken){ 

        $body = @{
            "resource" =      $Resource
            "client_id" =     $client_id
            "grant_type" =    "authorization_code"
            "redirect_uri" = "https://login.microsoftonline.com/common/oauth2/nativeclient"
            "code" = $refreshToken
            "scope" = "openid"
        }

        $global:response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/token" -Headers $Headers -Body $body
        Write-Output $response
        
    } 

}

# Refresh Token Functions
function Invoke-RefreshToSubstrateToken {
    <#
    .DESCRIPTION
        Generate a Substrate token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToSubstrateToken -domain myclient.org -refreshToken ey....
        $SubstrateToken.access_token
    #>

    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$False)]
    [String]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://substrate.office.com/"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    
    Write-Output $refreshToken
    $body = @{
        "resource" =      $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope" = "openid"
    }

    $global:SubstrateToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
    Write-Output $SubstrateToken
}
function Invoke-RefreshToYammerToken {
    <#
    .DESCRIPTION
        Generate a Substrate token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToSubstrateToken -domain myclient.org -refreshToken ey....
        $SubstrateToken.access_token
    #>

    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$False)]
    [String]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://www.yammer.com/"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    
    Write-Output $refreshToken
    $body = @{
        "resource" =      $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope" = "openid"
    }

    $global:YammerToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
    Write-Output $YammerToken
}
function Invoke-RefreshToMSManageToken {
    <#
    .DESCRIPTION
        Generate a manage token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMSManage -domain myclient.org -refreshToken ey....
        $MSManageToken.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$False)]
    [String]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://enrollment.manage.microsoft.com/"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    
    Write-Output $refreshToken
    $body = @{
        "resource" =      $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope" = "openid"
    }

    $global:MSManageToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
    Write-Output $MSManageToken
}
function Invoke-RefreshToMSTeamsToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Teams token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMSTeamsToken -domain myclient.org -refreshToken ey....
        $MSTeamsToken.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$False)]
    [String]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://api.spaces.skype.com/"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    
    Write-Output $refreshToken
    $body = @{
        "resource" =      $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope" = "openid"
    }

    $global:MSTeamsToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
    Write-Output $MSTeamsToken
}
function Invoke-RefreshToOfficeManagementToken {
    <#
    .DESCRIPTION
        Generate a Office Manage token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOfficeManagementToken -domain myclient.org -refreshToken ey....
        $OfficeManagement.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$False)]
    [String]$ClientId = "00b41c95-dab0-4487-9791-b9d2c32c80f2",
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://manage.office.com/"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    $global:refreshToken = $response.refresh_token 
    
    $body = @{
        "resource" = $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope"=         "openid"
    }

    $global:OfficeManagementToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
    Write-Output $OfficeManagementToken
}
function Invoke-RefreshToOutlookToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Outlook token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOutlookToken -domain myclient.org -refreshToken ey....
        $OutlookToken.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$False)]
    [String]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://outlook.office365.com/"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    $global:refreshToken = $response.refresh_token 
    
    $body = @{
        "resource" = $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope"=         "openid"
    }

    $global:OutlookToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
    Write-Output $OutlookToken
}
function Invoke-RefreshToMSGraphToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Graph token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMSGraphToken -domain myclient.org -refreshToken ey....
        $MSGraphToken.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$False)]
    [String]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
      
    $Resource = "https://graph.microsoft.com/"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    $global:refreshToken = $response.refresh_token 
    
    $body = @{
        "resource" = $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope"=         "openid"
    }

    $global:MSGraphToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
    Write-Output $MSGraphToken
}
function Invoke-RefreshToGraphToken {
    <#
    .DESCRIPTION
        Generate a windows graph token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToGraphToken -domain myclient.org -refreshToken ey....
        $GraphToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$domain,
        [Parameter(Mandatory=$false)]
        [string]$refreshToken = $response.refresh_token,
        [Parameter(Mandatory=$False)]
        [String]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://graph.windows.net/"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.com/$($TenantId)"

    Write-Output $refreshToken
    $body = @{
        "resource" =      $Resource
       "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope"=         "openid"
    }
    $global:GraphToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
    Write-Output $GraphToken
}
function Invoke-RefreshToOfficeAppsToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Office Apps token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToOfficeAppsToken -domain myclient.org -refreshToken ey....
        $OfficeAppsToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$domain,
        [Parameter(Mandatory=$false)]
        [string]$refreshToken = $response.refresh_token,
        [Parameter(Mandatory=$false)]
        [string]$ClientID = "ab9b8c07-8f02-4f72-87fa-80105867a763",
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent

    $Resource = "https://officeapps.live.com/"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    $global:refreshToken = $response.refresh_token
    Write-Output $refreshToken
    $body2 = @{
        "resource" =      $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope"=         "openid"
    }
    
    $global:OfficeAppsToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body2
    Write-Output $OfficeAppsToken
}
function Invoke-RefreshToAzureCoreManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Core Mangement token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureCoreManagementToken -domain myclient.org -refreshToken ey....
        $AzureCoreManagementToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$domain,
        [Parameter(Mandatory=$false)]
        [string]$refreshToken = $response.refresh_token,
        [Parameter(Mandatory=$False)]
        [String]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://management.core.windows.net/"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    $global:refreshToken = $response.refresh_token 
    Write-Output $refreshToken
    $body = @{
        "resource" =      $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope"=         "openid"
    }

    $global:AzureCoreManagementToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
    Write-Output $AzureCoreManagementToken
}
function Invoke-RefreshToAzureManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Mangement token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToAzureManagementToken -domain myclient.org -refreshToken ey....
        $AzureManagementToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$domain,
        [Parameter(Mandatory=$false)]
        [string]$refreshToken = $response.refresh_token,
        [Parameter(Mandatory=$False)]
        [String]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://management.azure.com/"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    $global:refreshToken = $response.refresh_token 
    Write-Output $refreshToken
    $body = @{
        "resource" =      $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope"=         "openid"
    }

    $global:AzureManagementToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
    Write-Output $AzureManagementToken
}
function Invoke-RefreshToMAMToken {
    <#
    .DESCRIPTION
        Generate a Microsoft intune mam token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToMAMToken -domain myclient.org -refreshToken ey....
        $MAMToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$domain,
        [Parameter(Mandatory=$false)]
        [string]$refreshToken = $response.refresh_token,
        [Parameter(Mandatory=$False)]
        [String]$ClientId = "6c7e8096-f593-4d72-807f-a5f86dcc9c77",
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://intunemam.microsoftonline.com/"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    $global:refreshToken = $response.refresh_token 
    Write-Output $refreshToken
    $body = @{
        "resource" =      $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope"=         "openid"
    }

    $global:MAMToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
    Write-Output $MamToken
}
function Invoke-RefreshToDODMSGraphToken {
    <#
    .DESCRIPTION
        Generate a Microsoft DOD Graph token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToDODMSGraphToken -domain myclient.org -refreshToken ey....
        $DODMSGraphToken.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$false)]
    [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
      
    $Resource = "https://dod-graph.microsoft.us"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.us/$($TenantId)"
    $global:refreshToken = $response.refresh_token 
    
    $body = @{
        "resource" = $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope"=         "openid"
    }

    $global:DODMSGraphToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body
    Write-Output $DODMSGraphToken
}
function Invoke-RefreshToSharepointOnlineToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Sharepoint Online token from a refresh token.
    .EXAMPLE
        Invoke-RefreshToSharepointOnlineToken -domain myclient.org -spoDomain myclient.sharepoint.com -refreshToken ey....
        $SPOToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$domain,
        [Parameter(Mandatory=$true)]
        [string]$spoDomain,
        [Parameter(Mandatory=$false)]
        [string]$refreshToken = $response.refresh_token,
        [Parameter(Mandatory=$false)]
        [string]$ClientID = "ab9b8c07-8f02-4f72-87fa-80105867a763",
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Invoke-ForgeUserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Invoke-ForgeUserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent

    $Resource = "https://$($spoDomain)/"
    $TenantId = Get-TenantID -domain $domain
    $authUrl = "https://login.microsoftonline.com/$($TenantId)"
    $global:refreshToken = $response.refresh_token
    Write-Output $refreshToken
    $body2 = @{
        "resource" =      $Resource
        "client_id" =     $ClientId
        "grant_type" =    "refresh_token"
        "refresh_token" = $refreshToken
        "scope"=         "openid"
    }
    
    $global:SPOToken = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$($authUrl)/oauth2/token?api-version=1.0" -Headers $Headers -Body $body2
    Write-Output $SPOToken
}
function Invoke-ClearToken {
    <#
    .DESCRIPTION
        Clear or "Null" your tokens.
    .EXAMPLE
        Invoke-ClearToken -Token All
        Invoke-ClearToken -Token Substrate
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [ValidateSet("All","Response","Outlook","MSTeams","Graph","AzureCoreManagement","OfficeManagement","MSGraph","DODMSGraph","Custom","Substrate","Yammer")]
    [string]$Token
    )
    if ($Token -eq "All") {

        $global:response = $null
        $global:OutlookToken = $null
        $global:MSTeamsToken = $null
        $global:GraphToken = $null
        $global:AzureCoreManagementToken = $null
        $global:OfficeManagementToken = $null
        $global:MSGraphToken = $null
        $global:DODMSGraphToken = $null
        $global:CustomToken = $null
        $global:SubstrateToken = $null
        $global:YammerToken = $null

    }
    elseif ($Token -eq "Response") {
        $global:response = $null
    }
    elseif ($Token -eq "MSTeams") {
        $global:MSTeamsToken = $null
    }
    elseif ($Token -eq "Graph") {
        $global:GraphToken = $null
    }
    elseif ($Token -eq "AzureCoreManagement") {
        $global:AzureCoreManagementToken = $null
    }
    elseif ($Token -eq "OfficeManagement") {
        $global:OfficeManagementToken = $null
    }
    elseif ($Token -eq "MSGraph") {
        $global:MSGraphToken = $null
    }
    elseif ($Token -eq "DODMSGraph") {
        $global:DODMSGraphToken = $null
    }
    elseif ($Token -eq "Custom") {
        $global:CustomToken = $null
    }
    elseif ($Token -eq "Substrate") {
        $global:SubstrateToken = $null
    }
    elseif ($Token -eq "Yammer") {
        $global:YammerToken = $null
    }
}