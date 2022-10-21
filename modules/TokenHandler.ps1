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
        $Resource = "https://graph.microsoft.com",
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser,
        [Parameter(Mandatory=$False)]
        [String]
        $CaptureCode
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    if($Client -eq "Outlook") {

        $body=@{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" =  "https://outlook.office365.com"
        }
    }
    elseif ($Client -eq "Substrate") {

        $body=@{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" =  "https://substrate.office.com"
        }
    }
    elseif ($Client -eq "Yammer") {

        $body=@{
            "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" =  "https://www.yammer.com"
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
            "resource" =      "https://api.spaces.skype.com"   
        }
    }
    elseif ($Client -eq "Graph") {
        
        $body = @{
            "client_id" =     "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" =      "https://graph.windows.net"  
        }
    }
    elseif ($Client -eq "MSGraph") {
        
        $body = @{
            "client_id" =     "d3590ed6-52b3-4102-aeff-aad2292ab01c"
            "resource" =      "https://graph.microsoft.com"  
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
            "resource" =      "https://management.core.windows.net"
        }
    }
    elseif ($Client -eq "AzureManagement") {
        
        $body = @{
            "client_id" =     "84070985-06ea-473d-82fe-eb82b4011c9d"
            "resource" =      "https://management.azure.com"
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
                
                $output = Parse-JWTtoken -token $jwt
                $global:upn = $output.upn
                write-output $upn
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
                
                $output = Parse-JWTtoken -token $jwt
                $global:upn = $output.upn
                write-output $upn
                break
            }
        }
    }
}
# Refresh Token Functions
function RefreshTo-SubstrateToken {
    <#
    .DESCRIPTION
        Generate a Substrate token from a refresh token.
    .EXAMPLE
        RefreshTo-SubstrateToken -domain myclient.org -refreshToken ey....
        $SubstrateToken.access_token
    #>

    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://substrate.office.com"
    $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
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
function RefreshTo-YammerToken {
    <#
    .DESCRIPTION
        Generate a Substrate token from a refresh token.
    .EXAMPLE
        RefreshTo-SubstrateToken -domain myclient.org -refreshToken ey....
        $SubstrateToken.access_token
    #>

    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://www.yammer.com"
    $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
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
function RefreshTo-MSManageToken {
    <#
    .DESCRIPTION
        Generate a manage token from a refresh token.
    .EXAMPLE
        RefreshTo-MSManage -domain myclient.org -refreshToken ey....
        $MSManageToken.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://enrollment.manage.microsoft.com"
    $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
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
function RefreshTo-MSTeamsToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Teams token from a refresh token.
    .EXAMPLE
        RefreshTo-MSTeamsToken -domain myclient.org -refreshToken ey....
        $MSTeamsToken.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://api.spaces.skype.com"
    $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
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
function RefreshTo-OfficeManagementToken {
    <#
    .DESCRIPTION
        Generate a Office Manage token from a refresh token.
    .EXAMPLE
        RefreshTo-OfficeManagementToken -domain myclient.org -refreshToken ey....
        $OfficeManagement.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://manage.office.com"
    $ClientId = "00b41c95-dab0-4487-9791-b9d2c32c80f2"
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
function RefreshTo-OutlookToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Outlook token from a refresh token.
    .EXAMPLE
        RefreshTo-OutlookToken -domain myclient.org -refreshToken ey....
        $OutlookToken.access_token
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$domain,
    [Parameter(Mandatory=$false)]
    [string]$refreshToken = $response.refresh_token,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
    [String]$Device,
    [Parameter(Mandatory=$False)]
    [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
    [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://outlook.office365.com"
    $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
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
function RefreshTo-MSGraphToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Graph token from a refresh token.
    .EXAMPLE
        RefreshTo-MSGraphToken -domain myclient.org -refreshToken ey....
        $MSGraphToken.access_token
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
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
      
    $Resource = "https://graph.microsoft.com"
    $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
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
function RefreshTo-GraphToken {
    <#
    .DESCRIPTION
        Generate a windows graph token from a refresh token.
    .EXAMPLE
        RefreshTo-GraphToken -domain myclient.org -refreshToken ey....
        $GraphToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
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
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://graph.windows.net"
    $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
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
function RefreshTo-OfficeAppsToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Office Apps token from a refresh token.
    .EXAMPLE
        RefreshTo-OfficeAppsToken -domain myclient.org -refreshToken ey....
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
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent

    $Resource = "https://officeapps.live.com"
    $ClientId = "ab9b8c07-8f02-4f72-87fa-80105867a763"
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
function RefreshTo-AzureCoreManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Core Mangement token from a refresh token.
    .EXAMPLE
        RefreshTo-AzureCoreManagementToken -domain myclient.org -refreshToken ey....
        $AzureCoreManagementToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$domain,
        [Parameter(Mandatory=$false)]
        [string]$refreshToken = $response.refresh_token,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://management.core.windows.net"
    $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
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
function RefreshTo-AzureManagementToken {
    <#
    .DESCRIPTION
        Generate a Microsoft Azure Mangement token from a refresh token.
    .EXAMPLE
        RefreshTo-AzureManagementToken -domain myclient.org -refreshToken ey....
        $AzureManagementToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$domain,
        [Parameter(Mandatory=$false)]
        [string]$refreshToken = $response.refresh_token,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://management.azure.com"
    $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
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
function RefreshTo-MAMToken {
    <#
    .DESCRIPTION
        Generate a Microsoft intune mam token from a refresh token.
    .EXAMPLE
        RefreshTo-MAMToken -domain myclient.org -refreshToken ey....
        $MAMToken.access_token
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$domain,
        [Parameter(Mandatory=$false)]
        [string]$refreshToken = $response.refresh_token,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    if ($Device) {
		if ($Browser) {
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
    $Resource = "https://intunemam.microsoftonline.com"
    $ClientId = "6c7e8096-f593-4d72-807f-a5f86dcc9c77"
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
function RefreshTo-DODMSGraphToken {
    <#
    .DESCRIPTION
        Generate a Microsoft DOD Graph token from a refresh token.
    .EXAMPLE
        RefreshTo-DODMSGraphToken -domain myclient.org -refreshToken ey....
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
			$UserAgent = Forge-UserAgent -Device $Device -Browser $Browser
		}
		else {
			$UserAgent = Forge-UserAgent -Device $Device
		}
	}
	else {
	   if ($Browser) {
			$UserAgent = Forge-UserAgent -Browser $Browser 
	   } 
	   else {
			$UserAgent = Forge-UserAgent
	   }
	}    
    $Headers=@{}
    $Headers["User-Agent"] = $UserAgent
      
    $Resource = "https://dod-graph.microsoft.us"
    $ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
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
function Clear-Token {
    <#
    .DESCRIPTION
        Clear or "Null" your tokens.
    .EXAMPLE
        Clear-Token -Token All
        Clear-Token -Token Substrate
    #>
    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [ValidateSet("All","Response","Outlook","MSTeams","Graph","AzureCoreManagement","OfficeManagement","MSGraph","DODMSGraph","Custom","Substrate")]
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
}