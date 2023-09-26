# TokenTactics
Azure JSON Web Token ("JWT") Manipulation Toolset

Azure access tokens allow you to authenticate to certain endpoints as a user who signs in with a device code. Even if they used multi-factor authentication. Once you have a user's access token, it may be possible to access certain apps such as Outlook, SharePoint, OneDrive, MSTeams and more. 

For instance, if you have a Graph or MSGraph token, you can then connect to Azure and dump users, groups, etc. You could then, depending on conditional access policies, switch to an Azure Core Management token and run [AzureHound](https://github.com/BloodHoundAD/AzureHound). Then, switch to an Outlook token and read/send emails or MS Teams and read/send messages!

For more on Azure token types [Microsoft identity platform access tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens)

There are some example requests to endpoints in the resources folder. There is also an example phishing template for device code phishing.

You may also use these tokens with [AAD Internals](https://o365blog.com/aadinternals/) as well. We strongly recommended to check this amazing tool out.

## Installation and Usage

```Import-Module .\TokenTactics.psd1```

```Get-Help Get-AzureToken```

```Invoke-RefreshToSubstrateToken```

### Generate Device Code

```Get-AzureToken -Client MSGraph```
Once the user has logged in, you'll be presented with the JWT and it will be saved in the $response variable. To access the access token use ```$response.access_token``` from your PowerShell window to display the token. You may also display the refresh token with ```$response.refresh_token```. Hint: You'll want the refresh token to keep refreshing to new access tokens! By default, Get-AzureToken results are logged to TokenLog.log.

#### DOD/Mil Device Code
```Get-AzureToken -Client DODMSGraph```

### Refresh or Switch Tokens

```Invoke-RefreshToOutlookToken -domain myclient.org -refreshToken 0.A```

```$OutlookToken.access_token```

### Connect
```Connect-AzureAD -AadAccessToken $response.access_token -AccountId user@myclient.org```

### Refresh a PRT

Once a PRT has been captured, auth with roadrecon to obtain your access_token and refresh_token. When refreshing with TokenTactics, use ClientID 1b730954-1685-4b74-9bfd-dac224a7b894.

```Invoke-RefreshToMSGraphToken -domain myclient.org -ClientId 1b730954-1685-4b74-9bfd-dac224a7b894 -refreshToken 0.A```

### Clear tokens
```Invoke-ClearToken -Token All```

### Commands
```powershell
Get-Command -Module TokenTactics

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Invoke-ClearToken                                        0.0.2      TokenTactics
Function        Invoke-DumpOWAMailboxViaMSGraphApi                       0.0.2      TokenTactics
Function        Invoke-ForgeUserAgent                                    0.0.2      TokenTactics
Function        Get-AzureToken                                           0.0.2      TokenTactics
Function        Get-TenantID                                             0.0.2      TokenTactics
Function        Invoke-OpenOWAMailboxInBrowser                           0.0.2      TokenTactics
Function        Invoke-ParseJWTtoken                                     0.0.2      TokenTactics
Function        Invoke-RefreshToAzureCoreManagementToken                 0.0.2      TokenTactics
Function        Invoke-RefreshToAzureManagementToken                     0.0.2      TokenTactics
Function        Invoke-RefreshToDODMSGraphToken                          0.0.2      TokenTactics
Function        Invoke-RefreshToGraphToken                               0.0.2      TokenTactics
Function        Invoke-RefreshToMAMToken                                 0.0.2      TokenTactics
Function        Invoke-RefreshToMSGraphToken                             0.0.2      TokenTactics
Function        Invoke-RefreshToMSManageToken                            0.0.2      TokenTactics
Function        Invoke-RefreshToMSTeamsToken                             0.0.2      TokenTactics
Function        Invoke-RefreshToO365SuiteUXToken                         0.0.2      TokenTactics
Function        Invoke-RefreshToOfficeAppsToken                          0.0.2      TokenTactics
Function        Invoke-RefreshToOfficeManagementToken                    0.0.2      TokenTactics
Function        Invoke-RefreshToOutlookToken                             0.0.2      TokenTactics
Function        Invoke-RefreshToSubstrateToken                           0.0.2      TokenTactics
Function        Invoke-RefreshToYammerToken                              0.0.2      TokenTactics
```

## Authors and contributors
- [@0xBoku](https://github.com/boku7) co-author and researcher.

TokenTactic's methods are highly influenced by the great research of Dr Nestori Syynimaa at https://o365blog.com/.

