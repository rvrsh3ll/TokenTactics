# Print the welcome message
$manifest = Import-PowerShellDataFile "$PSScriptRoot\TokenTactics.psd1"
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle="TokenTactics $version"

$banner=@"
___  __        ___      ___       __  ___    __   __  
 |  /  \ |__/ |__  |\ |  |   /\  /  `  |  | /  ` /__` 
 |  \__/ |  \ |___ | \|  |  /~~\ \__,  |  | \__, .__/ 
"@
Write-Host $logo -ForegroundColor Red

# Load the .ps1 scripts
#$scripts = @(Get-ChildItem -Path $PSScriptRoot\*.ps1 -ErrorAction SilentlyContinue)
$scripts = @(Get-ChildItem -Path $PSScriptRoot\modules\*.ps1 -ErrorAction SilentlyContinue)
$c = 0
foreach ($script in $scripts) {
    Write-Progress -Activity "Importing script" -Status $script -PercentComplete (($c++/$scripts.count)*100) 
    try {
        . $script.FullName
    } catch {
        Write-Error "Failed to import $($script.FullName): $_"
    }
}
# Export functions
$functions=@(
    # helpers.ps1
    "Invoke-ParseJWTtoken"
    "Invoke-GetTenantID"
    # TokenHandler.ps1
    "Get-AzureToken"
    "Invoke-RefreshToSubstrateToken"
    "Invoke-RefreshToMSManageToken"
    "Invoke-RefreshToMSTeamsToken"
    "Invoke-RefreshToOfficeManagementToken"
    "Invoke-RefreshToOutlookToken"
    "Invoke-RefreshToMSGraphToken"
    "Invoke-RefreshToGraphToken"
    "Invoke-RefreshToOfficeAppsToken"
    "Invoke-RefreshToAzureCoreManagementToken"
    "Invoke-RefreshToAzureManagementToken"
    "Invoke-RefreshToMAMToken"
    "Invoke-RefreshToDODMSGraphToken"
    "Invoke-RefreshToO365SuiteUXToken"
    "Invoke-RefreshToYammerToken"
    "Invoke-RefreshToSharepointOnlineToken"
    "Invoke-ClearToken"
    # CapBypass.ps1
    "Invoke-ForgeUserAgent"
    # OutlookEmailAbuse.ps1
    "Invoke-OpenOWAMailboxInBrowser"
    "Invoke-DumpOWAMailboxViaMSGraphApi"
)
$c = 0
foreach($function in $functions)
{
    Write-Progress -Activity "Exporting function" -Status $function -PercentComplete (($c++/$functions.count)*100)
    Export-ModuleMember -Function $function
}
