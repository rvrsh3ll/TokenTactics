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
    "Parse-JWTtoken"
    "Get-TenantID"
    # TokenHandler.ps1
    "Get-AzureToken"
    "RefreshTo-SubstrateToken"
    "RefreshTo-MSManageToken"
    "RefreshTo-MSTeamsToken"
    "RefreshTo-OfficeManagementToken"
    "RefreshTo-OutlookToken"
    "RefreshTo-MSGraphToken"
    "RefreshTo-GraphToken"
    "RefreshTo-OfficeAppsToken"
    "RefreshTo-AzureCoreManagementToken"
    "RefreshTo-AzureManagementToken"
    "RefreshTo-MAMToken"
    "RefreshTo-DODMSGraphToken"
    "RefreshTo-O365SuiteUXToken"
    "RefreshTo-YammerToken"
    "Clear-Token"
    # CapBypass.ps1
    "Forge-UserAgent"
    # OutlookEmailAbuse.ps1
    "Open-OWAMailboxInBrowser"
    "Dump-OWAMailboxViaMSGraphApi"
)
$c = 0
foreach($function in $functions)
{
    Write-Progress -Activity "Exporting function" -Status $function -PercentComplete (($c++/$functions.count)*100)
    Export-ModuleMember -Function $function
}
