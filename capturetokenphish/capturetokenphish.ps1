Param(
    [Parameter(ValueFromPipeline)]
    $Token
)
# Change to your file location
Import-Module ../TokenTactics.psd1
Get-AzureToken -Client Graph -CaptureCode $Token