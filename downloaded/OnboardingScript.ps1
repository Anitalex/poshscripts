 # Download the package
function download() {$ProgressPreference="SilentlyContinue"; Invoke-WebRequest -Uri https://aka.ms/AzureConnectedMachineAgent -OutFile AzureConnectedMachineAgent.msi}
download

# Install the package
msiexec /i AzureConnectedMachineAgent.msi /l*v installationlog.txt /qn | Out-String

# Run connect command
& "$env:ProgramFiles\AzureConnectedMachineAgent\azcmagent.exe" connect --resource-group "ProviDyn_OnPremises" --tenant-id "721b5192-86a6-44a4-9414-e49b1f3876d7" --location "eastus" --subscription-id "5e1c8252-788a-4b00-b54c-be7435627719"
