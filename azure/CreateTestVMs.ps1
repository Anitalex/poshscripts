$testrg = new-azresourcegroup -resourcegroupname testvms -location eastus

$desktopconf = New-AzVirtualNetworkSubnetConfig -AddressPrefix 10.75.4.0/24 -Name 'Desktops'
$srvconf = New-AzVirtualNetworkSubnetConfig -AddressPrefix 10.75.1.0/24 -Name 'Servers'
$gatwayconf = New-AzVirtualNetworkSubnetConfig -AddressPrefix 10.75.0.0/24 -Name 'GatewaySubnet'
$bastionconf = New-AzVirtualNetworkSubnetConfig -AddressPrefix 10.75.5.0/27 -Name 'AzureBastionSubnet'
$researchconf = New-AzVirtualNetworkSubnetConfig -AddressPrefix 10.75.2.0/24 -Name 'Research'
$adconf = New-AzVirtualNetworkSubnetConfig -AddressPrefix 10.75.3.0/24 -Name 'ADDomainService'
$onboardconf = New-AzVirtualNetworkSubnetConfig -AddressPrefix 10.75.5.96/27 -Name 'Onboard'
$wvdconf = New-AzVirtualNetworkSubnetConfig -AddressPrefix 10.75.6.0/24 -Name 'WVD'

New-AzVirtualNetwork -ResourceGroupName $testrg.ResourceGroupName -name CWA-vnet -Location eastus -AddressPrefix 10.75.0.0/16 -Subnet $desktopconf,$srvconf,$gatwayconf,$bastionconf,$researchconf,$adconf,$onboardconf,$wvdconf

$subnets = Get-AzVirtualNetwork -Name CWA-vnet -ResourceGroupName $testrg.ResourceGroupName | Get-AzVirtualNetworkSubnetConfig | select addressprefix,name

$VMLocalAdminUser = Read-Host "What is the local admin username"
$VMLocalAdminSecurePassword = Read-Host "What is the password?" | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ($VMLocalAdminUser, $VMLocalAdminSecurePassword);


foreach ($subnet in $subnets){
    $name = $subnet.name
    New-AzVM -Name $name -SubnetName $subnet.name -ResourceGroupName $testrg.ResourceGroupName -Location eastus -VirtualNetworkName CWA-vnet -OpenPorts 3389 -Credential $Credential
}

New-AzVM -Name AADDSJoin -SubnetName Desktops -ResourceGroupName $testrg.ResourceGroupName -Location eastus -VirtualNetworkName CWA-vnet -OpenPorts 3389 -Credential $Credential
New-AzVM -Name OnPremJoin -SubnetName Desktops -ResourceGroupName $testrg.ResourceGroupName -Location eastus -VirtualNetworkName CWA-vnet -OpenPorts 3389 -Credential $Credential


