. “C:\Program Files (x86)\VMware\Infrastructure\vSphere PowerCLI\Scripts\Initialize-PowerCLIEnvironment.ps1”
iex (New-Object Net.WebClient).DownloadString("https://gist.github.com/darkoperator/6152630/raw/c67de4f7cd780ba367cccbc2593f38d18ce6df89/instposhsshdev")

$verbosepreference = 'continue'   


#####################################################
### Connect to ESXi host ###

$ip = Read-Host "What is the current IP of the server that you want to configure?"
$cred = get-credential -Message "What is the password of the ESXi host?"
$session = connect-viserver -server $ip -credential $cred
$esxcli = Get-EsxCli -Server $session
$version = ($esxcli.system.version.get()).version
$vmhosts = Get-VMHost | Get-View
$sshsession = New-SSHSession -ComputerName $ip -Credential $cred 
$localstorage = 'C:\VMWARE'
$machine_name = ($esxcli.system.hostname.get()).FullyQualifiedDomainName
$htmlfile = "C:\Temp\QC_$machine_name.html"

############################################
# define output file for appending to HTML

$header = "
<html>
<head>
    <style type=`"text/css`">
    .good {color:green;}
    .bad {color:red;}
    </style>
    <title>ESX Quality Control report for [$machine_name]</title>
</head>
<body>
<h2 align=center>ESX Quality Control report for [$machine_name]</h2>
<table align=center border=1 width=80%>
<tr>
    <td><b><center>Quality Check Task</center></b></td>
    <td><b><center>Result (Green=GOOD, Red=BAD)</center></b></td>
    <td><b><center>Notes/Fix</center></b></td>
"

if (Test-Path c:\temp) {
    $header | Out-File -FilePath $htmlfile
} else {
    New-Item c:\temp -ItemType directory
    $header | Out-File -FilePath $htmlfile
}

####################################################
###   FUNCTIONS

Function Check-License {
    $ESXi5License = "N542Q-22K8K-M8V41-018HH-29Z7J"
    $ESXi6License = "4N407-FU2D3-58088-0U3UP-C43LN"
    $EvalLicense = "00000-00000-00000-00000-00000"
    $LicMgr = Get-View $session
    $License = (Get-View $LicMgr.Content.LicenseManager).licenses.licensekey
    if ($License -eq $ESXi5License){
        $license_output = "
        <tr>
            <td>ESXi License</td>
            <td class=good>The free ESXi5 license is applied!</td>
            <td class=good>Correct</td>
        </tr>
        "
    } elseif ($License -eq $ESXi6License){
        $license_output = "
        <tr>
            <td>ESXi License</td>
            <td class=good>The free ESXi6 license is applied!</td>
            <td class=good>Correct</td>
        </tr>
        "
    } elseif ($License -eq $EvalLicense){
        $license_output = "
        <tr>
            <td>ESXi License</td>
            <td class=bad>The demo license is applied!</td>
            <td class=bad>Please apply a license</td>
        </tr>
        "
    } else {
        $license_output = "
        <tr>
            <td>ESXi License</td>
            <td class=good>A paid for license is applied!</td>
            <td class=good>Correct</td>
        </tr>
        "
    }
    $license_output | Out-File -FilePath $htmlfile -append
 }    

Function Check-LocalDatastore {
    Write-Verbose "Checking for a local datastore"
    $datastores = Get-Datastore -Server $ip
    if ($datastores -eq $null){
        $datastore_output = "
        <tr>
            <td>Local Datastore</td>
            <td class=bad>There is no local datastore!</td>
            <td class=bad>Please validate if the local datastore is there!</td>
        </tr>
        "
    } elseif ($datastores.name -eq "datastore") {
        $datastore_output = "
        <tr>
            <td>Local Datastore</td>
            <td class=good>There is a local datastore named datastore!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    } else {
        $datastore_output = "
        <tr>
            <td>Local Datastore</td>
            <td class=nuetral>There is a local datastore but it is not named datastore!</td>
            <td class=nuetral>It is not named to the standard but it is there!</td>
        </tr>
        "
    }
    $datastore_output | Out-File -FilePath $htmlfile -append
 }

Function Check-WebAccess {
    $webaccess = (Get-ESXCli).software.vib.list() | where name -match "esx-ui"
    if ($webaccess -eq $null){
        $output = "
        <tr>
            <td>Web Access</td>
            <td class=bad>Web Access is not installed!</td>
            <td class=bad>Please setup Web Access!</td>
        </tr>
        "
    } else {
        $output = "
        <tr>
            <td>Web Access</td>
            <td class=good>Web Access appears to be installed!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    }
    $output | Out-File -FilePath $htmlfile -append
}

Function Check-SSH {
    $ssh = (Get-VMHostService -Server $ip | Where { $_.Key -eq “TSM-SSH” }).running
    if ($ssh -eq $false){
        $output = "
        <tr>
            <td>Enable SSH</td>
            <td class=bad>SSH is not enabled!</td>
            <td class=bad>Please enable SSH!</td>
        </tr>
        "
    } else {
        $output = "
        <tr>
            <td>Enable SSH</td>
            <td class=good>SSH appears to be enabled!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    }
    $esxishell = Get-VMHostService -Server $ip | Where { $_.Key -eq “TSM” }
    if ($esxishell -eq $false){
                $output = "
        <tr>
            <td>Enable ESXi Shell</td>
            <td class=bad>ESXi Shell is not enabled!</td>
            <td class=bad>Please enable ESXi Shell!</td>
        </tr>
        "
    } else {
        $output = "
        <tr>
            <td>Enable ESXi Shell</td>
            <td class=good>ESXi Shell appears to be enabled!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    }
    $output | Out-File -FilePath $htmlfile -append
}

Function Check-NTPServer {
    $ntp = Get-VMHostNtpServer -Server $ip
    if ($ntp -match 'pool.ntp.org') {
         $output = "
        <tr>
            <td>NTP Time Server</td>
            <td class=good>NTP Time Server is set to ntp.pool.org!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    } else {
        $output = "
        <tr>
            <td>NTP Time Server</td>
            <td class=bad>NTP Time Server is set NOT to ntp.pool.org!</td>
            <td class=bad>Please set the NTP server to ntp.pool.org!</td>
        </tr>
        "
    }
    $output | Out-File -FilePath $htmlfile -append
}

Function Check-Networking {
    $vmnic0 = Get-VMHostNetworkAdapter | where {$_.name -match "vmnic0"}
    $vmnic1 = Get-VMHostNetworkAdapter | where {$_.name -match "vmnic1"}
    $vmnic2 = Get-VMHostNetworkAdapter | where {$_.name -match "vmnic2"}
    $vmnic3 = Get-VMHostNetworkAdapter | where {$_.name -match "vmnic3"}
    $vmnic4 = Get-VMHostNetworkAdapter | where {$_.name -match "vmnic4"}
    $vmnic5 = Get-VMHostNetworkAdapter | where {$_.name -match "vmnic5"}

    $vswitch0 = get-virtualswitch | where {$_.Name -match "vSwitch0"}
    $vswitch1 = get-virtualswitch | where {$_.Name -match "vSwitch1"}

    $vswitch0NICS = $vswitch0.nic
    $vswitch1NICS = $vswitch1.nic

    $nicquantity = 0

    if ($vmnic0 -eq $null -and $vmnic1 -eq $null -and $vmnic2 -eq $null -and $vmnic3 -eq $null -and $vmnic4 -eq $null -and $vmnic5 -eq $null){
        $nicquantity = 0    
    } elseif ($vmnic0 -ne $null -and $vmnic1 -eq $null -and $vmnic2 -eq $null -and $vmnic3 -eq $null -and $vmnic4 -eq $null -and $vmnic5 -eq $null){
        $nicquantity = 1    
    } elseif ($vmnic0 -ne $null -and $vmnic1 -ne $null -and $vmnic2 -eq $null -and $vmnic3 -eq $null -and $vmnic4 -eq $null -and $vmnic5 -eq $null){
        $nicquantity = 2    
    } elseif ($vmnic0 -ne $null -and $vmnic1 -ne $null -and $vmnic2 -ne $null -and $vmnic3 -eq $null -and $vmnic4 -eq $null -and $vmnic5 -eq $null){
        $nicquantity = 3    
    } elseif ($vmnic0 -ne $null -and $vmnic1 -ne $null -and $vmnic2 -ne $null -and $vmnic3 -ne $null -and $vmnic4 -eq $null -and $vmnic5 -eq $null){
        $nicquantity = 4    
    } elseif ($vmnic0 -ne $null -and $vmnic1 -ne $null -and $vmnic2 -ne $null -and $vmnic3 -ne $null -and $vmnic4 -ne $null -and $vmnic5 -eq $null){
        $nicquantity = 5    
    } elseif ($vmnic0 -ne $null -and $vmnic1 -ne $null -and $vmnic2 -ne $null -and $vmnic3 -ne $null -and $vmnic4 -eq $null -and $vmnic5 -ne $null){
        $nicquantity = 6    
    }
    
    $switchquantity = 0

    if ($vswitch0 -eq $null -and $vswitch1 -eq $null){
        $switchquantity = 0    
    } elseif ($vswitch0 -ne $null -and $vswitch1 -eq $null){
        $switchquantity = 1    
    } elseif ($vswitch0 -ne $null -and $vswitch1 -ne $null){
        $switchquantity = 2    
    }


    if ($nicquantity -eq 2) {
        if ($vswitch0NICS -match "vmnic0" -and $vswitch0NICS -match "vmnic1"){
            $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=good>There are more than 2 NICs and both are attached to vswitch0!</td>
                <td class=good>Correct!</td>
            </tr>
            "
        } elseif($vswitch0NICS -match "vmnic0" -and $vswitch0NICS -notmatch "vmnic1") {
            $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=bad>vmnic1 is not attached to vswitch0!</td>
                <td class=bad>Please attach vmnic1 to vswitch0!</td>
            </tr>
            "
        } elseif($vswitch0NICS -notmatch "vmnic0" -and $vswitch0NICS -match "vmnic1") {
            $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=bad>vmnic0 is not attached to vswitch0!</td>
                <td class=bad>Please attach vmnic0 to vswitch0!</td>
            </tr>
            "
        } elseif($vswitch0NICS -notmatch "vmnic0" -and $vswitch0NICS -notmatch "vmnic1") {
            $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=bad>neither vmnic0 or vmnic1 are attached to vswitch0!</td>
                <td class=bad>Please attach vmnic0 and vmnic1 to vswitch0!</td>
            </tr>
            "
        }
    } elseif ($nicquantity -eq 4) {
        if ($vswitch0NICS -match "vmnic0" -and $vswitch0NICS -match "vmnic2"){
            $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=good>There are more than 2 NICs and both are attached to vswitch0!</td>
                <td class=good>Correct!</td>
            </tr>
            "
        } elseif($vswitch0NICS -match "vmnic0" -and $vswitch0NICS -notmatch "vmnic2") {
            $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=bad>vmnic2 is not attached to vswitch0!</td>
                <td class=bad>Please attach vmnic2 to vswitch0!</td>
            </tr>
            "
        } elseif($vswitch0NICS -notmatch "vmnic0" -and $vswitch0NICS -match "vmnic2") {
            $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=bad>vmnic0 is not attached to vswitch0!</td>
                <td class=bad>Please attach vmnic0 to vswitch0!</td>
            </tr>
            "
        } elseif($vswitch0NICS -notmatch "vmnic0" -and $vswitch0NICS -notmatch "vmnic2") {
            $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=bad>neither vmnic0 or vmnic2 are attached to vswitch0!</td>
                <td class=bad>Please attach vmnic0 and vmnic2 to vswitch0!</td>
            </tr>
            "
        } 

        if ($vswitch1nics -match "vmnic1" -and $vswitch1nics -match "vmnic3"){
            $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=good>There are more than 2 NICs and both are attached to vswitch0!</td>
                <td class=good>Correct!</td>
            </tr>
            "
        } elseif($vswitch1nics -match "vmnic1" -and $vswitch1nics -notmatch "vmnic3") {
            $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=bad>vmnic3 is not attached to vswitch0!</td>
                <td class=bad>Please attach vmnic3 to vswitch0!</td>
            </tr>
            "
        } elseif($vswitch1nics -notmatch "vmnic1" -and $vswitch1nics -match "vmnic3") {
            $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=bad>vmnic1 is not attached to vswitch0!</td>
                <td class=bad>Please attach vmnic1 to vswitch0!</td>
            </tr>
            "
        } elseif($vswitch1nics -notmatch "vmnic1" -and $vswitch1nics -notmatch "vmnic3") {
            $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=bad>neither vmnic1 or vmnic3 are attached to vswitch0!</td>
                <td class=bad>Please attach vmnic1 and vmnic3 to vswitch0!</td>
            </tr>
            "
        } 
    } elseif ($nicquantity -eq 3) {
        $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=nuetral>There are 3 NICs!</td>
                <td class=nuetral>Please validate that the NICs are properly balanced!</td>
            </tr>
            "
    } elseif ($nicquantity -gt 4) {
        $output = "
            <tr>
                <td>Networking Configuration</td>
                <td class=nuetral>There are more than 4 NICs!</td>
                <td class=nuetral>Please validate that the NICs are properly balanced!</td>
            </tr>
            "
    }       
    $output | Out-File -FilePath $htmlfile -append
}

Function Check-MemHotAdd($vm){
    $vmview = Get-vm $vm | Get-View 
    $memadd = $vmview.MemoryHotAddEnabled
    $cpuadd = $vmview.CPUHotAddEnabled
    $vmname = $vm.name

    If ($memadd -eq $true){
        $output = "
        <tr>
            <td>Memory Hot Add</td>
            <td class=good>Memory Hot Add is Enabled on $vmname!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    } else {
        $output = "
        <tr>
            <td>Memory Hot Add</td>
            <td class=bad>Memory Hot Add is disabled on $vmname!</td>
            <td class=bad>Please enable memory hot add!</td>
        </tr>
        "
    }
    If ($cpuadd -eq $true){
        $output = "
        <tr>
            <td>CPU Hot Add</td>
            <td class=good>CPU Hot Add is Enabled on $vmname!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    } else {
        $output = "
        <tr>
            <td>CPU Hot Add</td>
            <td class=bad>CPU Hot Add is disabled on $vmname!</td>
            <td class=bad>Please enable CPU hot add!</td>
        </tr>
        "
    }
    $output | Out-File -FilePath $htmlfile -append
}

#############################################################################################################################################
#############################################################################################################################################
##############          ######   ############  ###        ################################         ####  ########          ##################
##############  ##############    ###########  ###  #####  ###############################  ############  #######  ######  ##################
##############  ##############  #  ##########  ###  ######   #############################  ############## ######  ##########################
##############  ##############  ##  #########  ###  ########  ############################  #####################  ##########################
##############  ##############  ###  ########  ###  ########  ############################  #####################  ##########################
##############  ##############  ####  #######  ###  ########  ############################      #################  ##########################
##############  ##############  #####  ######  ###  ########  ############################  #####################          ##################
##############          ######  ######  #####  ###  ########  ############################  #############################  ##################
##############  ##############  #######  ####  ###  ########  ############################  #############################  ##################
##############  ##############  ########  ###  ###  ########  ############################  #############################  ##################
##############  ##############  #########  ##  ###  ########  ############################  #############################  ##################
##############  ##############  ##########  #  ###  #######  #############################  #############################  ##################
##############  ##############  ###########    ###  #####   ##############################  #####################  ######  ##################
##############          ######  ############   ###        ################################  #####################          ##################
#############################################################################################################################################
#############################################################################################################################################


Write-Verbose "Checking to see if the license has been applied"
Check-License

Write-Verbose "Checking for the local datastore and if it is named properly"
Check-LocalDatastore

Write-Verbose "Checking to see if Web Access has been installed"
Check-WebAccess

Write-Verbose "Checking to see if SSH and the ESXi Shell have been enabled"
Check-SSH

Write-Verbose "Checking to see if the NTP Time Server has been setup"
Check-NTPServer

Write-Verbose "Checking to see if the network is setup properly"
Check-Networking

Write-Verbose "Checking to see if Memory and CPU hot add are enabled!"
$vms = Get-VM
foreach ($vm in $vms){
    Check-MemHotAdd $vm
}










#####################################################
### Set the name of the ESX host ###

$NewName = Read-Host 'What would you like to name the ESX host?'
$esxcli.system.hostname.set($null,$NewName,$null)


#####################################################
### Ensure link speeds ###

$linkspeed = $vmhosts.Config.network.Pnic.linkspeed.speedmb
Write-Verbose "The current linkspeed is $linkspeed Mbps"

#####################################################
### Windows Server needs to be deployd ###

$image = $null
do{
    $srvversion = Read-Host "What version of Windows do you need to deploy?"
    if ($srvversion -match "2012"){
        if ($srvversion -match "R2"){
            $image = "$localstorage\Windows2012R2\Windows2012R2.ova"
            $ISO = "$localstorage\SW_DVD9_Windows_Svr_Std_and_DataCtr_2012_R2_64Bit_English_-4_MLF_X19-82891.ISO"
        } else {
            $image = "$localstorage\Windows2012x64\Windows2012x64.ova"
            $ISO = "$localstorage\SW_DVD5_Win_Svr_Std_and_DataCtr_2012_64Bit_English_Core_MLF_X18-27588.ISO"
        }
    } elseif ($srvversion -match "2008"){
        if ($srvversion -match "R2"){
            $image = "$localstorage\Windows2008R2\Windows2008R2.ova" 
            $ISO = "$localstorage\SW_DVD5_Windows_Svr_DC_EE_SE_Web_2008_R2_64Bit_English_w_SP1_MLF_X17-22580.ISO"
        } elseif ($srvversion -match "64") {
            $image = "$localstorage\Windows2008x64\Windows2008x64.ova" 
            $ISO = "$localstorage\SW_DVD5_Windows_Svr_2008w_SP2_English__x64_DC_EE_SE_X15-41371.ISO"
        } elseif ($srvversion -match "86" -or $srvversion -match "32") {
            $image = "$localstorage\Windows2008x86\Windows2008x86.ova" 
            $ISO = "$localstorage\SW_DVD5_Windows_Svr_2008w_SP2_English__x86_DC_EE_SE_X15-41116.ISO"
        } else {
            Write-Verbose "Version could not be determined.  Try using just the year and R2, x64, 32bit, or x86"
        }
    } 
}until($image -ne $null )

#####################################################
### Gather quantity of VMs and their names ###

[int]$quantity = Read-Host "How many virtual machines do you want to build?"
$names = @()
do  {
    $input = Read-Host "Type in a name of a server"
    $names += $input
    $quantity = $quantity - 1
    }
while ($quantity -gt 0)

#####################################################
### Create VMs and rename them ###

CreateVMs -names $Names -server $session -session $global:DefaultVIServer.SessionSecret -image $image
New-VIProperty -Name ToolsVersion -ObjectType VirtualMachine -ValueFromExtensionProperty 'Config.tools.ToolsVersion' -Force
New-VIProperty -Name ToolsVersionStatus -ObjectType VirtualMachine -ValueFromExtensionProperty 'Guest.ToolsVersionStatus' -Force
$VMs = Get-VM -Server $session

#####################################################
### Validate VM hard drive size ###

foreach ($vm in $vms){
    $harddrives = Get-HardDisk $vm
    foreach ($harddrive in $harddrives){
        $capacity = $harddrive.capacityGB
        if ($capacity -lt 120){
            Write-host "Increasing Hard Drive Size to 120Gb"
            Set-HardDisk -HardDisk $harddrive -CapacityGB 120
        }
    }
}

#####################################################
### Validate CPU and Memory Hotplug ###

foreach ($vm in $vms){
    Enable-MemHotAdd $vm
}

#####################################################
### Configure VM startup and shutdown options ###

Get-VMHost | Get-VMStartPolicy | Set-VMStartPolicy -StartAction PowerOn

#####################################################
### Validate VM Tools on all VMs ###

foreach ($vm in $vms){
    $VMname = $vm.Name
    $status = $vm.ToolsVersionStatus
    if ($status -eq "guestToolsCurrent"){
        Write-Verbose "VMware Tools is the latest version on VM $VMname "
    } else {
        Write-Verbose "Updating VMware Tools on VM $VMname "
        Start-VM $vm
        Start-Sleep -Seconds 60
        Mount-Tools $VM
        Update-Tools $VM
        Start-Sleep -Seconds 60
        Stop-VM
    }
}

#####################################################
### Configure USB Passthrough ###

foreach ($vm in (get-vm)) {
    get-vmhost $session | get-passthroughdevice | where {$_.name -match "USB"} | add-PassThroughDevice -VM $vm
}

#####################################################
### Set Root Password and reconnect ###

Set-VMHostAccount –UserAccount root –Password 'Altuscio7216$'

#####################################################
### Enter License Key ###

Add_License_to_vCenter

#####################################################
### Cleanup

Remove-SSHSession 

#####################################################
### Set Static IP to Host ###

$SetStatic = Read-Host "Do you need to set the static IP? Yes or No"

if($SetStatic -match "yes"){

    $NewIP = Read-Host "What is the permanent IP of the host?"
    $NewSubnet = Read-Host "What is the permanent subnet of the host?"
    $NewDNS01 = Read-Host "What is the permanent primary DNS server of the host?"
    $NewDNS02 = '208.67.222.222'

    Write-Verbose "Creating new host adapter"
    Get-VMHost  | New-VMHostNetworkAdapter -VirtualSwitch "vSwitch0" -PortGroup "MGMT Network" -IP "$NewIP" -SubnetMask "$NewSubnet" -ManagementTrafficEnabled:$true -Confirm:$false | out-null
    Get-VMHost  | Get-VirtualPortGroup -name "MGMT Network" | Get-NicTeamingPolicy | Set-NicTeamingPolicy -MakeNicActive vmnic0 | out-null
    Get-VMHost  | Get-VMHostNetwork | Set-VMHostNetwork -DnsAddress "$NewDNS01","$NewDNS02" | out-null

} else {
    Write-Verbose "Great thank you"
}

Start-Sleep 60


Workflow CreateVMs {
    param(
        [string]$server,
        [string[]]$names,
        [string]$image,
        $session
    )
    foreach -parallel($name in $names){

        $vm = InlineScript{
            $verbosepreference = 'continue'
            Add-PSSnapin "VMware.VimAutomation.Core"
            Write-Verbose "Connecting to the host"
            connect-viserver -server $Using:server -session $Using:session | Out-Null
            ###  Create the new VM from OVF template
            Write-Verbose "Creating VM $Using:name from template"
            Import-VApp -Server $Using:server -VMHost $Using:server -Source $Using:image -Name $Using:name
            ###  Starting the new VM and waiting for it to boot
            #Write-Verbose "Starting $using:name "
            #start-vm -VM $Using:name
            start-sleep -Seconds 60
        }
    }
}

Workflow SetupVMs {
    param(
        [string]$server,
        [pscredential]$credential,
        $VirtualMachines,
        $Session
    )
    <#

    Example on how to use

    $creds = Get-Credential -Message "What is the password of the VM's OS Administrator account?"
    Write-Verbose "Getting a list of VMs"
    $VMs = Get-VM -Server $session
    SetupVMs -credential $creds -server $session -VirtualMachines $vms -Session $global:DefaultVIServer.SessionSecret
    
    #>
    foreach -parallel($VirtualMachine in $VirtualMachines){

        $virtualm = InlineScript{
            $name = $using:VirtualMachine.name
            Add-PSSnapin "VMware.VimAutomation.Core"
            Write-Verbose "Connecting to the host"
            connect-viserver -server $Using:server -session $Using:session | Out-Null
           
            Write-Verbose "Getting IP for $name"
            $vmip = (Get-VMGuest -Server $server -VM $name).ipaddress[0]
            Write-Verbose "The IP for $name is $vmip"
            
            Write-Verbose "Adding $name to trusted host for WSMAN protocol"
            set-item wsman:\localhost\Client\TrustedHosts $vmip -Concatenate -force
            set-item wsman:\localhost\Client\TrustedHosts $name -Concatenate -force
                
            Write-Verbose "Creating session to remote to VM"
            New-PSSession $vmip -Credential $Using:credential
            
            # Ensure some basic settings are enabled
            $features = 'Telnet-Client','Powershell','Migration','NET-Framework-Features','NET-Framework-45-Features'
            $installedFeatures = Get-WindowsFeature -ComputerName $vmip -Credential $using:credential | where {$_.installstate -eq 'Installed'}
            foreach ($feature in $features){
                Write-Verbose "Checking $feature now on $name"
                $installed = $false
                foreach ($installedFeature in $installedFeatures){
                    if ($installedFeature.name -eq $feature){
                        Write-Verbose "$feature Has already been installed on $name" 
                        $installed = $true
                    } 
                }
                if ($installed -eq $false){
                        Write-Verbose "Installing $feature on $name"
                        Install-WindowsFeature $Feature -ComputerName $vmip -Credential $using:credential
                } 
            }

            #Rename the computer and reboot
            $currentname = (Get-WmiObject Win32_ComputerSystem -ComputerName $vmip -Credential $Using:credential).name
            Write-Verbose "Currently the name is $currentname"
            if ($currentname -eq "Base") {
                Write-Verbose "Renaming computer $vmip to $name and restarting"
                Rename-Computer -ComputerName $vmip -NewName $name -LocalCredential $Using:credential -restart
            }
        }
    }
}