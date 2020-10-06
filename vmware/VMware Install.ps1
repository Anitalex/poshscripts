. “C:\Program Files (x86)\VMware\Infrastructure\vSphere PowerCLI\Scripts\Initialize-PowerCLIEnvironment.ps1”

$verbosepreference = 'continue'   
$localstorage = 'C:\VMWARE'

#####################################################
### Connect to ESXi host ###

$ip = Read-Host "What is the current IP of the server that you want to configure?"
$cred = get-credential -Message "What is the password of the ESXi host?"
$session = connect-viserver -server $ip -credential $cred
$esxcli = Get-EsxCli -Server $session
$version = ($esxcli.system.version.get()).version
$vmhosts = Get-VMHost | Get-View

####################################################
###   FUNCTIONS

Function Enable-MemHotAdd($vm){
    $vmview = Get-vm $vm | Get-View 
    $vmConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $vmConfigSpec.MemoryHotAddEnabled = "true"
    $vmConfigSpec.CPUHotAddEnabled = "true"
    $vmview.ReconfigVM($vmConfigSpec)
}

Function Get-HTTPFile ($url,$file,$username,$password){
    <#
    This function takes in the url to download a file and then the destination.
    If needed it allows for username and password but this is not required
    #>
    $webclient = New-Object System.Net.WebClient
    $webclient.Credentials = New-Object System.Net.NetworkCredential($username,$password) 
    $webclient.DownloadFile($url,$file)
}

Function Add_License_to_vCenter {
   <#
   This function asks for the license of vmware and applies it.  If
   free is typed in then it applies the free license
   #>

    $ESXi5License = "N542Q-22K8K-M8V41-018HH-29Z7J"
    $ESXi6License = "4N407-FU2D3-58088-0U3UP-C43LN"
    $license = Read-Host "Type in FREE if you are using the free version or type in your key if purchased."
    if ($license -eq "free"){
        if ($version -eq '6.0.0'){
            Write-Verbose "Licensing ESXi 6 with a free license"
            $LicMgr = Get-View $session
            $AddLic= Get-View $LicMgr.Content.LicenseManager
            $AddLic.UpdateLicense($ESXi6License,$null)
        } else {
            Write-Verbose "Licensing ESXi 5 with a free license"
            $LicMgr = Get-View $session
            $AddLic= Get-View $LicMgr.Content.LicenseManager
            $AddLic.UpdateLicense($ESXi5License,$null)
        }
    } else {
        Write-Verbose "Licensing ESXi with a purchased license"
        $LicMgr = Get-View $session
        $AddLic= Get-View $LicMgr.Content.LicenseManager
        $AddLic.UpdateLicense($license,$null)
    }
 }    

Function Create-LocalDatastore {
    Write-Verbose "Checking for a local datastore"
    $datastores = Get-Datastore -Server $ip
    if ($datastores -eq $null){
        Write-Verbose "Creating local datastore"
        $path = (Get-SCSILun -Server $ip -LunType Disk | where {$_.islocal -eq $true -and $_.capacitygb -gt 64}).canonicalname
        New-Datastore -Server $ip -Name datastore -Path $path
    } else {
        Write-Verbose "The local datastore has already been created"
    }
 }

Function Enable-WebAccess {
    $datastore = Get-Datastore -Server $ip -Name datastore
    $file = 'esxui_signed.vib'
    $download ="http://download3.vmware.com/software/vmw-tools/esxui/esxui_signed.vib"
    $WApath = "$localstorage\$file"
    $datastorepath = $datastore.ExtensionData.Info.url
    $WAcmd = "esxcli software vib install -v $datastorepath/$file"

    Write-Verbose "Checking to see if Web Access has been downloaded already"
    if (Test-Path $WApath) {
        Write-Verbose "Web Access has already been downloaded"
    } else {
        Write-Verbose "Downloading Web Access now"
        Get-HTTPFile $download $WApath
    }

    Write-Verbose "Placing the host into maintenance mode"
    Set-VMHost -Server $session -State "Maintenance" -RunAsync

    Write-Verbose "Waiting for host to enter maintenance mode"
    do {  
    $state = (Get-VMHost -Server $session).ConnectionState
    } until($state -eq 'Maintenance')


    Write-Verbose "Install Web Access"
    Get-VMHost | Install-VMHostPatch -HostPath "$datastorepath/$file"

    Write-Verbose "Placing the host into maintenance mode"
    Set-VMHost -Server $session -State "Connected" -RunAsync

    Write-Verbose "Waiting for host to exit maintenance mode"
    do {  
    $state = (Get-VMHost -Server $session).ConnectionState
    } until($state -eq 'Connected')
}

Function Enable-SSH {
    Write-Verbose "Enabling SSH and ESXi Shell"
    Write-Verbose "Checking to see if SSH is enabled"
    $ssh = (Get-VMHostService -Server $ip | Where { $_.Key -eq “TSM-SSH” }).running
    if ($ssh -eq $false){
        Write-Verbose "SSH is not running.  Starting it now"
        Get-VMHostService -Server $ip | Where { $_.Key -eq “TSM-SSH” } | Start-VMHostService
    } else {
        Write-Verbose "SSH was already started"
    }
    $esxishell = Get-VMHostService -Server $ip | Where { $_.Key -eq “TSM” }
    if ($esxishell -eq $false){
        Write-Verbose "ESXi Shell is not running.  Starting it now"
        Get-VMHostService -Server $ip | Where { $_.Key -eq “TSM” } | Start-VMHostService
    } else {
        Write-Verbose "ESXi Shell was already started"
    }
}

Function Set-NTPServer {
    ### Configure NTP server
    $ntp = Get-VMHostNtpServer -Server $ip
    if ($ntp -match 'pool.ntp.org') {
        Write-Verbose "The NTP time server already set to pool.ntp.org"
    } else {
        Write-Verbose "Adding a NTP time server"
        Add-VMHostNtpServer -NtpServer pool.ntp.org -Server $ip
    }

    ### Allow NTP queries outbound through the firewall
    Write-Verbose "Verifying firewall exceptions for time server"
    $ntpfw = (Get-VMHostFirewallException -Server $ip | where {$_.Name -eq "NTP client"}).enabled
    if ($ntpfw -eq $false){
        Write-Verbose "Enbling firewall exceptions for time server"
        Get-VMHostFirewallException -Server $ip | where {$_.Name -eq "NTP client"} | Set-VMHostFirewallException -Enabled:$true
    } else {
        Write-Verbose "Firewall exceptions for time server were already in place"
    }

    ### Start NTP client service and set to automatic
    Write-Verbose "Checking the NTP time server service to see if Automatic and Enabled"
    $ntpsvc = Get-VmHostService -Server $ip | Where-Object {$_.key -eq "ntpd"}
    if ($ntpsvc.Running -eq $false){
        Write-Verbose "Starting the NTP time server"
        Get-VmHostService -Server $ip | Where-Object {$_.key -eq "ntpd"} | Set-VMHostService -policy "automatic" | Start-VMHostService
    } else {
        Write-Verbose "The NTP time server service already is Automatic and Enabled"
    }

    ### Set current date and time
    Write-Verbose "Setting the current date and time"
    $current = Get-Date
    $dst = Get-VMHost -Name $ip | %{ Get-View $_.ExtensionData.ConfigManager.DateTimeSystem }
    $dst.UpdateDateTime((Get-Date($current.ToUniversalTime()) -format u))
}

Function Set-Networking {

    sl c:\
    ### vSwitch0
    $s0nics = (get-virtualswitch -Server $session -Name vSwitch0).nic
    $vmnic1 = $false
    foreach ($s0nic in $s0nics){
        if ($s0nic -eq 'vmnic1'){
            Write-Verbose "vmnic1 is already added to vSwitch0"
            $vmnic1 = $true
        }
    }
    if ($vmnic1 -eq $false){
        Write-Verbose "Adding vmnic1 to vSwitch0"
        $vmnic1 = Get-VMHostNetworkAdapter -name vmnic1
        Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch vSwitch0 -VMHostPhysicalNic $vmnic1 -Server $session
    }


    $3rdnic = (Get-VMHostNetworkAdapter).devicename -match "vmnic2"

    if ($3rdnic -eq "vmnic2"){
        ### vSwitch1
        Write-Verbose "Checking to see if vSwitch1 exists"
        $vswitch1 = get-virtualswitch -Server $session -Name vSwitch1
        if ($vswitch1 -eq $null) {
            ### vSwitch1
            Write-Verbose "Creating vSwitch1 with vmnic2 and vmnic3"
            New-VirtualSwitch -Name vSwitch1 -Nic vmnic2,vmnic3 -Server $session
        } else {
            Write-Verbose "vSwitch1 does exists"
            Write-Verbose "Checking to see what vmnics are associated"
            $s1nics = (get-virtualswitch -Server $session -Name vSwitch1).nic
            $vmnic2 = $false
            $vmnic3 = $false
            foreach ($s1nic in $s1nics){
                if ($s1nic -eq 'vmnic2'){
                    Write-Verbose "vmnic2 is already added to vSwitch1"
                    $vmnic2 = $true
                }
                if ($s1nic -eq 'vmnic3'){
                    Write-Verbose "vmnic3 is already added to vSwitch1"
                    $vmnic3 = $true
                }
            }
            if ($vmnic2 -ne $true){
                Write-Verbose "Adding vmnic2 to vSwitch1"
                $vmnic2 = Get-VMHostNetworkAdapter -name vmnic2
                Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch vSwitch1 -VMHostPhysicalNic $vmnic2 -Server $session
            }
            if ($vmnic3 -ne $true){
                Write-Verbose "Adding vmnic3 to vSwitch1"
                $vmnic3 = Get-VMHostNetworkAdapter -name vmnic3
                Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch vSwitch1 -VMHostPhysicalNic $vmnic3 -Server $session
            }
        }
    } else {
        Write-Verbose "There are only 2 NIC's installed on this server"
    }

}

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

Workflow SetupVMsParallel {
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

            Function Enable-MemHotAdd($vm){
                $vmview = Get-vm $using:VirtualMachine | Get-View 
                $vmConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
                $vmConfigSpec.MemoryHotAddEnabled = "true"
                $vmConfigSpec.CPUHotAddEnabled = "true"
                $vmview.ReconfigVM($vmConfigSpec)
            }


            $name = $using:VirtualMachine.name
            Add-PSSnapin "VMware.VimAutomation.Core"
            Write-Verbose "Connecting to the host"
            connect-viserver -server $Using:server -session $Using:session | Out-Null
           
            Write-Verbose "Getting IP for $name"
            $vmip = (Get-VMGuest -Server $server -VM $name).ipaddress[0]
            Write-Verbose "The IP for $name is $vmip"
            
            ### Validate CPU and Memory Hotplug ###
            Enable-MemHotAdd $name

            ### Validate VM hard drive size ###
            $harddrives = Get-HardDisk $using:VirtualMachine
            foreach ($harddrive in $harddrives){
                $capacity = $harddrive.capacityGB
                if ($capacity -lt 120){
                    Write-host "Increasing Hard Drive Size to 120Gb"
                    Set-HardDisk -HardDisk $harddrive -CapacityGB 120
                }
            }

            ### Validate VM Tools on all VMs ###
            $VMname = $using:VirtualMachine.Name
            $status = $using:VirtualMachine.ToolsVersionStatus
            if ($status -eq "guestToolsCurrent"){
                Write-Verbose "VMware Tools is the latest version on VM $VMname "
            } else {
                Write-Verbose "Updating VMware Tools on VM $VMname "
                Start-VM $using:VirtualMachine
                Start-Sleep -Seconds 60
                Mount-Tools $using:VirtualMachine
                Update-Tools $using:VirtualMachine
                Start-Sleep -Seconds 60
                Stop-VM
            }

            ### Setup start policy ###
            $using:VirtualMachine | Set-VMStartPolicy -StartAction PowerOn

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

Workflow SetupVMs {
    param(
        [string]$server,
        [pscredential]$credential,
        $VirtualMachine,
        $Session
    )

    $name = $VirtualMachine.name
    Add-PSSnapin "VMware.VimAutomation.Core"
    Write-Verbose "Connecting to the host"
    connect-viserver -server $server -session $session | Out-Null
           
    Write-Verbose "Getting IP for $name"
    $vmip = (Get-VMGuest -Server $server -VM $name).ipaddress[0]
    Write-Verbose "The IP for $name is $vmip"
            
    ### Validate CPU and Memory Hotplug ###
    Enable-MemHotAdd $name

    ### Validate VM hard drive size ###
    $harddrives = Get-HardDisk $VirtualMachine
    foreach ($harddrive in $harddrives){
        $capacity = $harddrive.capacityGB
        if ($capacity -lt 120){
            Write-host "Increasing Hard Drive Size to 120Gb"
            Set-HardDisk -HardDisk $harddrive -CapacityGB 120
        }
    }

    ### Validate VM Tools on all VMs ###
    $VMname = $VirtualMachine.Name
    $status = $VirtualMachine.ToolsVersionStatus
    if ($status -eq "guestToolsCurrent"){
        Write-Verbose "VMware Tools is the latest version on VM $VMname "
    } else {
        Write-Verbose "Updating VMware Tools on VM $VMname "
        Start-VM $VirtualMachine
        Start-Sleep -Seconds 60
        Mount-Tools $VirtualMachine
        Update-Tools $VirtualMachine
        Start-Sleep -Seconds 60
        Stop-VM
    }

    ### Setup start policy ###
    $VirtualMachine | Set-VMStartPolicy -StartAction PowerOn

    Write-Verbose "Adding $name to trusted host for WSMAN protocol"
    set-item wsman:\localhost\Client\TrustedHosts $vmip -Concatenate -force
    set-item wsman:\localhost\Client\TrustedHosts $name -Concatenate -force
                
    Write-Verbose "Creating session to remote to VM"
    New-PSSession $vmip -Credential $credential
            
    # Ensure some basic settings are enabled
    $features = 'Telnet-Client','Powershell','Migration','NET-Framework-Features','NET-Framework-45-Features'
    $installedFeatures = Get-WindowsFeature -ComputerName $vmip -Credential $credential | where {$_.installstate -eq 'Installed'}
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
                Install-WindowsFeature $Feature -ComputerName $vmip -Credential $credential
        } 
    }

    #Rename the computer and reboot
    $currentname = (Get-WmiObject Win32_ComputerSystem -ComputerName $vmip -Credential $credential).name
    Write-Verbose "Currently the name is $currentname"
    if ($currentname -eq "Base") {
        Write-Verbose "Renaming computer $vmip to $name and restarting"
        Rename-Computer -ComputerName $vmip -NewName $name -LocalCredential $credential -restart
    }
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

#####################################################
### Set the name of the ESX host ###

$NewName = Read-Host 'What would you like to name the ESX host?'
$esxcli.system.hostname.set($null,$NewName,$null)

#####################################################
### Create to local datastore on ESXi host ###

Create-LocalDatastore

#####################################################
### Ensure link speeds ###

$linkspeed = $vmhosts.Config.network.Pnic.linkspeed.speedmb
Write-Verbose "The current linkspeed is $linkspeed Mbps"

#####################################################
### Enable WebAccess ###

Enable-WebAccess

#####################################################
### Setup Networking ###

Set-Networking

#####################################################
### Enable SSH and ESXi Shell ###

Enable-SSH

#####################################################
### Setup NTP Time Server ###

Set-NTPServer

#####################################################
### Windows Server needs to be deployd ###

$image = $null
do{
    # determine the version needed to install and then set the local variables to point to the locations locally
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
### Setup VMs and rename them ###

$creds = Get-Credential


SetupVMs -credential $creds -server $session -VirtualMachines $vms -Session $global:DefaultVIServer.SessionSecret

#####################################################
### Set Root Password and reconnect ###

Set-VMHostAccount –UserAccount root –Password 'Altuscio7216$'

#####################################################
### Enter License Key ###

Add_License_to_vCenter


