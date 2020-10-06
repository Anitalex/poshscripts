Start-Transcript -Path "c:\vmware\installs\$(Get-Date -Format MMddyyyy-hhmm).rtf" -Append -NoClobber -Force
. “C:\Program Files (x86)\VMware\Infrastructure\vSphere PowerCLI\Scripts\Initialize-PowerCLIEnvironment.ps1”

#region source

##################################################
#   This script was created for and by 
#   Carlos McCray
#   Rights reserved by creator
##################################################

#endregion

#region ScriptVaribles

$verbosepreference = 'continue'   
$localstorage = 'C:\SyncedFolder\Technical\Windows2016Template'
$ova = "C:\SyncedFolder\Technical\Windows2016Template\Windows2016Template.ova"
$hddcapacity = 120
$memcapacity = 4096

#endregion

#region ConnecttoESXi

Write-Verbose "Trying to ping the host"
$ip = Read-Host "What is the current IP of the server that you want to configure?"
if (Test-Connection -computername $ip -Quiet -Count 1 -ErrorAction stop){
    Write-Verbose "Host pinged successfully"
    $cred = get-credential -Message "What is the password of the ESXi host?"
    Write-Verbose "Attempting to connect to the host"
    $session = connect-viserver -server $ip -credential $cred
    if ($session -ne $null){
        Write-Verbose "Successfully connected to the host"
        $esxcli = Get-EsxCli -Server $session
        Write-Verbose "Getting the version of ESXi"
        $version = ($esxcli.system.version.get()).version
        Write-Verbose "The version is $version"
        $vmhosts = Get-VMHost | Get-View
        $NewName = Read-Host 'What would you like to name the ESX host?'
        # Gather quantity of VMs and their names
        [int]$quantity = Read-Host "How many virtual machines do you want to build?"
        $total = $quantity
        if ($quantity -gt 0){
            $names = @()
            do {
                $input = Read-Host "Type in a name of a server"
                $names += $input
                $quantity = $quantity - 1
            } while ($quantity -gt 0)
        }
    } elseif ($error[0] -match "The Term 'connect-viserver' is not recognized as the name of a cmdlet") {
        Read-Host "You need to load the VMware environment and modules.  Please install and run script again.  Press Enter to continue...."
        Exit
    }
} else {
    Read-Host "Unable to connect to the host as it is not pingable.  Please resolve and run script again.  Press Enter to continue...."
    Exit
}

#endregion

#region Functions

<# List of functions

Start-QCInformation
Start-QCStaticIP
Start-QCNetworkLinkSpeed
Start-QCTime
Get-HTTPFile
Install-DellOpenManage
Start-QCDellOpenManage
Install-License
Start-QCLicense
New-LocalDatastore
Start-QCLocalDatastore
Enable-WebAccess
Start-QCWebAccess
Enable-SSH
Start-QCSSH
Set-NTPServer
Start-QCNTPServer
Set-Networking
Start-QCNetworking
Set-SyslogPath
Start-QCSyslogPath
New-VM
Start-QCHostAutoStart
Start-QCVMs

#>

Function Start-QCInformation {
    $vmhosts = (get-vmhost | Get-View).config.product | Select-Object @{ Name = "Name"; Expression ={ ((get-vmhost | Get-View)).Name }},@{ Name = "OS"; Expression ={ $_.Name }}, Version, Build, FullName, ApiVersion
    $name = $vmhosts.name
    $os = $vmhosts.os
    $version = $vmhosts.version
    $build = $vmhosts.build
    $fullname = $vmhosts.fullname


    $output = "
        <tr>
            <td>Host Information</td>
            <td><b>Name:</b> $name
            <br /><b>Host OS:</b> $os
            <br /><b>OS Version:</b> $version
            <br /><b>OS Build:</b> $build
            <br /><b>Host Full Name:</b> $fullname</td>
            <td>Verify latest version.</td>
        </tr>
        "
    $output | Out-File -FilePath $htmlfile -append

}

Function Get-HTTPFile ($url,$file,$username,[securestring]$password){
    <#
    This function takes in the url to download a file and then the destination.
    If needed it allows for username and password but this is not required
    #>
    if (Test-Path $file){
        Write-Verbose "The file needed has already been downloaded to the proper location"
    } else {
        Write-Verbose "Downloading the file now..."
        $webclient = New-Object System.Net.WebClient
        $webclient.Credentials = New-Object System.Net.NetworkCredential($username,$password) 
        $webclient.DownloadFile($url,$file)
    }
}

Function Start-QCStaticIP {
    $nics = Get-VMHostNetworkadapter | Where-Object {$_.ManagementTrafficEnabled -eq $true -and $_.DhcpEnabled -eq $true}
    if ($nics -eq $null){
    $output = "
        <tr>
            <td>DHCP Enabled Nics</td>
            <td class=good>All NICs are static!</td>
            <td class=good>Correct</td>
        </tr>
        "
    } else {
        $output = "
        <tr>
            <td>DHCP Enabled Nics</td>
            <td class=bad>The management NIC is set to DHCP!</td>
            <td class=bad>Please set the NIC to be static</td>
        </tr>
        "
    }
    $output | Out-File -FilePath $htmlfile -append
}

Function Start-QCNetworkLinkSpeed {
    $vmhost = Get-VMHost | Get-View
    $nics = $vmhost.Config.Network.pnic
    foreach ($nic in $nics){
        $device = $nic.device
        $speed = $nic.linkspeed.speedmb
        if ($speed -ge 1000) {
        $output = "
        <tr>
            <td>Network Adapter Link Speed</td>
            <td class=good>The network adapter link speed on $device is 1Gb or greater!</td>
            <td class=good>Correct</td>
        </tr>
        "
        } else {
            $output = "
            <tr>
                <td>Network Adapter Link Speed</td>
                <td class=bad>The network adapter link speed on $device is less than 1Gb!</td>
                <td class=bad>Please investigate!</td>
            </tr>
            "
        }
    $output | Out-File -FilePath $htmlfile -append
    }

}

Function Start-QCTime {
    $vmhost = Get-VMHost | Get-View
    Write-Verbose "Getting the current time on the host"
    $VMHostDateTimeSystem = get-view -id $VMHost.ConfigManager.DateTimeSystem
    $VMHostTime=$VMHostDateTimeSystem.QueryDateTime()
    Write-Verbose "Getting the current Universal Time"
    $UTCTime = (Get-Date).ToUniversalTime() 
    $difference = $UTCTime - $VMHostTime

    if ($difference.days -eq 0 -and $difference.hours -eq 0) {
        if ($difference.Minutes -le 5){
            Write-Verbose "Correct time"
            $output = "
            <tr>
                <td>Host Time</td>
                <td class=good>The time on the host is within 5 minutes of Universal Time!</td>
                <td class=good>Correct</td>
            </tr>
            "
        } else {
            Write-Verbose "Time is greater than 5 mins difference"
            $output = "
            <tr>
                <td>Host Time</td>
                <td class=bad>The time on the host is greater than 5 minutes of Universal Time!</td>
                <td class=bad>Please investigate!</td>
            </tr>
            "
        }
    } else {
        Write-Verbose "Time is greater than 1 hour difference"
         $output = "
            <tr>
                <td>Host Time</td>
                <td class=bad>The time on the host is greater than 1 hour difference of Universal Time!</td>
                <td class=bad>Please investigate!</td>
            </tr>
            "
    }
    $output | Out-File -FilePath $htmlfile -append
}

function Install-DellOpenManage {
    # Install Dell Open Manage on the hypervisor

    $file = 'OM-SrvAdmin-Dell-Web-8.1.0-1518.VIB-ESX60i_A00.zip'
    $download ="http://downloads.dell.com/FOLDER02867568M/1/$file"
    $OMSApath = "$localstorage\$file"

    Write-Verbose "Checking to see if OMSA has been downloaded already"
    if (Test-Path $OMSApath) {
        Write-Verbose "OMSA has already been downloaded"
    } else {
        Write-Verbose "Downloading OMSA now"
        Get-HTTPFile $download $OMSApath
    }

    $datastore = Get-Datastore -Server $ip -Name datastore
    
    if (Test-Path ds:\){} else{
        New-PSDrive -Location $datastore -Name ds -PSProvider VimDatastore -Root "\"
    }
    Set-Location ds:\
    if (Test-Path "ds:\$file") {
        Write-Verbose "OMSA install files are already on the datastore"
    } else {
        Write-Verbose "Copying OMSA to the local datastore of the host"
        Copy-DatastoreItem -Item $OMSApath -Destination ds:\
    }

    Write-Verbose "Placing the host into maintenance mode"
    Set-VMHost -Server $ip -State "Maintenance" -RunAsync
    Write-Verbose "Install DELL OMSA"
    Install-VMHostPatch -VMHost $ip -HostPath "/vmfs/devices/localdatastore/$file" 
    Write-Verbose "Placing the host into maintenance mode"
    Set-VMHost -Server $ip -State "Connected" -RunAsync

    set-location c:\

}

function Start-QCDellOpenManage {
    # Check for Dell Open Manage on the hypervisor

    $status = ((Get-ESXCli).software.vib.list() | Where-Object {$_.vendor -match "dell"}).id
    if ($status -eq 'Dell_bootbank_dell-configuration-vib_6.5-0A00'){
        $output = "
        <tr>
            <td>Dell Open Manage Server Administrator for ESXi</td>
            <td class=good>Dell Open Manage Server Administrator for ESXi is applied!</td>
            <td class=good>Correct</td>
        </tr>
        "
    } else {
        $output = "
        <tr>
            <td>Dell Open Manage Server Administrator for ESXi</td>
            <td class=bad>Dell Open Manage Server Administrator for ESXi is applied!</td>
            <td class=bad>Please install Dell Open Manage Server Administrator for ESXi</td>
        </tr>
        "
    }
    $output | Out-File -FilePath $htmlfile -append
}

Function Install-License {
   <#
   This function asks for the license of vmware and applies it.  If
   free is typed in then it applies the free license
   #>
    Write-Verbose "Beginning the licensing section"
    $ESXi5License = "N542Q-22K8K-M8V41-018HH-29Z7J"
    $ESXi6License = "4N407-FU2D3-58088-0U3UP-C43LN"
    $license = Read-Host "Type in FREE if you are using the free version or type in your key if purchased."
    Write-Verbose "You chose to license it with:  $license"
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
 
Function Start-QCLicense {
    $ESXi5License = "N542Q-22K8K-M8V41-018HH-29Z7J"
    $ESXi6License = "4N407-FU2D3-58088-0U3UP-C43LN"
    $EvalLicense = "00000-00000-00000-00000-00000"
    $LicMgr = Get-View $session
    $License = (Get-View $LicMgr.Content.LicenseManager).licenses.licensekey
    if ($License -eq $ESXi5License){
        $output = "
        <tr>
            <td>ESXi License</td>
            <td class=good>The free ESXi5 license is applied!</td>
            <td class=good>Correct</td>
        </tr>
        "
    } elseif ($License -eq $ESXi6License){
        $output = "
        <tr>
            <td>ESXi License</td>
            <td class=good>The free ESXi6 license is applied!</td>
            <td class=good>Correct</td>
        </tr>
        "
    } elseif ($License -eq $EvalLicense){
        $output = "
        <tr>
            <td>ESXi License</td>
            <td class=bad>The demo license is applied!</td>
            <td class=bad>Please apply a license</td>
        </tr>
        "
    } else {
        $output = "
        <tr>
            <td>ESXi License</td>
            <td class=good>A paid for license is applied!</td>
            <td class=good>Correct</td>
        </tr>
        "
    }
    $output | Out-File -FilePath $htmlfile -append
 }   

Function New-LocalDatastore {
    Write-Verbose "Checking for a local datastore"
    $datastores = Get-Datastore -Server $ip
    if ($datastores -eq $null){
        Write-Verbose "Local datastore was not found....creating local datastore now"
        $path = (Get-SCSILun -Server $ip -LunType Disk | Where-Object {$_.islocal -eq $true -and $_.capacitygb -gt 64}).canonicalname
        New-Datastore -Server $ip -Name datastore -Path $path
    } else {
        Write-Verbose "The local datastore has already been created"
    }
 }

Function Start-QCLocalDatastore {
    Write-Verbose "Checking for a local datastore"
    $datastores = Get-Datastore -Server $ip
    if ($datastores -eq $null){
        $output = "
        <tr>
            <td>Local Datastore</td>
            <td class=bad>There is no local datastore!</td>
            <td class=bad>Please validate if the local datastore is there!</td>
        </tr>
        "
    } elseif ($datastores.name -eq "datastore") {
        $output = "
        <tr>
            <td>Local Datastore</td>
            <td class=good>There is a local datastore named datastore!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    } else {
        $output = "
        <tr>
            <td>Local Datastore</td>
            <td class=nuetral>There is a local datastore but it is not named datastore!</td>
            <td class=nuetral>It is not named to the standard but it is there!</td>
        </tr>
        "
    }
    $output | Out-File -FilePath $htmlfile -append
}

Function Enable-WebAccess {
    $datastore = Get-Datastore -Server $ip -Name datastore
    $file = 'esxui_signed.vib'
    $download ="http://download3.vmware.com/software/vmw-tools/esxui/esxui_signed.vib"
    $WApath = "$localstorage\$file"
    $datastorepath = $datastore.ExtensionData.Info.url

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

Function Start-QCWebAccess {
    $webaccess = (Get-ESXCli).software.vib.list() | Where-Object name -match "esx-ui"
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

Function Enable-SSH {
    Write-Verbose "Enabling SSH and ESXi Shell"
    Write-Verbose "Checking to see if SSH is enabled"
    $ssh = (Get-VMHostService -Server $ip | Where-Object { $_.Key -eq “TSM-SSH” }).running
    if ($ssh -eq $false){
        Write-Verbose "SSH is not running.  Starting it now"
        Get-VMHostService -Server $ip | Where-Object { $_.Key -eq “TSM-SSH” } | Start-VMHostService
    } else {
        Write-Verbose "SSH was already started"
    }
    $esxishell = Get-VMHostService -Server $ip | Where-Object { $_.Key -eq “TSM” }
    if ($esxishell -eq $false){
        Write-Verbose "ESXi Shell is not running.  Starting it now"
        Get-VMHostService -Server $ip | Where-Object { $_.Key -eq “TSM” } | Start-VMHostService
    } else {
        Write-Verbose "ESXi Shell was already started"
    }
}

Function Start-QCSSH {
    $ssh = (Get-VMHostService -Server $ip | Where-Object { $_.Key -eq “TSM-SSH” }).running
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
    $esxishell = Get-VMHostService -Server $ip | Where-Object { $_.Key -eq “TSM” }
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

Function Set-NTPServer {
    Write-Verbose "Setting the time configuration"
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
    $ntpfw = (Get-VMHostFirewallException -Server $ip | Where-Object {$_.Name -eq "NTP client"}).enabled
    if ($ntpfw -eq $false){
        Write-Verbose "Enbling firewall exceptions for time server"
        Get-VMHostFirewallException -Server $ip | Where-Object {$_.Name -eq "NTP client"} | Set-VMHostFirewallException -Enabled:$true
    } else {
        Write-Verbose "Firewall exceptions for time server were already in place"
    }

    ### Start NTP client service and set to automatic
    Write-Verbose "Checking the NTP time server service to see if Automatic and Enabled"
    $ntpsvc = Get-VmHostService -Server $ip | Where-Object-Object {$_.key -eq "ntpd"}
    if ($ntpsvc.Running -eq $false){
        Write-Verbose "Starting the NTP time server"
        Get-VmHostService -Server $ip | Where-Object-Object {$_.key -eq "ntpd"} | Set-VMHostService -policy "automatic" | Start-VMHostService
    } else {
        Write-Verbose "The NTP time server service already is Automatic and Enabled"
    }

    ### Set current date and time
    Write-Verbose "Setting the current date and time"
    $current = Get-Date
    $dst = Get-VMHost -Name $ip | ForEach-Object{ Get-View $_.ExtensionData.ConfigManager.DateTimeSystem }
    $dst.UpdateDateTime((Get-Date($current.ToUniversalTime()) -format u))
}

Function Start-QCNTPServer {
    $ntp = Get-VMHostNtpServer -Server $ip
    if ($ntp -match 'pool.ntp.org') {
         $output = "
        <tr>
            <td>NTP Time Server</td>
            <td class=good>NTP Time Server is set to pool.ntp.org!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    } else {
        $output = "
        <tr>
            <td>NTP Time Server</td>
            <td class=bad>NTP Time Server is set NOT to pool.ntp.org!</td>
            <td class=bad>Please set the NTP server to pool.ntp.org!</td>
        </tr>
        "
    }
    $output | Out-File -FilePath $htmlfile -append
}

Function Set-Networking {
    Write-Verbose "Setting the network configuration on the host"
    Set-Location c:\
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

    Write-Verbose "Checking to see if a 3rd network adapter is installed"
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

Function Start-QCNetworking {
    $vmnic0 = Get-VMHostNetworkAdapter | Where-Object {$_.name -match "vmnic0"}
    $vmnic1 = Get-VMHostNetworkAdapter | Where-Object {$_.name -match "vmnic1"}
    $vmnic2 = Get-VMHostNetworkAdapter | Where-Object {$_.name -match "vmnic2"}
    $vmnic3 = Get-VMHostNetworkAdapter | Where-Object {$_.name -match "vmnic3"}
    $vmnic4 = Get-VMHostNetworkAdapter | Where-Object {$_.name -match "vmnic4"}
    $vmnic5 = Get-VMHostNetworkAdapter | Where-Object {$_.name -match "vmnic5"}

    $vswitch0 = get-virtualswitch | Where-Object {$_.Name -match "vSwitch0"}
    $vswitch1 = get-virtualswitch | Where-Object {$_.Name -match "vSwitch1"}

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

Function Set-SyslogPath {
    $logpath = "[datastore] syslogs/$machine_name.log"
    $current = (Get-AdvancedSetting -Entity $ip -Name Syslog.global.logDir ).value

    if ($current -eq $logpath) {
        Write-Verbose "The current syslog path is correct!"
    }else {
        Write-Verbose "The current syslog path is not correct!"
        Get-AdvancedSetting -Entity $ip -Name Syslog.global.logDir | Set-AdvancedSetting -Value $logpath -Confirm:$false
    }

}

Function Start-QCSyslogPath {
    $logpath = "[datastore] syslogs/$machine_name.log"
    $current = (Get-AdvancedSetting -Entity $ip -Name Syslog.global.logDir ).value

    if ($current -eq $logpath) {
        Write-Verbose "The current syslog path is correct!"
        $output = "
        <tr>
            <td>Syslog Path</td>
            <td class=good>The Systlog Path is set correctly to the datastore!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    }else {
        Write-Verbose "The current syslog path is not correct!"
         $output = "
        <tr>
            <td>Syslog Path</td>
            <td class=bad>The Systlog Path is NOT set to the datastore!</td>
            <td class=bad>Please move the syslog to the datastore!</td>
        </tr>
        "
    }

}

Function Start-QCHostAutoStart {
    Write-Verbose "Validating that the host has autostart enabled"
    $hostautostart = (Get-VMHostStartPolicy).Enabled
    If ($hostautostart -eq $true){
        $output = "
        <tr>
            <td>Host Autostart</td>
            <td class=good>The host is set to autostart!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    } else {
        $output = "
        <tr>
            <td>Host Autostart</td>
            <td class=bad>The host is <b>NOT</b> set to autostart!</td>
            <td class=bad>Please enable autostart on the host!</td>
        </tr>
        "
    }
    $output | Out-File -FilePath $htmlfile -append
}

Function Start-QCVMs {
    param(
        [string]$server,
        [string]$datastore,
        $session,
        $hddsize,
        $memsize
    )
    $vms = Get-VM -Server $server
    $count = $vms.count
    if ($count -eq $total){
        $vmcount_output = "
        <tr>
            <td>Check for correct number of VMs</td>
            <td class=good>There are $count VMs!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    } else {
        $vmcount_output = "
        <tr>
            <td>Check for correct number of VMs</td>
            <td class=bad>There are $count VMs and should have been $total!</td>
            <td class=bad>Please check the VMs!</td>
        </tr>
        "
    }
    $vmcount_output | Out-File -FilePath $htmlfile -append

    foreach ($vm in $vms){
        Write-Verbose "Validating the VM name for $vm"
        $vmname = $vm.name
        Write-Verbose "The VM name is $vmname"
        $disksize = ($vm | Get-HardDisk).CapacityGB
        Write-Verbose "The disk size is $disksize"
        $view = Get-View $vm
        $memorysize = $vm.memorymb
        Write-Verbose "The memory size is $memorysize"
        $memhotadd = (Get-vm $vm | Get-View).config.MemoryHotAddEnabled
        Write-Verbose "Is memory hot add enabled: $memhotadd"
        $cpuhotadd = (Get-vm $vm | Get-View).config.CpuHotAddEnabled
        Write-Verbose "Is cpu hot add enabled: $cpuhotadd"
        $nics = Get-NetworkAdapter $vm
        Write-Verbose "$vmname has these nics $nics"
        $vmStartAction = (Get-VMStartPolicy $vm).StartAction
        Write-Verbose "The start action for $vmname is $vmStartAction"
        $vmStartDelay = (Get-VMStartPolicy $vm).StartDelay
        Write-Verbose "The start delay for $vmname is $vmStartDelay"
        $vmStartOrder = (Get-VMStartPolicy $vm).StartOrder
        Write-Verbose "The start order for $vmname is $vmStartOrder"
        $rightname = $false
        foreach ($name in $names){
            if ($vmname -match $name){
               $name_output = "
                <tr>
                    <td>Check VM name $vmname</td>
                    <td class=good>VM name is correct!</td>
                    <td class=good>Correct!</td>
                </tr>
                "
                $rightname = $true
            }
        }
        if ($rightname -eq $false){
            $name_output = "
            <tr>
                <td>Check VM name $vmname</td>
                <td class=bad>VM name is NOT correct!</td>
                <td class=bad>Please check the name on the VM $vmname!</td>
            </tr>
            "
            $rightname = $true
        }

        Write-Verbose "Validating the disk size for $vmname"
        if ($disksize -eq $hddsize){
            $disksize_output = "
            <tr>
                <td>Check Hard Disk Size for $vmname</td>
                <td class=good>Hard Disk is $hddsize!</td>
                <td class=good>Correct!</td>
            </tr>
            "
        } else {
            $disksize_output = "
            <tr>
                <td>Check Hard Disk Size for $vmname</td>
                <td class=bad>Hard Disk is not $memsize!</td>
                <td class=bad>Please check the hard disk size!</td>
            </tr>
            "
        }
        $disksize_output | Out-File -FilePath $htmlfile -append
                
        Write-Verbose "Verifying that the disks are not Thin Provisioned"
        if ($view.config.hardware.Device.Backing.ThinProvisioned -eq $false){
            $thin_output = "
                <tr>
                    <td>Thin Provisioned</td>
                    <td class=good>The harddrive on $vmname is <b>NOT</b> Thin Provisioned</td>
                    <td class=good>Correct!</td>
                </tr>
                "
        } else {
            $thin_output = "
            <tr>
                <td>Thin Provisioned</td>
                <td class=bad>The harddrive on $vmname is Thin Provisioned</td>
                <td class=bad>Please recreate the hard drive as a thick provisioned drive!</td>
            </tr>
            "
        }
        $thin_output | Out-File -FilePath $htmlfile -append

        Write-Verbose "Validating the memory size for $vmname"
        if ($memorysize -eq $memsize){
            $memsize_output = "
            <tr>
                <td>Check Memory Size for $vmname</td>
                <td class=good>Memory size is $hddsize!</td>
                <td class=good>Correct!</td>
            </tr>
            "
        } else {
            $memsize_output = "
            <tr>
                <td>Check Memory Size for $vmname</td>
                <td class=bad>Memory size is not $memsize!</td>
                <td class=bad>Please check the memory!</td>
            </tr>
            "
        }
        $memsize_output | Out-File -FilePath $htmlfile -append

        Write-Verbose "Validating that Memory Hot Add is enabled for $vmname"
        If ($memhotadd -eq $true){
            $memoutput = "
            <tr>
                <td>Memory Hot Add</td>
                <td class=good>Memory Hot Add is Enabled on $vmname!</td>
                <td class=good>Correct!</td>
            </tr>
            "
        } else {
            $memoutput = "
            <tr>
                <td>Memory Hot Add</td>
                <td class=bad>Memory Hot Add is disabled on $vmname!</td>
                <td class=bad>Please enable memory hot add!</td>
            </tr>
            "
        }
        $memoutput | Out-File -FilePath $htmlfile -append

        Write-Verbose "Validating that CPU Hot Add is enabled for $vmname"
        If ($cpuhotadd -eq $true){
            $cpuoutput = "
            <tr>
                <td>CPU Hot Add</td>
                <td class=good>CPU Hot Add is Enabled on $vmname!</td>
                <td class=good>Correct!</td>
            </tr>
            "
        } else {
            $cpuoutput = "
            <tr>
                <td>CPU Hot Add</td>
                <td class=bad>CPU Hot Add is disabled on $vmname!</td>
                <td class=bad>Please enable CPU hot add!</td>
            </tr>
            "
        }
        $cpuoutput | Out-File -FilePath $htmlfile -append

        Write-Verbose "Validating that the network adapters are VMNET3"
        foreach ($nic in $nics){
            $name = $nic.Name
            $type = $nic.type
            if ($type -eq 'Vmxnet3'){
                Write-Verbose "Correct NIC type"
                $netoutput = "
                <tr>
                    <td>VM Network Adapter Type</td>
                    <td class=good>The network adapter $name is VMNET3 adapter on VM $vmname!</td>
                    <td class=good>Correct</td>
                </tr>
                "
            } else {
                Write-Verbose "NIC is not a VMNET3 adapter"
                $netoutput = "
                <tr>
                    <td>VM Network Adapter Type</td>
                    <td class=bad>The network adapter $name is <b>NOT</b> VMNET3 adapter on VM $vmname!</td>
                    <td class=bad>Please investigate!</td>
                </tr>
                "
            }
        }
        $netoutput | Out-File -FilePath $htmlfile -append

        Write-Verbose "Validating that the vm has autostart enabled and delay start set correctly"
        if ($vmname -match "dc" -or $vmname -match "domaincontroller"){
            If ($vmStartAction -eq $true){
                $vmstartactionoutput = "
                <tr>
                    <td>VM Autostart</td>
                    <td class=good>The VM named $vmname is set to autostart!</td>
                    <td class=good>Correct!</td>
                </tr>
                "
            } else {
                $vmstartactionoutput = "
                <tr>
                    <td>VM Autostart</td>
                    <td class=bad>The VM named $vmname is <b>NOT</b> set to autostart!</td>
                    <td class=bad>Please enable autostart on the VM $vmname!</td>
                </tr>
                "
            }
            $vmstartactionoutput | Out-File -FilePath $htmlfile -append

            If ($vmStartDelay -eq 0){
                $vmStartDelayoutput = "
                <tr>
                    <td>VM StartDelay</td>
                    <td class=good>The VM named $vmname is set to 0 on StartDelay!</td>
                    <td class=good>Correct!</td>
                </tr>
                "
            } else {
                $vmStartDelayoutput = "
                <tr>
                    <td>VM StartDelay</td>
                    <td class=bad>The VM named $vmname is <b>NOT</b> set to 0 on StartDelay!</td>
                    <td class=bad>Please set the start delay to 0 on the VM $vmname!</td>
                </tr>
                "
            }
            $vmStartDelayoutput | Out-File -FilePath $htmlfile -append

            If ($vmStartOrder -eq 1){
                $vmStartOrderoutput = "
                <tr>
                    <td>VM StartOrder</td>
                    <td class=good>The VM named $vmname is set to 1 on StartOrder!</td>
                    <td class=good>Correct!</td>
                </tr>
                "
            } else {
                $vmStartOrderoutput = "
                <tr>
                    <td>VM StartOrder</td>
                    <td class=bad>The VM named $vmname is <b>NOT</b> set to 1 on StartOrder!</td>
                    <td class=bad>Please set the start order to 1 on the VM $vmname!</td>
                </tr>
                "
            }
            $vmStartOrderoutput | Out-File -FilePath $htmlfile -append
        } else {
            If ($vmStartAction -eq $true){
                $vmstartactionoutput = "
                <tr>
                    <td>VM Autostart</td>
                    <td class=good>The VM named $vmname is set to autostart!</td>
                    <td class=good>Correct!</td>
                </tr>
                "
            } else {
                $vmstartactionoutput = "
                <tr>
                    <td>VM Autostart</td>
                    <td class=bad>The VM named $vmname is <b>NOT</b> set to autostart!</td>
                    <td class=bad>Please enable autostart on the VM $vmname!</td>
                </tr>
                "
            }
            $vmstartactionoutput | Out-File -FilePath $htmlfile -append

            If ($vmStartDelay -eq 300){
                $vmStartDelayoutput = "
                <tr>
                    <td>VM StartDelay</td>
                    <td class=good>The VM named $vmname is set to 300 on StartDelay!</td>
                    <td class=good>Correct!</td>
                </tr>
                "
            } else {
                $vmStartDelayoutput = "
                <tr>
                    <td>VM StartDelay</td>
                    <td class=bad>The VM named $vmname is <b>NOT</b> set to 300 on StartDelay!</td>
                    <td class=bad>Please set the start delay to 300 on the VM $vmname!</td>
                </tr>
                "
            }
            $vmStartDelayoutput | Out-File -FilePath $htmlfile -append

            If ($vmStartOrder -gt 1){
                $vmStartOrderoutput = "
                <tr>
                    <td>VM StartOrder</td>
                    <td class=good>The VM named $vmname is set to 2 on StartOrder!</td>
                    <td class=good>Correct!</td>
                </tr>
                "
            } else {
                $vmStartOrderoutput = "
                <tr>
                    <td>VM StartOrder</td>
                    <td class=bad>The VM named $vmname is <b>NOT</b> set to 2 on StartOrder!</td>
                    <td class=bad>Please set the start order to 2 on the VM $vmname!</td>
                </tr>
                "
            }
            $vmStartOrderoutput | Out-File -FilePath $htmlfile -append
        }
    }
}

#endregion

#region Workflows

Workflow New-VM {
    param(
        [string]$server,
        [string[]]$names,
        [string]$ova,
        [string]$datastore,
        $session,
        $hddsize,
        $memsize
    )
    foreach -parallel($name in $names){

        $vm = InlineScript{

            Write-Verbose "Creating a VM for $Using:name"
            $verbosepreference = 'continue'
            . “C:\Program Files (x86)\VMware\Infrastructure\vSphere PowerCLI\Scripts\Initialize-PowerCLIEnvironment.ps1”
            Write-Verbose "Connecting to the host for $using:name"
            connect-viserver -server $Using:server -session $Using:session | Out-Null
            
            # Validate if the VM has been setup
            Write-Verbose "Getting a list of VMs"
            $vms = Get-VM
            $done = $false
            foreach ($vm in $using:vms){
                Write-Verbose "VM name is $using:vm"
                if ($Using:name -match $using:vm.name){
                    Write-Verbose "A VM named $using:vm already exist"
                    $done = $true
                }
            }

            if ($using:done -eq $false){
                ###  Create the new VM from Template
                Add-PSSnapin "VMware.VimAutomation.Core"
                ###  Create the new VM from OVF template
                Write-Verbose "Creating VM $Using:name from template"
                Import-VApp -Server $Using:server -VMHost $Using:server -Source "C:\SyncedFolder\Technical\Windows2016Template\Windows2016Template.ova" -Name $Using:name
                ###  Starting the new VM and waiting for it to boot
                Get-VM |Get-NetworkAdapter |Where-Object {$_.NetworkName -eq 'VM Network' } |Set-NetworkAdapter -NetworkName 'Buildroom' -Confirm:$false
                Write-Verbose "Starting $using:name "
                start-vm -VM $Using:name
                start-sleep -Seconds 60
            }
            Write-Verbose "Getting a list of VMs again"
            $vms2 = Get-VM
            foreach ($item in $using:vms2){
                Write-Verbose "VM name is $using:item"
                if ($Using:name -match $using:item.name){
                    Write-Verbose "A VM named $using:item already exist"
                    # Enable hot memory add for the VM
                    Write-Verbose "Validating that Memory Hot Add is enabled for $using:item"
                    $memhotadd = (Get-vm $using:item | Get-View)
                    if ($using:memhotadd.config.MemoryHotAddEnabled -eq $false){
                        Write-Verbose "Memory Hot Add was not enabled for $using:item...Enabling"
                        $vmConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
                        $vmConfigSpec.MemoryHotAddEnabled = "true"
                        $memhotadd.ReconfigVM($using:vmConfigSpec)
                    } else {
                        Write-Verbose "Memory Hot Add is already enabled on $using:item"
                    }

                    # Enable hot CPU add for the VM
                    Write-Verbose "Validating that CPU Hot Add is enabled for $using:item"
                    $cpuhotadd = (Get-vm $using:item | Get-View)
                    if ($using:cpuhotadd.config.CpuHotAddEnabled -eq $false){
                        Write-Verbose "CPU Hot Add was not enabled for $using:item...Enabling"
                        $vmConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
                        $vmConfigSpec.CPUHotAddEnabled = "true"
                        $cpuhotadd.ReconfigVM($using:vmConfigSpec)
                    } else {
                        Write-Verbose "Memory Hot Add is already enabled on $using:item"
                    }

                    ### Validate VM hard drive size ###
                    Write-Verbose "Validating the Hard Drive Size on $vm.name"
                    $harddrives = Get-HardDisk $using:item
                    foreach ($harddrive in $using:harddrives){
                        $capacity = $using:harddrive.capacityGB
                        Write-Verbose "The capacity of the hard drive for $using:item. is $capacity"
                        if ($using:capacity -lt $using:hddsize){
                            Write-Verbose "Increasing Hard Drive Size to $using:hddsize Gb for $using:item"
                            Set-HardDisk -HardDisk $using:harddrive -CapacityGB 120
                        }
                    }

                    # Changing net adapters
                    Write-Verbose "Starting the VM named $using:item"
                    $netadaptertype = (Get-NetworkAdapter $using:item).type
                    Write-Verbose "Network adapter type is $using:netadaptertype on $using:item"
                    if ($using:netadaptertype -ne 'vmxnet3'){
                        Write-Verbose "Removing old network adapter"
                        Get-NetworkAdapter -VM $using:item | Remove-NetworkAdapter -Confirm:$false
                        Write-Verbose "Adding a VMXNET3 adapter"
                        New-NetworkAdapter -VM $using:item -networkname "VM Network" -Type Vmxnet3 -StartConnected
                    }

                    # starting the VM
                    Write-Verbose "Starting the VM named $using:item"
                    $powerstate = (Get-vm $using:item).powerstate
                    if ($using:powerstate -ne 'PoweredOn'){
                        Write-Verbose "Starting $using:item"
                        Start-VM $using:item
                    } else{
                        Write-Verbose "$using:item is already powered on"
                    }

                    # Setting the autostart policy on the ho
                    Write-Verbose "Checking the host for autostart"
                    $HostStartAction = (Get-VMHostStartPolicy).Enabled
                    if ($using:HostStartAction -ne $true){
                        Write-Verbose "Settting autostart on the host"
                        Get-VMHostStartPolicy | Set-VMHostStartPolicy -Enabled $true -StartDelay 0
                    } else{
                        Write-Verbose "The host is already set to autostart"
                    }

                    # Setting the autostart policy on the VM
                    Write-Verbose "Checking the VM named $using:item to autostart"
                    $StartAction = (Get-vm $using:item | Get-VMStartPolicy).StartAction
                    Write-Verbose "The start action is $using:startaction"
                    if ($using:StartAction -ne 'PowerOn'){
                        Write-Verbose "Settting autostart on $using:item"
                        if ($using:item -match "dc" -or $using:item -match "domaincontroller"){
                            Write-Verbose "Server $using:item is a domain controller.  Setting start order to 1 and start delay to 0"
                            Get-VMStartPolicy $using:item | Set-VMStartPolicy -StartAction PowerOn -StartDelay 0 -StartOrder 1
                        } else {
                            Write-Verbose "Server $using:item is NOT a domain controller.  Setting start order to 2 and start delay to 300"
                            start-sleep 30
                            Get-VMStartPolicy $using:item | Set-VMStartPolicy -StartAction PowerOn -StartDelay 300 -StartOrder 2
                        }
                    } else{
                        Write-Verbose "$using:item is already set to autostart"
                    }
                }
            }            
        }
    }
}

#endregion

#region ConfigureESXi

$machine_name = ($esxcli.system.hostname.get()).FullyQualifiedDomainName

#####################################################
### Set the name of the ESX host ###

$esxcli.system.hostname.set($null,$NewName,$null)

#####################################################
### Create to local datastore on ESXi host ###

New-LocalDatastore

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
### Install Dell Open Manage Server Administrator ###

#Install-DellOpenManage

#####################################################
### Set Syslog Path ###

Set-SyslogPath

#endregion

#region SetupVMs

# create new VMs
Write-Verbose "Creating the new VMs"
New-VM -server $session -names $Names -ova $ova -datastore $datastore -session $global:DefaultVIServer.SessionSecret  -hddsize $hddcapacity -memsize $memcapacity

#$global:DefaultVIServer.SessionSecret 

# set VMtools
Write-Verbose "Ensuring that VM Tools is setup on the host"
New-VIProperty -Name ToolsVersion -ObjectType VirtualMachine -ValueFromExtensionProperty 'Config.tools.ToolsVersion' -Force
New-VIProperty -Name ToolsVersionStatus -ObjectType VirtualMachine -ValueFromExtensionProperty 'Guest.ToolsVersionStatus' -Force

#endregion

#region QualityControl

$htmlfile = "$localstorage\Installs\QC_$machine_name.html"

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
<table align=center border=1 width=80ForEach-Object>
<tr>
    <td><b><center>Quality Check Task</center></b></td>
    <td><b><center>Result (Green=GOOD, Red=BAD)</center></b></td>
    <td><b><center>Notes/Fix</center></b></td>
"

if (Test-Path c:\vmware\installs ) {
    $header | Out-File -FilePath $htmlfile
} else {
    New-Item c:\vmware\installs -ItemType directory
    $header | Out-File -FilePath $htmlfile
}

Write-Verbose "Obtaining information about the server"
Start-QCInformation 

Write-Verbose "Checking to see if the management network is set to static"
Start-QCStaticIP

Write-Verbose "Checking to see if the license has been applied"
Start-QCLicense

Write-Verbose "Checking for the local datastore and if it is named properly"
Start-QCLocalDatastore

Write-Verbose "Checking to see if Web Access has been installed"
Start-QCWebAccess

Write-Verbose "Checking to see if SSH and the ESXi Shell have been enabled"
Start-QCSSH

Write-Verbose "Checking to see if the NTP Time Server has been setup"
Start-QCNTPServer

Write-Verbose "Checking to see if the network is setup properly"
Start-QCNetworking

Write-Verbose "Checking to see if the network link speeds are greater than 1Gb"
Start-QCNetworkLinkSpeed

Write-Verbose "Checking to see if the time is correct"
Start-QCTime

#Write-Verbose "Checking to see if Dell Open Manage Server Administrator is setup properly"
#Start-QCDellOpenManage 

Write-Verbose "Checking to see if the Syslog path is set to the datastore"
Start-QCSyslogPath

Write-Verbose "Checking to see if the VM's have the right settings"
Start-QCVMs -server $ip -datastore $datastore -session $session -hddsize $hddcapacity -memsize $memcapacity

Write-Verbose "Checking to see if the host is set to autostart"
Start-QCHostAutoStart

#endregion

#region ScriptCleanup

# Set Root Password and reconnect
Set-VMHostAccount –UserAccount root –Password 'Pr0v1dyn!!'

# Enter License Key
#Install-License

#endregion

Invoke-Item $htmlfile
Stop-Transcript;