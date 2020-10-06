Start-Transcript -Path "C:\Windows\LTSvc\Scripts\WindowsServerQC_Transcript.rtf" -append -NoClobber

############################################
# define output file for appending to HTML

$verbosepreference = 'continue'
$os = (gwmi Win32_OperatingSystem -computer localhost).caption
$bios_output
$machine_name = gc env:computername
$QC_htmlfile = "C:\Windows\LTSvc\Scripts\WindowsServerQC_$machine_name.html"

$QCheader = "
<html>
<head>
    <style type=`"text/css`">
    .good {color:green;}
    .bad {color:red;}
    </style>
    <title>Server Quality Control report for [$machine_name]</title>
</head>
<body>
<h2 align=center>Server Quality Control report for [$machine_name]</h2>
<table align=center border=1 width=80%>
<tr>
    <td><b><center>Quality Check Task</center></b></td>
    <td><b><center>Result (Green=GOOD, Red=BAD)</center></b></td>
    <td><b><center>Notes/Fix</center></b></td>
"
$QCheader | Out-File -FilePath $QC_htmlfile



<#

#####################################################
LIST OF FUNCTIONS

OperatingSystemSection
LicenseKeySection
ApplicationSection
RolesSection
OSLocationCheck
DriveSizeCheck
RemoteDesktopConfig
DeviceCheck
EnableFeature
DisableIEESC
FirewallCheck
UACDisableCheck
AppCheck
WebrootCheck
ComputerInfo
WindowsUpdate
WMF5Check
ReceiveSideScaling
StaticIP
NicPower
VMXNET3
ActivatedCheck
NtpTime
Get-GPOPrinters
LabTechCheck
NTPSrvCheck
PSTools
ShadowCopy
OnDomain
CheckFSMO
ShortFileConfig
checkMapDriveGPO
DomainController

#>

#####################################################
#   Create the Operating System Configuration Section at the bottom

function OperatingSystemSection {
    # this just starts a new section near the bottom for license keys as I can decode them
    $section = "
    </table>
    <h2 align=center>Operating System Configuration</h2>
    <table align=center border=1 width=80%>
    <tr>
        <td><b><center>Quality Check Task</center></b></td>
        <td><b><center>Result (Green=GOOD, Red=BAD)</center></b></td>
        <td><b><center>Notes/Fix</center></b></td>
    </tr>
    "
    $section  | Out-File -FilePath $qc_htmlfile -append

}

#####################################################
#   Create the license Key Section at the bottom

function LicenseKeySection {
    # this just starts a new section near the bottom for license keys as I can decode them
    $section = "
    </table>
    <h2 align=center>Software Licensing</h2>
    <table align=center border=1 width=80%>
    <tr>
        <td><b><center>Software Package</center></b></td>
        <td><b><center>License Key</center></b></td>
    </tr>
    "
    $section  | Out-File -FilePath $qc_htmlfile -append

}

#####################################################
#   Create the Application Section at the bottom

function ApplicationSection {
    # this just starts a new section near the bottom for client specific settings
    $section = "
    </table>
    <h2 align=center>Application Configuration Section</h2>
    <table align=center border=1 width=80%>
    <tr>
        <td><b><center>Quality Check Task</center></b></td>
        <td><b><center>Result (Green=GOOD, Red=BAD)</center></b></td>
        <td><b><center>Notes/Fix</center></b></td>
    </tr>
    "
    $section  | Out-File -FilePath $qc_htmlfile -append

}

#####################################################
#   Create the Operating System Configuration Section at the bottom

function RolesSection {
    # this just starts a new section near the bottom for license keys as I can decode them
    $section = "
    </table>
    <h2 align=center>Roles and Features Configuration</h2>
    <table align=center border=1 width=80%>
    <tr>
        <td><b><center>Quality Check Task</center></b></td>
        <td><b><center>Result (Green=GOOD, Red=BAD)</center></b></td>
        <td><b><center>Notes/Fix</center></b></td>
    </tr>
    "
    $section  | Out-File -FilePath $qc_htmlfile -append

}

############################################
# Check for what drive Windows is installed on

function OSLocationCheck {
    $sysroot = gc env:systemroot
    $drivesize = ((get-WmiObject win32_logicaldisk | where {$_.deviceid -match "C:"}).size/1GB).ToString("#.##")

    if($sysroot -match "C:") {    
    $section = "
        <tr>
            <td>Operating System install location</td>
            <td class=good>Installed at $sysroot!</td>
            <td class=good>Correct</td>
        </tr>
        "
    } else {
    $section = "
        <tr>
            <td>Operating System install location</td>
            <td class=bad>Installed at $sysroot!</td>
            <td class=bad>REBUILD THE MACHINE!</td>
        </tr>
        "
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

############################################
# Check for what drive Windows is installed on

function DriveSizeCheck {

    $drivesize = ((get-WmiObject win32_logicaldisk | where {$_.deviceid -match "C:"}).size/1GB).ToString("#.##")

    if($drivesize -ge "119.00") {    
    $section = "
        <tr>
            <td>System Drive Size</td>
            <td class=good>Drive is the right size!</td>
            <td class=good>Correct</td>
        </tr>
        "
    } else {
    $section = "
        <tr>
            <td>System Drive Size</td>
            <td class=bad>Drive size $drivesize is not correct!</td>
            <td class=bad>REBUILD THE MACHINE or fix the volume size!</td>
        </tr>
        "
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

############################################
# Check to see if Remote Desktop is enabled

Function RemoteDesktopConfig {
    if ((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0){
    $section = "
        <tr>
            <td>Remote Desktop Check</td>
            <td class=good>Remote Desktop connections are enabled</td>
            <td class=good>Correct</td>
        </tr>
        "
    } 
    else {
    $section = "
        <tr>
            <td>Remote Desktop Check</td>
            <td class=bad>Remote Desktop connections are NOT enabled</td>
            <td class=bad>Please enable it!</td>
        </tr>
        "
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

############################################
# Check to see if there are any uninstalled devices

function DeviceCheck {
    $hw_check = Get-WmiObject Win32_PnPEntity | Where-Object {$_.ConfigManagerErrorCode -ne 0}
    $hw_count = $hw_check.count

    if($hw_count -ge 0) {
        $hw_check | ForEach-Object {
            $dev_desc= ("Device "+ $_.Description)
            $dev_devID= ($_.DeviceID)
        
    
            $section = "
            <tr>
                <td>Hardware Status Check</td>
                <td class=bad>$dev_desc has an error!</td>
                <td class=bad>Go into Device Manager and fix $dev_devID !</td>
            </tr>
            "
            $section | Out-File -FilePath $qc_htmlfile -append
        }
    } elseif($hw_count -eq 0 -or $hw_count -eq $null) {
        $section = "
        <tr>
            <td>Hardware Status Check</td>
            <td class=good>There are no items with errors!</td>
            <td class=good>Correct</td>
        </tr>
        "
        $section | Out-File -FilePath $qc_htmlfile -append
    }
}

############################################
# Check to see if Windows Feature is installed

Function EnableFeature {
    param($feature)
    $name = (Get-WindowsFeature -Name $feature).DisplayName
    $enabled = (Get-WindowsFeature -Name $feature).Installed
    if ($enabled -eq $True){
        $section = "
        <tr>
            <td>$name - Feature Status Check</td>
            <td class=good>$name is installed!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    } else {
        $section = "
        <tr>
            <td>$name - Feature Status Check</td>
            <td class=bad>$name is NOT installed!</td>
            <td class=bad>Go install $name!</td>
        </tr>
        "
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

############################################
# Check to see if IE Enhanced Security Configuration is enabled

Function DisableIEESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    $enabled = (Get-ItemProperty -Path $AdminKey -Name "IsInstalled").isinstalled
    if ($enabled -eq 0){
        $section = "
        <tr>
            <td>IE Enhanced Security Configuration Status Check</td>
            <td class=good>IE Enhanced Security Configuration has been disabled for admins!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    } else {
        $section = "
        <tr>
            <td>IE Enhanced Security Configuration Status Check</td>
            <td class=bad>IE Enhanced Security Configuration is still enabled!</td>
            <td class=bad>Go disable IE Enhanced Security Configuration!</td>
        </tr>
        "
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

############################################
# Check to see if the Windows Firewall is configured properly

function FirewallCheck {

    $rules = get-netfirewallrule| where {$_.displayname -match "Remote Desktop" -or $_.displayname -match "Echo Request - ICMPv4" -and ($_.profile -match "domain" -or $_.profile -match "private")}
    
    foreach ($item in $rules) {
        $name = $item.displayname
        $enabled = $item.Enabled
        if($enabled -eq $true) {
            $section = "
            <tr>
                <td>Windows Firewall Check</td>
                <td class=good>The firewall rule $name is enabled!.</td>
                <td class=good>Correct</td>
            </tr>
            "  
            $section | Out-File -FilePath $qc_htmlfile -append
          
        } else {
            $section = "
            <tr>
                <td>Windows Firewall Check</td>
                <td class=bad>$name is not enabled.</td>
                <td class=bad>Please check the firewall settings.</td>
            </tr>
            "  
            $section | Out-File -FilePath $qc_htmlfile -append 
        }
    }
}

############################################
# Check to see if UAC is disabled

function UACDisableCheck {

    $uac = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $uacquery = Get-ItemProperty -path $uac -name EnableLUA
    $uacval = $uacquery.EnableLUA

    if($uacval -eq 1) {
        # Do an initial query to see if it's Windows XP or Windows Vista/7
        $oscheck_query = gwmi Win32_OperatingSystem -computer localhost
        $osversion = $oscheck_query.Caption
        if ($osversion -match "Microsoft Windows 8"){
        $section = "
        <tr>
            <td>User Account Control Check</td>
            <td class=good>UAC is enabled.</td>
            <td class=good>Correct because it is Windows 8</td>
        </tr>
        "
        } else {
        $section = "
        <tr>
            <td>User Account Control Check</td>
            <td class=bad>UAC is still enabled.</td>
            <td class=bad>Disable UAC!</td>
        </tr>
        "
        }
    } else {
        $section = "
        <tr>
            <td>User Account Control Check</td>
            <td class=good>UAC is disabled.</td>
            <td class=good>Correct</td>
        </tr>
        "
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

############################################
# Check to see if Java is installed and up to date

function AppCheck {
[CmdletBinding()]
        param (
        [parameter(ValueFromPipeLine = $True,Mandatory=$true)]
        [string[]]$AppName,
        [parameter(ValueFromPipeLine = $True,Mandatory=$true)]
        [string[]]$TargetVersion
        )
BEGIN {}
PROCESS {
        $app = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
        Foreach{gp $_.PSPath} | Where{$_.DisplayName -match $AppName -and $_.DisplayName -ne "java auto updater"}
    
        if ($app -eq $null ) {
            $app = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                    Foreach{gp $_.PSPath} | Where{$_.DisplayName -match $AppName -and $_.DisplayName -ne "java auto updater"}
        }
        $appver = $app.displayversion

        # If it doesn't exist...
        if($appver -eq $null) {
            $section = "
                <tr>
                    <td>$AppName Check</td>
                    <td class=bad>NOT INSTALLED</td>
                    <td class=bad>$AppName $TargetVersion not installed!</a></td>
                </tr>
                "
        } elseif($appver -lt $TargetVersion) {
            $section = "
                <tr>
                    <td>$AppName Check</td>
                    <td class=bad>Version $appver is not the latest version!</td>
                    <td class=bad>Update to $AppName $TargetVersion !</a></td>
                </tr>
                "
        } elseif($appver -eq $TargetVersion) {
            $section = "
                <tr>
                    <td>$AppName Check</td>
                    <td class=good>$AppName installed and is version $TargetVersion .</td>
                    <td class=good>Correct</td>
                </tr>
                "
        } elseif($appver -gt $TargetVersion) {
            $section = "
                <tr>
                    <td>$AppName Check</td>
                    <td class=Neutral>$AppName installed but is version $appver . $TargetVersion is no longer the latest version.</td>
                    <td class=Neutral>Update Default Build and QC scripts</td>
                </tr>
                "
        }
        $section | Out-File -FilePath $qc_htmlfile -append
    }
}

############################################
# Check to see if Webroot is installed and updated.

function WebrootCheck {
    #### set the target version ####
    $Webroot_target_version= "9.8.100"

    # query the version
    $Webrootquery = gwmi -class Win32_Product | where-object {$_.name -match "Webroot"}
    $Webroot_ver = $Webrootquery.version

    ### QUERY AV CLIENT ###
    if($Webrootquery -eq $NULL) {
        $section = "
        <tr>
            <td>Webroot Check</td>
            <td class=bad>Webroot SecureAnywhere $Webroot_target_version is not installed!</td>
            <td class=bad>Please install Webroot SecureAnywhere $Webroot_target_version</td>
        </tr>
        "
    } else {
        if($Webrootquery.version -ne $Webroot_target_version){
            $section = "
            <tr>
                <td>Webroot Check</td>
                <td class=bad>Webroot SecureAnywhere is version: $Webroot_ver.</td>
                <td class=bad>Please remove this version and install $Webroot_target_version</td>
            </tr>
            "
        } else {
            $section = "
            <tr>
                <td>Webroot Check</td>
                <td class=good>Webroot SecureAnywhere is version: $Webroot_ver.</td>
                <td class=good>Correct</td>
            </tr>
            "
        }  
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

############################################
# Check the Computer Information

function ComputerInfo {
    $biosquery = gwmi -class Win32_BIOS
    # assign values
    $bios_manu = $biosquery.Manufacturer
    $bios_name = $biosquery.Name
    $bios_sn = $biosquery.SerialNumber
    $bios_ver = $biosquery.Version

    $bios_output = "<tr>
        <td>Computer Information Check</td>
        <td>Manufacturer: $bios_manu
            <br />Serial: $bios_sn
            <br />Version: $bios_ver</td>
        <td>Verify latest version.</td>
        </tr>
    "

    $bios_output | Out-File -FilePath $qc_htmlfile -append
}

#############################################
#  Get list of updates left

function WindowsUpdates {
    Write-Verbose "Checking for available updates"
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    $availableupdates = $SearchResult.Updates
    $upd_count= $availableupdates.count
    Write-Verbose "There are $upd_count updates available"

    if($upd_count -ge 1) {
        $section = "
            <tr>
                <td>Windows Update Status Check</td>
                <td class=bad>There are $upd_count updates available!</td>
                <td class=bad>Please run Windows Updates!</td>
            </tr>
            "
    } elseif($upd_count -eq 0 -or $upd_count -eq $null) {
        $section = "
        <tr>
            <td>Windows Update Status Check</td>
            <td class=good>There are no updates available!</td>
            <td class=good>Correct</td>
        </tr>
        "
        $section | Out-File -FilePath $qc_htmlfile -append
   }
   $section | Out-File -FilePath $qc_htmlfile -append
}

############################################
# Check for WMF 5.0 being installed on the server

function WMF5Check {

    $wmf = $PSVersionTable.PSVersion.Major
   
    if($wmf -eq 5) {    
    $section = "
        <tr>
            <td>WMF 5.0 Check</td>
            <td class=good>Windows Management Framework 5.0 is installed!</td>
            <td class=good>Correct</td>
        </tr>
        "
    } 
    else {
    $section = "
        <tr>
            <td>WMF 5.0 Check</td>
            <td class=bad>Windows Management Framework 5.0 is not installed</td>
            <td class=bad>Please install Windows Management Framework 5.0!</td>
        </tr>
        "
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

#############################################
#  Get the status of Recieve Side Scaling

function ReceiveSideScaling { 
    $status = (Get-NetAdapter | Get-NetAdapterRss).Enabled
             
    if ($status -eq $true) {
        $section = "
        <tr>
            <td>Receive Side Scaling Check</td>
            <td class=good>Receive Side Scaling is enabled!</td>
            <td class=good>Correct</td>
        </tr>
        "
    } else {
        $section = "
        <tr>
            <td>Receive Side Scaling Check</td>
            <td class=bad>Receive Side Scaling is disabled!</td>
            <td class=bad>Please enable it!</td>
        </tr>
        "
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

#############################################
#  Get the status of Static IP

function StaticIP {
    Write-Verbose "Getting the network adapters"
    $adapters = Get-NetAdapter | Where {$_.Status -eq "Up"}
    foreach ($adapter in $adapters){
        $name = $adapter.Name
        $description = $adapter.InterfaceDescription

        Write-Verbose "Checking the network adapters for static IP's"
        $status = (Get-NetIPinterface | where {$_.ifAlias -eq $name -and $_.AddressFamily -eq "IPv4"}).dhcp
        if ($status -eq 'Disabled') {
            $section = "
            <tr>
                <td>Static IP Check</td>
                <td class=good>$description has a static IP!</td>
                <td class=good>Correct</td>
            </tr>
            "
        } else {
            $section = "
            <tr>
                <td>Static IP  Check</td>
                <td class=bad>DHCP is enabled on $description!</td>
                <td class=bad>Please set a static IP on $description</td>
            </tr>
            "
        }
        $section | Out-File -FilePath $qc_htmlfile -append
    }
}

#############################################
#  Get the status of the NIC's power

function NicPower { 
[CmdletBinding()]
        param ()
BEGIN {}
PROCESS {
        $namespace = "root\WMI"
        $status = $false
        $nic_name = ''
        Get-WmiObject Win32_NetworkAdapter -filter "AdapterTypeId=0" | where {$_.PhysicalAdapter -eq $true} |
             Foreach-Object {
                $strNetworkAdapterID=$_.PNPDeviceID.ToUpper()
                $nic_name=$_.Name
                Write-Verbose $nic_name
                Get-WmiObject -class MSPower_DeviceEnable -Namespace $namespace |
                     Foreach-Object {
                        if($_.InstanceName.ToUpper().startsWith($strNetworkAdapterID)) {
                            if ($_.Enable) {
                                $status = $true
                            }
                        }
                    }
            if ($status -eq $true -and $nic_name -notmatch "Virtual") {
            $section = "
            <tr>
                <td>NIC Power Status Check</td>
                <td class=bad>The power on $nic_name is still enabled!</td>
                <td class=bad>Please turn off the NIC Power in device manager!</td>
            </tr>
            "
            }
        }
        if ($status -eq $FALSE) {
            $section = "
            <tr>
                <td>NIC Power Status Check</td>
                <td class=good>The NIC power is disabled!</td>
                <td class=good>Correct</td>
            </tr>
            "
        }
        $section | Out-File -FilePath $qc_htmlfile -append
    }
END {}
}

#############################################
#  Get the status of VMXNET3

function VMXNET3 {
    $Manufacturer = (get-wmiobject win32_computersystem).Manufacturer
    if ($Manufacturer -ne 'VMware, Inc.'){
        $section = "
            <tr>
                <td>VMXNET3 Check</td>
                <td class=good>The server is not a VMware VM!</td>
                <td class=good>Correct!</td>
            </tr>
            "
        $section | Out-File -FilePath $qc_htmlfile -append
    } else {
        Write-Verbose "Getting the network adapters"
        $adapters = Get-NetAdapter | Where {$_.Status -eq "Up"}
        foreach ($adapter in $adapters){
            $name = $adapter.Name
            $description = $adapter.InterfaceDescription
            Write-Verbose "Checking the type of adapter $name"
            Write-Verbose "Adapter is a $description"
            if ($description -notmatch "vmxnet3") {
                $section = "
                <tr>
                    <td>VMXNET3 Check</td>
                    <td class=bad>$name is a $description adapter!</td>
                    <td class=bad>Please recreate $name as a VMXNET3 adapter!</td>
                </tr>
                "
            } else {
                $section = "
                <tr>
                    <td>VMXNET3 Check</td>
                    <td class=good>$name is a VMXNET3 adapter!</td>
                    <td class=good>Correct!</td>
                </tr>
                "
            }
            $section | Out-File -FilePath $qc_htmlfile -append
        }
    }
}

############################################
# Check to see if Windows is activated

function ActivatedCheck {

    $activated = (Get-CimInstance -ClassName SoftwareLicensingProduct | where PartialProductKey).licensestatus

    if($activated -eq 1) {    
    $section = "
        <tr>
            <td>Windows Activation Check</td>
            <td class=good>Windows is activated</td>
            <td class=good>Correct</td>
        </tr>
        "
    } 
    else {
    $section = "
        <tr>
            <td>Windows Activation Check</td>
            <td class=bad>Windows is NOT activated</td>
            <td class=bad>Please activate Windows</td>
        </tr>
        "
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

#############################################
#  Checks to see if the NTP time is close to the server's time

Function NtpTime {

<#
.Synopsis
   Gets (Simple) Network Time Protocol time (SNTP/NTP, rfc-1305, rfc-2030) from a specified server
.DESCRIPTION
   This function connects to an NTP server on UDP port 123 and retrieves the current NTP time.
   Selected components of the returned time information are decoded and returned in a PSObject.
.PARAMETER Server
   The NTP Server to contact.  Uses pool.ntp.org by default.
.PARAMETER MaxOffset
   The maximum acceptable offset between the local clock and the NTP Server, in milliseconds.
   The script will throw an exception if the time difference exceeds this value (on the assumption
   that the returned time may be incorrect).  Default = 10000 (10s).
.PARAMETER NoDns
   (Switch) If specified do not attempt to resolve Version 3 Secondary Server ReferenceIdentifiers.
.EXAMPLE
   Get-NtpTime uk.pool.ntp.org
   Gets time from the specified server.
.EXAMPLE
   Get-NtpTime | fl *
   Get time from default server (pool.ntp.org) and displays all output object attributes.
.OUTPUTS
   A PSObject containing decoded values from the NTP server.  Pipe to fl * to see all attributes.
.FUNCTIONALITY
   Gets NTP time from a specified server.
#>

    [CmdletBinding()]
    [OutputType()]
    Param (
        [String]$Server = 'pool.ntp.org',
        [Int]$MaxOffset = 10000,     # (Milliseconds) Throw exception if network time offset is larger
        [Switch]$NoDns               # Do not attempt to lookup V3 secondary-server referenceIdentifier
    )


    # NTP Times are all UTC and are relative to midnight on 1/1/1900
    $StartOfEpoch=New-Object DateTime(1900,1,1,0,0,0,[DateTimeKind]::Utc)   


    Function OffsetToLocal($Offset) {
    # Convert milliseconds since midnight on 1/1/1900 to local time
        $StartOfEpoch.AddMilliseconds($Offset).ToLocalTime()
    }


    # Construct a 48-byte client NTP time packet to send to the specified server
    # (Request Header: [00=No Leap Warning; 011=Version 3; 011=Client Mode]; 00011011 = 0x1B)

    [Byte[]]$NtpData = ,0 * 48
    $NtpData[0] = 0x1B    # NTP Request header in first byte


    $Socket = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,
                                            [Net.Sockets.SocketType]::Dgram,
                                            [Net.Sockets.ProtocolType]::Udp)
    $Socket.SendTimeOut = 2000  # ms
    $Socket.ReceiveTimeOut = 2000   # ms

    Try {
        $Socket.Connect($Server,123)
    }
    Catch {
        Write-Error "Failed to connect to server $Server"
        Throw 
    }


# NTP Transaction -------------------------------------------------------

        $t1 = Get-Date    # t1, Start time of transaction... 
    
        Try {
            [Void]$Socket.Send($NtpData)
            [Void]$Socket.Receive($NtpData)  
        }
        Catch {
            Write-Error "Failed to communicate with server $Server"
            Throw
        }

        $t4 = Get-Date    # End of NTP transaction time

# End of NTP Transaction ------------------------------------------------

    $Socket.Shutdown("Both") 
    $Socket.Close()

# We now have an NTP response packet in $NtpData to decode.  Start with the LI flag
# as this is used to indicate errors as well as leap-second information

    # Check the Leap Indicator (LI) flag for an alarm condition - extract the flag
    # from the first byte in the packet by masking and shifting 

    $LI = ($NtpData[0] -band 0xC0) -shr 6    # Leap Second indicator
    If ($LI -eq 3) {
        Throw 'Alarm condition from server (clock not synchronized)'
    } 

    # Decode the 64-bit NTP times

    # The NTP time is the number of seconds since 1/1/1900 and is split into an 
    # integer part (top 32 bits) and a fractional part, multipled by 2^32, in the 
    # bottom 32 bits.

    # Convert Integer and Fractional parts of the (64-bit) t3 NTP time from the byte array
    $IntPart = [BitConverter]::ToUInt32($NtpData[43..40],0)
    $FracPart = [BitConverter]::ToUInt32($NtpData[47..44],0)

    # Convert to Millseconds (convert fractional part by dividing value by 2^32)
    $t3ms = $IntPart * 1000 + ($FracPart * 1000 / 0x100000000)

    # Perform the same calculations for t2 (in bytes [32..39]) 
    $IntPart = [BitConverter]::ToUInt32($NtpData[35..32],0)
    $FracPart = [BitConverter]::ToUInt32($NtpData[39..36],0)
    $t2ms = $IntPart * 1000 + ($FracPart * 1000 / 0x100000000)

    # Calculate values for t1 and t4 as milliseconds since 1/1/1900 (NTP format)
    $t1ms = ([TimeZoneInfo]::ConvertTimeToUtc($t1) - $StartOfEpoch).TotalMilliseconds
    $t4ms = ([TimeZoneInfo]::ConvertTimeToUtc($t4) - $StartOfEpoch).TotalMilliseconds
 
    # Calculate the NTP Offset and Delay values
    $Offset = (($t2ms - $t1ms) + ($t3ms-$t4ms))/2
    $Delay = ($t4ms - $t1ms) - ($t3ms - $t2ms)
<#
    # Make sure the result looks sane...
    If ([Math]::Abs($Offset) -gt $MaxOffset) {
        # Network server time is too different from local time
        Throw "Network time offset exceeds maximum ($($MaxOffset)ms)"
    }#>

    # Decode other useful parts of the received NTP time packet

    # We already have the Leap Indicator (LI) flag.  Now extract the remaining data
    # flags (NTP Version, Server Mode) from the first byte by masking and shifting (dividing)

    $LI_text = Switch ($LI) {
        0    {'no warning'}
        1    {'last minute has 61 seconds'}
        2    {'last minute has 59 seconds'}
        3    {'alarm condition (clock not synchronized)'}
    }

    $VN = ($NtpData[0] -band 0x38) -shr 3    # Server version number

    $Mode = ($NtpData[0] -band 0x07)     # Server mode (probably 'server')
    $Mode_text = Switch ($Mode) {
        0    {'reserved'}
        1    {'symmetric active'}
        2    {'symmetric passive'}
        3    {'client'}
        4    {'server'}
        5    {'broadcast'}
        6    {'reserved for NTP control message'}
        7    {'reserved for private use'}
    }

    # Other NTP information (Stratum, PollInterval, Precision)

    $Stratum = [UInt16]$NtpData[1]   # Actually [UInt8] but we don't have one of those...
    $Stratum_text = Switch ($Stratum) {
        0                            {'unspecified or unavailable'}
        1                            {'primary reference (e.g., radio clock)'}
        {$_ -ge 2 -and $_ -le 15}    {'secondary reference (via NTP or SNTP)'}
        {$_ -ge 16}                  {'reserved'}
    }

    $PollInterval = $NtpData[2]              # Poll interval - to neareast power of 2
    $PollIntervalSeconds = [Math]::Pow(2, $PollInterval)

    $PrecisionBits = $NtpData[3]      # Precision in seconds to nearest power of 2
    # ...this is a signed 8-bit int
    If ($PrecisionBits -band 0x80) {    # ? negative (top bit set)
        [Int]$Precision = $PrecisionBits -bor 0xFFFFFFE0    # Sign extend
    } else {
        # ..this is unlikely - indicates a precision of less than 1 second
        [Int]$Precision = $PrecisionBits   # top bit clear - just use positive value
    }
    $PrecisionSeconds = [Math]::Pow(2, $Precision)
    


    # Determine the format of the ReferenceIdentifier field and decode
    
    If ($Stratum -le 1) {
        # Response from Primary Server.  RefId is ASCII string describing source
        $ReferenceIdentifier = [String]([Char[]]$NtpData[12..15] -join '')
    }
    Else {

        # Response from Secondary Server; determine server version and decode

        Switch ($VN) {
            3       {
                        # Version 3 Secondary Server, RefId = IPv4 address of reference source
                        $ReferenceIdentifier = $NtpData[12..15] -join '.'

                        If (-Not $NoDns) {
                            If ($DnsLookup =  Resolve-DnsName $ReferenceIdentifier -QuickTimeout -ErrorAction SilentlyContinue) {
                                $ReferenceIdentifier = "$ReferenceIdentifier <$($DnsLookup.NameHost)>"
                            }
                        }
                        Break
                    }

            4       {
                        # Version 4 Secondary Server, RefId = low-order 32-bits of  
                        # latest transmit time of reference source
                        $ReferenceIdentifier = [BitConverter]::ToUInt32($NtpData[15..12],0) * 1000 / 0x100000000
                        Break
                    }

            Default {
                        # Unhandled NTP version...
                        $ReferenceIdentifier = $Null
                    }
        }
    }


    # Calculate Root Delay and Root Dispersion values
    
    $RootDelay = [BitConverter]::ToInt32($NtpData[7..4],0) / 0x10000
    $RootDispersion = [BitConverter]::ToUInt32($NtpData[11..8],0) / 0x10000


    # Finally, create output object and return

    $NtpTimeObj = [PSCustomObject]@{
        NtpServer = $Server
        NtpTime = OffsetToLocal($t4ms + $Offset)
        Offset = $Offset
        OffsetSeconds = [Math]::Round($Offset/1000, 3)
        Delay = $Delay
        t1ms = $t1ms
        t2ms = $t2ms
        t3ms = $t3ms
        t4ms = $t4ms
        t1 = OffsetToLocal($t1ms)
        t2 = OffsetToLocal($t2ms)
        t3 = OffsetToLocal($t3ms)
        t4 = OffsetToLocal($t4ms)
        LI = $LI
        LI_text = $LI_text
        NtpVersionNumber = $VN
        Mode = $Mode
        Mode_text = $Mode_text
        Stratum = $Stratum
        Stratum_text = $Stratum_text
        PollIntervalRaw = $PollInterval
        PollInterval = New-Object TimeSpan(0,0,$PollIntervalSeconds)
        Precision = $Precision
        PrecisionSeconds = $PrecisionSeconds
        ReferenceIdentifier = $ReferenceIdentifier
        RootDelay = $RootDelay
        RootDispersion = $RootDispersion
        Raw = $NtpData   # The undecoded bytes returned from the NTP server
    }

    # Set the default display properties for the returned object
    [String[]]$DefaultProperties =  'NtpServer', 'NtpTime', 'OffsetSeconds', 'NtpVersionNumber', 
                                    'Mode_text', 'Stratum', 'ReferenceIdentifier'

    # Create the PSStandardMembers.DefaultDisplayPropertySet member
    $ddps = New-Object Management.Automation.PSPropertySet('DefaultDisplayPropertySet', $DefaultProperties)

    # Attach default display property set and output object
    $PSStandardMembers = [Management.Automation.PSMemberInfo[]]$ddps 
    $NtpTimeObj | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $PSStandardMembers -PassThru
    $time = $NtpTimeObj.NtpTime
    $date = Get-Date -Format G
    $difference = New-TimeSpan -Start $date -End $time

    if ($difference.days -ne 0 -or $difference.Hours -ne 0){
        $section= "
            <tr>
                <td>Current Time Setting</td>
                <td class=bad>Current time is off by more than an hour</td>
                <td class=bad>Please change the time</td>
            </tr>    "    
    } elseif ($difference.days -eq 0 -and $difference.Hours -eq 0 -and $difference.minutes -gt 10 -or $difference.minutes -lt -10){
        $section= "
            <tr>
                <td>Current Time Setting</td>
                <td class=bad>Current time is off by more than 10 minutes</td>
                <td class=bad>Please change the time</td>
            </tr> "
    } else {
        $section= "
            <tr>
                <td>Current Time Setting</td>
                <td class=good>Current Time is within 10 mins</td>
                <td class=good>Current NTP time is $time</td>
            </tr> "
    }
    $section | out-file -filepath $qc_htmlfile -append
}

############################################
# Check to see if the GPO's are setup to deploy printers

function Get-GPOPrinters {
    <#
    .SYNOPSIS     
    The script finds all shared printers deployed with GPO (both deployed printers GPP.) in your domain. 
    .NOTES     
               File Name: Get-GPOPrinters.ps1     
               Author   : Johan Dahlbom, johan[at]dahlbom.eu     
               The script are provided “AS IS” with no guarantees, no warranties, and it confer no rights. 
               Blog     : 365lab.net
    #>
    #Import the required module GroupPolicy
    try {
    Import-Module GroupPolicy -ErrorAction Stop
    } catch {
    throw "Module GroupPolicy not Installed"
    }
    $GPO = Get-GPO -All
 
    foreach ($Policy in $GPO){
 
        $GPOID = $Policy.Id
        $GPODom = $Policy.DomainName
        $GPODisp = $Policy.DisplayName
        $PrefPath = "\\$($GPODom)\SYSVOL\$($GPODom)\Policies\{$($GPOID)}\User\Preferences"
 
        #Get GP Preferences Printers
        $XMLPath = "$PrefPath\Printers\Printers.xml"
        if (Test-Path "$XMLPath") {
            [xml]$PrintXML = Get-Content "$XMLPath"
 
            foreach ( $Printer in $PrintXML.Printers.SharedPrinter ) {
                New-Object PSObject -Property @{
                    GPOName = $GPODisp
                    PrinterPath = $printer.Properties.Path
                    PrinterAction = $printer.Properties.action.Replace("U","Update").Replace("C","Create").Replace("D","Delete").Replace("R","Replace")
                    PrinterDefault = $printer.Properties.default.Replace("0","False").Replace("1","True")
                    FilterGroup = $printer.Filters.FilterGroup.Name
                    GPOType = "Group Policy Preferences"
                }
            }
        }
        #Get Deployed Printers
        [xml]$xml = Get-GPOReport -Id $GPOID -ReportType xml
        $User = $xml.DocumentElement.User.ExtensionData.extension.printerconnection
        $Computer = $xml.DocumentElement.computer.ExtensionData.extension.printerconnection
 
        foreach ($U in $User){
            if ($U){
 
                New-Object PSObject -Property @{
                    GPOName = $GPODisp
                    PrinterPath = $u.Path
                }
            }
 
        }
 
        foreach ($C in $Computer){
            if ($c){
 
                New-Object PSObject -Property @{
                    GPOName = $GPODisp
                    PrinterPath = $c.Path
                }
            }
 
        }
    }
}

############################################
# Check to see if Labtech is running

function LabTechCheck {

    $LabTechcheck = get-service | where-object {$_.name -match "LTService"}
    if($LabTechcheck.status -match "Running") {
        $section = "
        <tr>
            <td>LabTech Agent Check</td>
            <td class=good>LabTech is running.</td>
            <td class=good>Correct</td>
        </tr>
        "
    } else {
        $section = "
        <tr>
            <td>LabTech Agent Check</td>
            <td class=bad>LabTech is stopped, paused, or does not exist.</td>
            <td class=bad>Start the agent and ensure checkin.</td>
        </tr>
        "
    }

    $section | out-file -filepath $qc_htmlfile -append
}

############################################
# Check to see if the NTP server is pool.ntp.org

function NTPSrvCheck {

    $ntpsrv = ((Get-ItemProperty "hklm:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\").ntpserver).split(",")[0]
    if($ntpsrv -match "pool.ntp.org") {
        $section = "
        <tr>
            <td>NTP Server Check</td>
            <td class=good>NTP server is pool.ntp.org</td>
            <td class=good>Correct</td>
        </tr>
        "
    } else {
        $section = "
        <tr>
            <td>NTP Server Check</td>
            <td class=bad>NTP Server is not valid.</td>
            <td class=bad>Please set the NTP server to pool.ntp.org.</td>
        </tr>
        "
    }

    $section | out-file -filepath $qc_htmlfile -append
}

#############################################
#  Get the status of PSTools

function PSTools {
    $status = Test-Path C:\PSTools
    if ($status -eq $true){
        $section = "
        <tr>
            <td>PS Tools Status Check</td>
            <td class=good>The PS Tools folder is on the C:\ drive!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    } else {
        $section = "
        <tr>
            <td>PS Tools Status Check</td>
            <td class=bad>The PS Tools folder is not present at C:\PSTools!</td>
            <td class=bad>Please install PS Tools!</td>
        </tr>
        "
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

#############################################
#  Get the status of Volume Shadow Copy

function ShadowCopy {
    $status = Get-WmiObject win32_shadowcopy
    if ($status -eq $null){
        $section = "
        <tr>
            <td>Volume Shadow Copy Status Check</td>
            <td class=bad>Volume Shadow Copy is not enabled</td>
            <td class=bad>Please enable Volume Shadow Copy!</td>
        </tr>
        "
    } else {
        $section = "
        <tr>
            <td>Volume Shadow Copy Status Check</td>
            <td class=good>Volume Shadow Copy is enabled!</td>
            <td class=good>It is enabled (schedule cannot be verified)!</td>
        </tr>
        "
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

#############################################
#  Get the status of domain

function OnDomain {
    $status = (Get-WmiObject win32_computersystem).partofdomain
    if ($status -eq $false){
        $section = "
        <tr>
            <td>On Domain Status Check</td>
            <td class=bad>This server is not on a domain</td>
            <td class=bad>If this is not by design, please join the domain!</td>
        </tr>
        "
    } else {
        $section = "
        <tr>
            <td>On Domain Status Check</td>
            <td class=good>This server is on a domain!</td>
            <td class=good>Correct!</td>
        </tr>
        "
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

############################################
#  Check to see if the FSMO roles are installed

Function CheckFSMO {
    
    $roles = (Get-ADDomainController -Server $env:computername).OperationMasterRoles

    if ($roles -eq $null){
        $section = "
        <tr>
            <td>FSMO Status Check</td>
            <td class=bad>FSMO - $role is NOT installed!</td>
            <td class=bad>There are no FSMO roles on this server!</td>
        </tr>
        "
        $section | Out-File -FilePath $qc_htmlfile -append
    } else {
        foreach ($role in $roles){
            $section = "
            <tr>
                <td>FSMO Status Check</td>
                <td class=good>FSMO - $role is installed!</td>
                <td class=good>Correct!</td>
            </tr>
            "
            $section | Out-File -FilePath $qc_htmlfile -append
        }
    }
}

###############################################
#  Checking to see if short file name is configured

Function ShortFileConfig {
    if ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem').NtfsDisable8dot3NameCreation  -eq 1){
    $section = "
        <tr>
            <td>Short File Name Check</td>
            <td class=good>Short File Name is disabled</td>
            <td class=good>Correct</td>
        </tr>
        "
    } 
    else {
    $section = "
        <tr>
            <td>Short File Name Check</td>
            <td class=bad>Short File Name is enabled</td>
            <td class=bad>Please disable it!</td>
        </tr>
        "
    }
    $section | Out-File -FilePath $qc_htmlfile -append
}

############################################
#  Check to see if the mapped drives are installed by GPO

function checkMapDriveGPO {

    <#
    .SYNOPSIS     
               The script finds the GPP Drive Maps in your domain. 
    .NOTES     
               File Name: Get-GPPDriveMaps.ps1     
               Author   : Johan Dahlbom, johan[at]dahlbom.eu     
	       Blog: 365lab.net
               The script are provided “AS IS” with no guarantees, no warranties, and it confer no rights. 
    #>

    #Import the required module GroupPolicy
    try {
        Import-Module GroupPolicy -ErrorAction Stop
    } catch {
        throw "Module GroupPolicy not Installed"
    }
    $GPO = Get-GPO -All
    $present = $null

    foreach ($Policy in $GPO){
 
        $GPOID = $Policy.Id
        $GPODom = $Policy.DomainName
        $GPODisp = $Policy.DisplayName
 
        if (Test-Path "\\$($GPODom)\SYSVOL\$($GPODom)\Policies\{$($GPOID)}\User\Preferences\Drives\Drives.xml"){
            [xml]$DriveXML = Get-Content "\\$($GPODom)\SYSVOL\$($GPODom)\Policies\{$($GPOID)}\User\Preferences\Drives\Drives.xml"
            foreach ( $drivemap in $DriveXML.Drives.Drive ){
                $DriveLetter = $drivemap.Properties.Letter + ":"
                $DrivePath = $drivemap.Properties.Path
                $DriveAction = $drivemap.Properties.action.Replace("U","Update").Replace("C","Create").Replace("D","Delete").Replace("R","Replace")
                $DriveLabel = $drivemap.Properties.label
                $DrivePersistent = $drivemap.Properties.persistent.Replace("0","False").Replace("1","True")
                $DriveFilterGroup = $drivemap.Filters.FilterGroup.Name
                $present = $true
                $section = "
                <tr>
                    <td>GPO Deployed Mapped Drives Check</td>
                    <td class=good>The drive $DrivePath is deployed through Group Policy!</td>
                    <td class=good>Correct!</td>
                </tr>
                "
                $section | Out-File -FilePath $qc_htmlfile -append
            }
        } else {
           
        }
    }
    if ($present -eq $null) {
         $section = "
        <tr>
            <td>GPO Deployed Mapped Drives Check</td>
            <td class=bad>The server is NOT deploying mapped drives via GPO!</td>
            <td class=bad>Please validate!</td>
        </tr>
        "
        $section | Out-File -FilePath $qc_htmlfile -append
    }
}

############################################
#  Check to see if there are any GPO's to deploy printers

function CheckGPOPrinters {
    $printers = Get-GPOPrinters
    if ($printers -eq $null){
        $section = "
        <tr>
            <td>GPO Deployed Printers Check</td>
            <td class=bad>The server is NOT deploying printers via GPO!</td>
            <td class=bad>Please validate!</td>
        </tr>
        "
        $section | Out-File -FilePath $qc_htmlfile -append
    } else {
        foreach ($printer in $printers) {
            $path = $printer.printerpath
            $GPOName = $printer.GPOName
            $section = "
            <tr>
                <td>GPO Deployed Printers Check</td>
                <td class=good>The printer $path is deployed through $GPOName!</td>
                <td class=good>Correct!</td>
            </tr>
            "
            $section | Out-File -FilePath $qc_htmlfile -append
        }
    }
}

############################################
#  Check to see if this server is a global catalog

function CheckGlobalCatalog {
    $gcs = (Get-Adforest).GlobalCatalogs
    $globalcat = $false
    foreach ($gc in $gcs) {
        if ($gc -match $env:computername) {
            $globalcat = $true
        }
    }
    if ($globalcat -eq $true){
        $section = "
        <tr>
            <td>Global Catalog  Check</td>
            <td class=good>The server is a Global Catalog!</td>
            <td class=good>Correct!</td>
        </tr>
        "
        $section | Out-File -FilePath $qc_htmlfile -append
    } else {
        $section = "
        <tr>
            <td>Global Catalog Check</td>
            <td class=bad>The server is NOT Global Catalog!</td>
            <td class=bad>Please make this a Global Catalog!</td>
        </tr>
        "
        $section | Out-File -FilePath $qc_htmlfile -append
    }
}

#############################################
#  Determine if AD DS is setup properly

function DomainController {
    $dc = (Get-ADComputer $env:computername -Properties *).PrimaryGroupID
    if ($dc -eq 516) {
            
        RolesSection

        $section = "
        <tr>
            <td>Domain Controller Check</td>
            <td class=good>The server is a domain controller!</td>
            <td class=good>Correct!</td>
        </tr>
        "
        $section | Out-File -FilePath $qc_htmlfile -append
        # active directory
        EnableFeature AD-Domain-Services 
        EnableFeature RSAT-AD-Tools 
        EnableFeature RSAT-AD-PowerShell
        EnableFeature RSAT-ADDS
        EnableFeature RSAT-AD-AdminCenter
        EnableFeature RSAT-ADDS-Tools
        EnableFeature RSAT-ADLDS
    
        # group policy
        EnableFeature GPMC

        # dns
        EnableFeature DNS 
        EnableFeature RSAT-DNS-Server

        # dhcp
        EnableFeature DHCP

        # file services
        EnableFeature Storage-Services

        #print services
        EnableFeature Print-Services
        EnableFeature RSAT-Print-Services
        EnableFeature Print-Server

        # Check to see if this server is a global catalog
        CheckGlobalCatalog         
        
        # Check to see if any FSMO roles are on this server
        CheckFSMO

        # Check to see if there are any GPO's to deploy printers
        CheckGPOPrinters

        # check to see if mapped drives are deployed by GPO
        checkMapDriveGPO

        # check to see if short file name is configured
        ShortFileConfig
    } else {
        $section = "
        <tr>
            <td>Domain Controller Check</td>
            <td class=bad>The server is NOT domain controller!</td>
            <td class=bad>If this was supposed to be a domain controller then you need to evalutate it!</td>
        </tr>
        "
        $section | Out-File -FilePath $qc_htmlfile -append
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



###########################################################################
# Run all the functions above

Write-Verbose (("Checking Computer Info at ") + (get-date))
ComputerInfo

Write-Verbose (("Checking Operating System Location at ") + (get-date))
OSLocationCheck

Write-Verbose (("Checking Drive Size at ") + (get-date))
DriveSizeCheck

Write-Verbose (("Checking Activation  status status at ") + (get-date))
ActivatedCheck

Write-Verbose (("Checking Device status at ") + (get-date))
DeviceCheck

Write-Verbose (("Checking for Windows Updates at ") + (get-date))
WindowsUpdates

Write-Verbose (("Checking for WMF 5.0 at ") + (get-date))
WMF5Check

Write-Verbose (("Checking Windows Firewall at ") + (get-date))
FirewallCheck

Write-Verbose (("Checking Remote Desktop status at ") + (get-date))
RemoteDesktopConfig

Write-Verbose (("Checking NTP Server status at ") + (get-date))
NTPSrvCheck

Write-Verbose (("Checking Time status at ") + (get-date))
NtpTime

Write-Verbose (("Checking IE Enhanced Security Configuration at ") + (get-date))
DisableIEESC

Write-Verbose (("Checking .Net 3.5 status at ") + (get-date))
EnableFeature NET-Framework-Features

Write-Verbose (("Checking .Net 4.5 status at ") + (get-date))
EnableFeature NET-Framework-45-Features

Write-Verbose (("Checking User Desktop Experience status at ") + (get-date))
EnableFeature Desktop-Experience

Write-Verbose (("Checking Telnet Client status at ") + (get-date))
EnableFeature telnet-client

Write-Verbose (("Checking Windows Search Service status at ") + (get-date))
EnableFeature search-service

Write-Verbose (("Checking Windows Server Migration Tools status at ") + (get-date))
EnableFeature migration

Write-Verbose (("Checking Windows Powershell status at ") + (get-date))
EnableFeature PowershellRoot

Write-Verbose (("Checking Windows Powershell 4.0 status at ") + (get-date))
EnableFeature Powershell

Write-Verbose (("Checking Windows Powershell DSC status at ") + (get-date))
EnableFeature DSC-Service

Write-Verbose (("Checking Windows Powershell ISE status at ") + (get-date))
EnableFeature Powershell-ISE

Write-Verbose (("Checking DHCP status at ") + (get-date))
StaticIP

Write-Verbose (("Checking NIC power status at ") + (get-date))
NicPower

Write-Verbose (("Checking Recieve Side Scaling status at ") + (get-date))
ReceiveSideScaling

Write-Verbose (("Checking VMXNET3 status at ") + (get-date))
VMXNET3

Write-Verbose (("Checking domain status at ") + (get-date))
OnDomain

Write-Verbose (("Checking Labtech's status at ") + (get-date))
LabTechCheck

Write-Verbose (("Checking Webroot at ") + (get-date))
WebrootCheck

Write-Verbose (("Checking Volume Shadow Copy at ") + (get-date))
ShadowCopy

Write-Verbose (("Checking for PS Tools at ") + (get-date))
PSTools

###############################

Write-Verbose (("Adding Application Configuration section at ") + (get-date)) 
ApplicationSection

Write-Verbose (("Checking Applications at ") + (get-date))
AppCheck -AppName 'Putty' -TargetVersion "0.67"
AppCheck -AppName 'VMware vSphere Client' -TargetVersion "6.0.0.5505"

$virtual = (gwmi Win32_ComputerSystem -computer localhost).Manufacturer

if ($virtual -match "vmware") {
} else {
    AppCheck -AppName 'Dell OpenManage Systems Management Software' -TargetVersion "8.1.0"
}

###############################

Write-Verbose (("Adding Roles and Features Section section at ") + (get-date)) 
DomainController

###############################

Write-Verbose (("Showing the output html at ") + (get-date))
Invoke-Item $qc_htmlfile













