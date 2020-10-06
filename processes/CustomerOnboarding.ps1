Start-Transcript -Path "C:\_Installation_Files\builds\WorkstationBuild_Transcript.rtf" -append -NoClobber

###############################################################################################
#  Created by Carlos McCray
#  Last Update 6/17/2016

$VerbosePreference = "Continue"
$machine_name = gc env:computername
$htmlfile = "C:\_Installation_Files\builds\WorkstationBuild_$machine_name.html"
$OperatingSystem = (get-wmiobject win32_operatingsystem).caption
$OSArchitecture = (get-wmiobject win32_operatingsystem).OSArchitecture
$buildxml = 'C:\_Installation_Files\build.xml'

<#
List of available functions

Disable-NicPower
Get-NicPower
Disable-UAC
Get-ExpressServiceCode
Get-Chassis
Get-Firewall
Set-Firewall 
Get-DeviceStatus
Get-UAC
Get-HTTPFile 
Get-OfficeVersion
Get-OfficeKey
Import-WLAN 
Enable-User
New-User 
New-MapDrive
New-LocalUser
New-HTMLOutput 
Remove-Software
Set-HTMLOutput 
Set-Registry 
Set-ClientWSUSSetting 
Set-WindowsUpdates 
Get-WindowsUpdates
Start-WindowsUpdates
Set-Power 
send-email 
Start-SystemRestore 
Remove-WSUS
 
 
#>

###############################################################################################
#   Functions

#########################################
#  Office key

function Get-OfficeKey {
    $computername = gc env:computername

    $product = @()
    $hklm = 2147483650
    $path = "SOFTWARE\Microsoft\Office"

    foreach ($computer in $computerName) {

        $wmi = [WMIClass]"\\$computer\root\default:stdRegProv"

        $subkeys1 = $wmi.EnumKey($hklm,$path)
        foreach ($subkey1 in $subkeys1.snames) {
            $subkeys2 = $wmi.EnumKey($hklm,"$path\$subkey1")
            foreach ($subkey2 in $subkeys2.snames) {
                $subkeys3 = $wmi.EnumKey($hklm,"$path\$subkey1\$subkey2")
                foreach ($subkey3 in $subkeys3.snames) {
                    $subkeys4 = $wmi.EnumValues($hklm,"$path\$subkey1\$subkey2\$subkey3")
                    foreach ($subkey4 in $subkeys4.snames) {
                        if ($subkey4 -eq "digitalproductid") {
                            $temp = "" | select ComputerName,ProductName,ProductKey
                            $temp.ComputerName = $computer
                            $productName = $wmi.GetStringValue($hklm,"$path\$subkey1\$subkey2\$subkey3","productname")
                            $productName = $wmi.GetStringValue($hklm,"$path\$subkey1\$subkey2\$subkey3","ConvertToEdition")
                            $temp.ProductName = $productName.sValue

                            $data = $wmi.GetBinaryValue($hklm,"$path\$subkey1\$subkey2\$subkey3","digitalproductid")
                            $valueData = ($data.uValue)[52..66]

                            # decrypt base24 encoded binary data 
                            $productKey = ""
                            $chars = "BCDFGHJKMPQRTVWXY2346789"
                            for ($i = 24; $i -ge 0; $i--) { 
                                $r = 0 
                                for ($j = 14; $j -ge 0; $j--) { 
                                    $r = ($r * 256) -bxor $valueData[$j] 
                                    $valueData[$j] = [math]::Truncate($r / 24)
                                    $r = $r % 24 
                                } 
                                $productKey = $chars[$r] + $productKey 
                                if (($i % 5) -eq 0 -and $i -ne 0) { 
                                    $productKey = "-" + $productKey 
                                } 
                            } 
                            $temp.ProductKey = $productKey
                            $product += $temp
                        }
                    }
                }
            }
        }
    }
    #output time
    $version = $product[0].ProductName
    $key = $product[0].ProductKey
    return $key
}

#########################################
#  Get Officev Version

function Get-OfficeVersion {
# define Office Version SP
$office10sp1 = "14.0.6029.1000"
$office07sp3 = "12.0.6612.1000"
$office03sp3 = "11.0.8173.0"
  
$office = Get-WmiObject -class Win32_Product | Where-Object {$_.Name -match "Microsoft Office" -and $_.regowner -ne $null}

if ($office.version -match "14.0.6029.1000")
    {
    Write-Verbose "Office year is 2010"
    $year = "2010"
    $name = $office.Name
    }
elseif($office.version -match "12.0.6612.1000")
    {
    Write-Verbose "Office year is 2007"
    $year = "2007"
    $name = $office.Name
    }
elseif($office.version -match "11.0.8173.0")
    {
    Write-Verbose "Office year is 2003"
    $year = "2003"
    $name = $office.Name
    }
    return $year, $name
    
}

#########################################
#  Express Service Code

function Get-ExpressServiceCode {
$manufacturer = (get-wmiobject win32_bios).manufacturer
$Serial = (get-wmiobject win32_bios).serialnumber
if ($manufacturer -match "Dell")
    {
    $Base = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $Length = $Serial.Length
    For ($CurrentChar = $Length; $CurrentChar -ge 0; $CurrentChar--) 
        {
        $Out = $Out + [int64](([Math]::Pow(36, ($CurrentChar - 1)))*($Base.IndexOf($serial[($Length - $CurrentChar)])))
        }
    }
else
    {
    $Out = $false
    }
    return $Out
}

#########################################
#   Get Chassis

Function Get-Chassis {
 Param(
 [string]$computer = "localhost"
 )
 $isLaptop = $false
 if(Get-WmiObject -Class win32_systemenclosure -ComputerName $computer | 
    Where-Object { $_.chassistypes -eq 9 -or $_.chassistypes -eq 10 `
    -or $_.chassistypes -eq 14})
   { $isLaptop = $true }
 if(Get-WmiObject -Class win32_battery -ComputerName $computer) 
   { $isLaptop = $true }
if ($isLaptop)
    {
    $chassis = "Laptop"
    }
else
    {
    $chassis = "Desktop"
    }
    $chassis
}

#########################################

Function Remove-WSUS {

stop-service wuauserv

$WU = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'

$WUremovetings = Get-ItemProperty $wu

remove-ItemProperty -path $wu -name ElevateNonAdmins
remove-ItemProperty -path $wu -name TargetGroup
remove-ItemProperty -path $wu -name TargetGroupEnabled
remove-ItemProperty -path $wu -name WUServer
remove-ItemProperty -path $wu -name WUStatusServer
Set-ItemProperty -path $wu -name AutoInstallMinorUpdates -value '00000000'
Set-ItemProperty -path $wu -name NoAutoRebootWithLoggedOnUsers -value '00000000'
Set-ItemProperty -path $wu -name NoAutoUpdate -value '00000000'
Set-ItemProperty -path $wu -name UseWUServer -value '00000000'

$AU = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'

$AUremovetings = Get-ItemProperty $AU

Set-ItemProperty -path $AU -name NoAutoUpdate -value '00000000'

remove-ItemProperty -path $AU -name AUOptions
remove-ItemProperty -path $AU -name AutoInstallMinorUpdates
remove-ItemProperty -path $AU -name DetectionFrequencyEnabled
remove-ItemProperty -path $AU -name NoAUAsDefaultShutdownOption
remove-ItemProperty -path $AU -name NoAUShutdownOption
remove-ItemProperty -path $AU -name NoAutoRebootWithLoggedOnUsers
remove-ItemProperty -path $AU -name RebootRelaunchTimeoutEnabled
remove-ItemProperty -path $AU -name RebootRelaunchTimeout
remove-ItemProperty -path $AU -name RebootWarningTimeoutEnabled
remove-ItemProperty -path $AU -name RebootWarningTimeout
remove-ItemProperty -path $AU -name RescheduleWaitTimeEnabled
remove-ItemProperty -path $AU -name RescheduleWaitTime
remove-ItemProperty -path $AU -name ScheduledInstallDay
remove-ItemProperty -path $AU -name ScheduledInstallTime
remove-ItemProperty -path $AU -name UseWUServer

Start-Service wuauserv
}

#########################################

function Get-Power {
$VerbosePreference = "Continue"

Write-Verbose "Checking power settings"
#check default power plan
$powerplan=get-wmiobject -namespace "root\cimv2\power" -class Win32_powerplan  
[array]$recommended = $powerplan | Where-Object{$_.isactive -eq $true}


#check power settings
$powersettingindexes=get-wmiobject -namespace "root\cimv2\power" -class Win32_powersettingdataindex|where-object {$_.instanceid.contains($recommended[0].instanceid.split("\")[1])}
    foreach ($powersettingindex in $powersettingindexes)
        {
            $powersettings=get-wmiobject -namespace "root\cimv2\power" -class Win32_powersetting|where-object {$_.instanceid.contains($powersettingindex.instanceid.split("\")[3])}
            foreach ($powersetting in $powersettings)
                {
                $name = $powersetting.ElementName
                $value = $powersettingindex.settingindexvalue   
                $output = @()
                $output += "$name","$value"
                $settings += , $output
                #Write-Verbose "$name is set to $value"
                }
    
        } 


$array = ("Power button action","3"),
("Lid close action","1"), 
("Turn off display after","1800"),
("Turn off hard disk", "0"),
("Hibernate after","0")

$exit = $true
$name = ""
$value = ""
foreach ($item in $array)
    {
    $name = $item[0]
    $value = $item[1]
    $Status = $true
    foreach ($setting in $settings)
        {
        $element = $setting[0]
        $elementvalue = $setting[1]
        if ($element -match $name -and $elementvalue -ne $value)
                {
                $Status = $false
                }
        }
    Write-Verbose "$name is $status"
    if ($status -eq $false)
        {
        $exit = $false
        }
    }
Return $exit
}  

#########################################
#  Device Status

Function Get-DeviceStatus {
    $hw_check = gwmi -class Win32_PnPEntity | Where-Object {$_.status -match "Error"}
    $devicecount = ($hw_check.count)
    if ($devicecount -eq $null){$devicecount = $true}
    if ($devicecount -eq $true)
        {
        $DeviceStatus = $true
        }
    else
        {
        $DeviceStatus = $false
        }
    
    return $DeviceStatus
    }

#########################################
#  UAC Status

Function Get-UAC {
$uac = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$uacquery = Get-ItemProperty -path $uac -name EnableLUA
$uacval = $uacquery.EnableLUA
$uacstatus = ($uacval -eq 1)
return $uacstatus            
}

###########################################
            
function Set-Registry{
<# 
    .SYNOPSIS 
        Set-RemoteRegistry allows user to set any given registry key/value pair. 
 
    .DESCRIPTION 
        Set-RemoteRegistry allows user to change registry on remote computer using remote registry access. 
 
    .PARAMETER  ComputerName 
        Computer name where registry change is desired. If not specified, defaults to computer where script is run. 
 
    .PARAMETER  Hive 
        Registry hive where the desired key exists. If no value is specified, LocalMachine is used as default value. Valid values are: ClassesRoot,CurrentConfig,CurrentUser,DynData,LocalMachine,PerformanceData and Users. 
 
    .PARAMETER  Key 
        Key where item value needs to be created/changed. Specify Key in the following format: System\CurrentControlSet\Services. 
 
    .PARAMETER  Name 
        Name of the item that needs to be created/changed. 
         
    .PARAMETER  Value 
        Value of item that needs to be created/changed. Value must be of correct type (as specified by -Type). 
         
    .PARAMETER  Type 
        Type of item being created/changed. Valid values for type are: String,ExpandString,Binary,DWord,MultiString and QWord. 
         
    .PARAMETER  Force 
        Allows user to bypass confirmation prompts. 
         
    .EXAMPLE 
        PS C:\> .\Set-RemoteRegistry.ps1 -Key SYSTEM\CurrentControlSet\services\AudioSrv\Parameters -Name ServiceDllUnloadOnStop -Value 1 -Type DWord 
 
    .EXAMPLE 
        PS C:\> .\Set-RemoteRegistry.ps1 -ComputerName ServerA -Key SYSTEM\CurrentControlSet\services\AudioSrv\Parameters -Name ServiceDllUnloadOnStop -Value 0 -Type DWord -Force 
 
    .INPUTS 
        System.String 
 
    .OUTPUTS 
        System.String 
 
    .NOTES 
        Created and maintainted by Bhargav Shukla (MSFT). Please report errors through contact form at http://blogs.technet.com/b/bshukla/contact.aspx. Do not remove original author credits or reference. 
 
    .LINK 
        http://blogs.technet.com/bshukla 
#> 
    [CmdletBinding(SupportsShouldProcess=$true)] 
    param 
    ( 
        [Parameter(Position=0, Mandatory=$false)] 
        [System.String] 
        $ComputerName = $Env:COMPUTERNAME, 
        
        [Parameter(Position=1, Mandatory=$false)] 
        [ValidateSet("ClassesRoot","CurrentConfig","CurrentUser","DynData","LocalMachine","PerformanceData","Users")] 
        [System.String] 
        $Hive = "LocalMachine", 
        
        [Parameter(Position=2, Mandatory=$true, HelpMessage="Enter Registry key in format System\CurrentControlSet\Services")] 
        [ValidateNotNullOrEmpty()] 
        [System.String] 
        $Key, 
        
        [Parameter(Position=3, Mandatory=$true)] 
        [ValidateNotNullOrEmpty()] 
        [System.String] 
        $Name, 
        
        [Parameter(Position=4, Mandatory=$true)] 
        [ValidateNotNullOrEmpty()] 
        [System.String] 
        $Value,         
        
        [Parameter(Position=5, Mandatory=$true)] 
        [ValidateSet("String","ExpandString","Binary","DWord","MultiString","QWord")] 
        [System.String] 
        $Type, 
        
        [Parameter(Position=6, Mandatory=$false)] 
        [Switch] 
        $Force 
    ) 
     
    If ($pscmdlet.ShouldProcess($ComputerName, "Open registry $Hive")) { 
        #Open remote registry 
        try { 
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Hive, $ComputerName) 
        }catch { 
            Write-Error "The computer $ComputerName is inaccessible. Please check computer name. Please ensure remote registry service is running and you have administrative access to $ComputerName." 
            Return 
        } 
    } 
 
    If ($pscmdlet.ShouldProcess($ComputerName, "Check existense of $Key")) { 
        #Open the targeted remote registry key/subkey as read/write 
        $regKey = $reg.OpenSubKey($Key,$true) 
         
        #Since trying to open a regkey doesn't error for non-existent key, let's sanity check 
        #Create subkey if parent exists. If not, exit. 
        If ($regkey -eq $null) {     
            Write-Warning "Specified key $Key does not exist in $Hive." 
            $Key -match ".*\x5C" | Out-Null 
            $parentKey = $matches[0] 
            $Key -match ".*\x5C(\w*\z)" | Out-Null 
            $childKey = $matches[1] 
 
            try { 
                $regtemp = $reg.OpenSubKey($parentKey,$true) 
            } catch { 
                Write-Error "$parentKey doesn't exist in $Hive or you don't have access to it. Exiting." 
                Return 
            } 
            If ($regtemp -ne $null) { 
                Write-Output "$parentKey exists. Creating $childKey in $parentKey." 
                try { 
                    $regtemp.CreateSubKey($childKey) | Out-Null 
                } catch { 
                    Write-Error "Could not create $childKey in $parentKey. You  may not have permission. Exiting." 
                    Return 
                } 
 
                $regKey = $reg.OpenSubKey($Key,$true) 
            }else{ 
                Write-Error "$parentKey doesn't exist. Exiting." 
                Return 
            } 
        } 
     
            #Cleanup temp operations 
            try { 
                $regtemp.close() 
                Remove-Variable $regtemp,$parentKey,$childKey 
            }catch{ 
                #Nothing to do here. Just suppressing the error if $regtemp was null 
            } 
    } 
     
    #If we got this far, we have the key, create or update values 
    If ($Force) { 
        If ($pscmdlet.ShouldProcess($ComputerName, "Create or change $Name's value to $Value in $Key. Since -Force is in use, no confirmation needed from user")) { 
            $regKey.Setvalue("$Name", "$Value", "$Type") 
        } 
    }else{ 
        If ($pscmdlet.ShouldProcess($ComputerName, "Create or change $Name's value to $Value in $Key. No -Force specified, user will be asked for confirmation")) { 
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","" 
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","" 
            $choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes,$no) 
            $caption = "Warning!" 
            $message = "Value of $Name will be set to $Value. Current value `(If any`) will be replaced. Do you want to proceed?" 
            Switch ($result = $Host.UI.PromptForChoice($caption,$message,$choices,0)) 
            { 
                1 
                    { 
                        Return 
                    } 
                0 
                    { 
                        $regKey.Setvalue("$Name", "$Value", "$Type") 
                    } 
            } 
        } 
    } 
     
    #Cleanup all variables 
    try{ 
        $regKey.close() 
        Remove-Variable $ComputerName,$Hive,$Key,$Name,$Value,$Force,$reg,$regKey,$yes,$no,$caption,$message,$result 
    }catch { 
        #Nothing to do here. Just suppressing the error if any variable is null 
    }
}
    
########################################

Function Get-HTTPFile ($url,$file,$username,$password){
$webclient = New-Object System.Net.WebClient
$webclient.Credentials = New-Object System.Net.NetworkCredential($username,$password) 
$webclient.DownloadFile($url,$file)
}

################################################################

function send-email { 
[CmdletBinding()]

            <#
            This function allows you to email a file

            There are 3 parameters that are all mandatory

            --From -- This is the email that you want to send from

            --To -- This is the email you want to send too

            --File -- This is the file you would like to send

            Example:
            send-email -from "support@ribbit.net" -to "test@ribbit.net" -file "c:\file.txt"

            #>
        param (

        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $From,
        
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $To,
                
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $File

        )

BEGIN {}
PROCESS {
        $mailmessage = New-Object system.net.mail.mailmessage
        $mailmessage.from = ($from)
        $mailmessage.To.add($to)
        $mailmessage.Subject = $emailsubject
        $mailmessage.Body = $emailbody

        $EmailSubject = "$file" 
        $emailbody = ""

        $SMTPServer = ""
        $SMTPAuthUsername = ""
        $SMTPAuthPassword = ""

        $emailattachment = $file 

        $attachment = New-Object System.Net.Mail.Attachment($emailattachment, 'text/plain')
            $mailmessage.Attachments.Add($attachment)


        #$mailmessage.IsBodyHTML = $true
        $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 25) 
        $SMTPClient.Credentials = New-Object System.Net.NetworkCredential("$SMTPAuthUsername", "$SMTPAuthPassword")
        $SMTPClient.Send($mailmessage)
        }
END {}
} 

###############################################

function New-User { 
<#
Function to create new users

Parameters....
Users - names that you would like to create
Membership - list groups that you would like to add each user to
Domain - IP address of domain controller
$credential - supplied by a $credential = Get-Credential that you should
    use before running the function


Example - 
$credential = Get-Credential

$users = "Joe" , "John" , "Rantor"
$membership = 'CN=Backup Operators,CN=Builtin,DC=BR,DC=local','CN=TelnetClients,CN=Builtin,DC=BR,DC=local'


foreach($user in $users)
    {
    New-User -user $user -membership $membership -domain "192.168.40.102" -credential $credential
    }
#>
[CmdletBinding()]
        param (

        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string[]]$users,
        
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string[]]$membership,

        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $domain,
                    
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $credential
        )

BEGIN {                    
}
PROCESS {
        $Verbosepreference = "Continue"
        Write-Verbose "Adding Quest Snap-In"
        Add-PSSnapin Quest.ActiveRoles.ADManagement
                    
        Write-Verbose "Connecting to Domain"
        Connect-QADService -service $domain -Credential $credential

        foreach ($user in $users)
            {
            Write-Verbose "Make new user"
            New-QADUser -Name $user -ParentContainer "CN=Users,DC=BR,DC=LOCAL" -SamAccountName $user `
                    -DisplayName $user -Description $user -FirstName $user -LastName $user
            Enable-QADUser -Identity $user
            $membership | 
                    ForEach-Object {get-qadgroup $_ | 
                        Add-qADGroupMember -confirm:$false -member $user}
            }
        }
END {}
}

#########################################################################

function Remove-Software { 
[CmdletBinding()]

<#
This function allows you to uninstall software that is listed in WMI.  
    To find if it is listed run this command...
    get-wmiobject win32_product | where {$_.name -match "Reader"}

There are 2 parameters that are all mandatory

--application -- This is the name of the application as it exist in WMI

--command -- this is the uninstall command to uninstall the software

Example:
foreach($item in $apps)
    {
    Remove-Software -application $item[0] -command $item[1]
    }
#>
param   (
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string[]]$application,
                
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $command
        )

BEGIN {}
PROCESS {
        $app = get-wmiobject win32_product | where {$_.name -match "$application"}
        $appid = $app.IdentifyingNumber
        
        if (test-path 'c:\program files (x86)')  {
            $appreg = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
                      Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "$application"}
        }
        else{
            $appreg = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                      Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "$application"}
        }
                            
        if($app)
            {
            $uninstallcommand = $command.Replace("{}","$appid")
            Write-Verbose "$application is installed"
            Invoke-Expression $uninstallcommand     
            if($check = get-wmiobject win32_product | where {$_.name -match "$application"})
                {
                Write-Verbose "$application did not uninstall and is still installed"
                }
            else
                {
                Write-Verbose "$application has been uninstalled properly"
                }
            }
        elseif($appreg)
            {
            Write-Verbose "$application is installed"
            Invoke-Expression $command
            if (test-path 'c:\program files (x86)')  {
                $appreg2 = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
                          Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "$application"}
            }
            else{
                $appreg2 = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                          Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "$application"}
            }
            if($appreg2)
                {
                Write-Verbose "$application did not uninstall properly"
                }
            else
                {
                Write-Verbose "$application has been uninstalled"
                }
            }
        }             
END {}
}

##########################################################################
            
function New-MapDrive { 
[CmdletBinding()]
        param (

        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string[]]$driveletter,
        
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string[]]$share,
        
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $username,
        
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $password
        
        )

BEGIN {}
PROCESS {
        <#
        This function allows you to map a network drive

        There are 4 parameters that are all mandatory

        --driveletter -- Utilize this parameter for the drive letter.  You need the colon in the string.

        --share -- Put in the full path the share

        --username --Put in the full username with the domain\username format.

        --password --Put in the password

        Example:
        New-MapDrive -driveletter "X:" -share "\\192.168.40.103\Utility" -username "br\tech" -password "Lfs123!"

        #>
        #Map drives to Utility Shares
        $network = new-object -com WScript.Network

        #Mapping network drives       
        Write-Verbose "Mapping $driveletter drive to $share"
        $network.MapNetworkDrive($driveletter, $share, "true",$username,$password)
        }
END {}
}

#########################################################################

Function Set-ClientWSUSSetting {
    <#  
    .SYNOPSIS  
        Sets the wsus client settings on a local or remove system.

    .DESCRIPTION
        Sets the wsus client settings on a local or remove system.
         
    .PARAMETER Computername
        Name of computer to connect to. Can be a collection of computers.

    .PARAMETER UpdateServer
        URL of the WSUS server. Must use Https:// or Http://

    .PARAMETER TargetGroup
        Name of the Target Group to which the computer belongs on the WSUS server.
    
    .PARAMETER DisableTargetGroup
        Disables the use of setting a Target Group
    
    .PARAMETER Options
        Configure the Automatic Update client options. 
        Accepted Values are: "Notify","DownloadOnly","DownloadAndInstall","AllowUserConfig"

    .PARAMETER DetectionFrequency
        Specifed time (in hours) for detection from client to server.
        Accepted range is: 1-22
    
    .PARAMETER DisableDetectionFrequency
        Disables the detection frequency on the client.
    
    .PARAMETER RebootLaunchTimeout
        Set the timeout (in minutes) for scheduled restart.
        Accepted range is: 1-1440
    
    .PARAMETER DisableRebootLaunchTimeout              
        Disables the reboot launch timeout.
    
    .PARAMETER RebootWarningTimeout
        Set the restart warning countdown (in minutes)
        Accepted range is: 1-30
     
    .PARAMETER DisableRebootWarningTimeout
        Disables the reboot warning timeout  
        
    .PARAMETER RescheduleWaitTime
        Time (in minutes) that Automatic Updates should wait at startup before applying updates from a missed scheduled installation time.
      
    .PARAMETER DisableRescheduleWaitTime
        Disables the RescheduleWaitTime   
    
    .PARAMETER ScheduleInstallDay                  
        Specified Day of the week to perform automatic installation. Only valid when Options is set to "DownloadAndInstall"
        Accepted values are: "Everyday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"
    
    .PARAMETER ElevateNonAdmins
        Allow non-administrators to approve or disapprove updates
        Accepted values are: "Enable","Disable"
    
    .PARAMETER AllowAutomaticUpdates
        Enables or disables Automatic Updates
        Accepted values are: "Enable","Disable"
    
    .PARAMETER UseWSUSServer
        Enables or disables use of a Windows Update Server
        Accepted values are: "Enable","Disable"
    
    .PARAMETER AutoInstallMinorUpdates
        Enables or disables silent installation of minor updates.
        Accepted values are: "Enable","Disable"
    
    .PARAMETER AutoRebootWithLoggedOnUsers
        Enables or disables automatic reboots after patching completed whether users or logged into the machine or not.
        Accepted values are: "Enable","Disable"

    .NOTES  
        Name: Set-WSUSClient
        Author: Boe Prox
        https://learn-powershell.net
        DateCreated: 02DEC2011 
        
        To do: Add -PassThru support
               
    .LINK  
        http://technet.microsoft.com/en-us/library/cc708449(WS.10).aspx
        
    .EXAMPLE
    Set-ClientWSUSSetting -UpdateServer "http://testwsus.com" -UseWSUSServer Enable -AllowAutomaticUpdates Enable -DetectionFrequency 4 -Options DownloadOnly

    Description
    -----------
    Configures the local computer to enable automatic updates and use testwsus.com as the update server. Also sets the update detection
    frequency to occur every 4 hours and only downloads the updates. 
    
    .EXAMPLE
    Set-ClientWSUSSetting -UpdateServer "http://testwsus.com" -UseWSUSServer Enable -AllowAutomaticUpdates Enable -DetectionFrequency 4 -Options DownloadAndInstall -RebootWarningTimeout 15 
    -ScheduledInstallDay Monday -ScheduledInstallTime 20
    
    Description
    -----------
    Configures the local computer to enable automatic updates and use testwsus.com as the update server. Also sets the update detection
    frequency to occur every 4 hours and performs the installation automatically every Monday at 8pm and configured to reboot 15 minutes (with a timer for logged on users) after updates
    have been installed.

    #>
    [cmdletbinding(
        SupportsShouldProcess = $True
    )]
    Param (
        [parameter(Position=0,ValueFromPipeLine = $True)]
        [string[]]$Computername = $Env:Computername,
        [parameter(Position=1)]
        [string]$UpdateServer,
        [parameter(Position=2)]
        [string]$TargetGroup,
        [parameter(Position=3)]
        [switch]$DisableTargetGroup,         
        [parameter(Position=4)]
        [ValidateSet('Notify','DownloadOnly','DownloadAndInstall','AllowUserConfig')]
        [string]$Options,
        [parameter(Position=5)]
        [ValidateRange(1,22)]
        [Int32]$DetectionFrequency,
        [parameter(Position=6)]
        [switch]$DisableDetectionFrequency,        
        [parameter(Position=7)]
        [ValidateRange(1,1440)]
        [Int32]$RebootLaunchTimeout,
        [parameter(Position=8)]
        [switch]$DisableRebootLaunchTimeout,        
        [parameter(Position=9)]
        [ValidateRange(1,30)]  
        [Int32]$RebootWarningTimeout,
        [parameter(Position=10)]
        [switch]$DisableRebootWarningTimeout,        
        [parameter(Position=11)]
        [ValidateRange(1,60)]
        [Int32]$RescheduleWaitTime,
        [parameter(Position=12)]
        [switch]$DisableRescheduleWaitTime,        
        [parameter(Position=13)]
        [ValidateSet('EveryDay','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')]
        [ValidateCount(1,1)]
        [string]$ScheduleInstallDay,
        [parameter(Position=14)]
        [ValidateRange(0,23)]
        [Int32]$ScheduleInstallTime,
        [parameter(Position=15)]
        [ValidateSet('Enable','Disable')]
        [string]$ElevateNonAdmins,    
        [parameter(Position=16)]
        [ValidateSet('Enable','Disable')]
        [string]$AllowAutomaticUpdates,  
        [parameter(Position=17)]
        [ValidateSet('Enable','Disable')]
        [string]$UseWSUSServer,
        [parameter(Position=18)]
        [ValidateSet('Enable','Disable')]
        [string]$AutoInstallMinorUpdates,
        [parameter(Position=19)]
        [ValidateSet('Enable','Disable')]
        [string]$AutoRebootWithLoggedOnUsers                                              
    )
    Begin {
    }
    Process {
        $PSBoundParameters.GetEnumerator() | ForEach {
            Write-Verbose ("{0}" -f $_)
        }
        ForEach ($Computer in $Computername) {
            If (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
                $WSUSEnvhash = @{}
                $WSUSConfigHash = @{}
                $ServerReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$Computer) 
                #Check to see if WSUS registry keys exist
                $temp = $ServerReg.OpenSubKey('Software\Policies\Microsoft\Windows',$True)
                If (-NOT ($temp.GetSubKeyNames() -contains 'WindowsUpdate')) {
                    #Build the required registry keys
                    $temp.CreateSubKey('WindowsUpdate\AU') | Out-Null
                }
                #Set WSUS Client Environment Options
                $WSUSEnv = $ServerReg.OpenSubKey('Software\Policies\Microsoft\Windows\WindowsUpdate',$True)
                If ($PSBoundParameters['ElevateNonAdmins']) {
                    If ($ElevateNonAdmins -eq 'Enable') {
                        If ($pscmdlet.ShouldProcess("Elevate Non-Admins","Enable")) {
                            $WsusEnv.SetValue('ElevateNonAdmins',1,[Microsoft.Win32.RegistryValueKind]::DWord)
                        }
                    } ElseIf ($ElevateNonAdmins -eq 'Disable') {
                        If ($pscmdlet.ShouldProcess("Elevate Non-Admins","Disable")) {
                            $WsusEnv.SetValue('ElevateNonAdmins',0,[Microsoft.Win32.RegistryValueKind]::DWord)
                        }
                    }
                }
                If ($PSBoundParameters['UpdateServer']) {
                    If ($pscmdlet.ShouldProcess("WUServer","Set Value")) {
                        $WsusEnv.SetValue('WUServer',$UpdateServer,[Microsoft.Win32.RegistryValueKind]::String)
                    }
                    If ($pscmdlet.ShouldProcess("WUStatusServer","Set Value")) {
                        $WsusEnv.SetValue('WUStatusServer',$UpdateServer,[Microsoft.Win32.RegistryValueKind]::String)
                    }
                }
                If ($PSBoundParameters['TargetGroup']) {
                    If ($pscmdlet.ShouldProcess("TargetGroup","Enable")) {
                        $WsusEnv.SetValue('TargetGroupEnabled',1,[Microsoft.Win32.RegistryValueKind]::Dword)
                    }
                    If ($pscmdlet.ShouldProcess("TargetGroup","Set Value")) {
                        $WsusEnv.SetValue('TargetGroup',$TargetGroup,[Microsoft.Win32.RegistryValueKind]::String)
                    }
                }    
                If ($PSBoundParameters['DisableTargetGroup']) {
                    If ($pscmdlet.ShouldProcess("TargetGroup","Disable")) {
                        $WsusEnv.SetValue('TargetGroupEnabled',0,[Microsoft.Win32.RegistryValueKind]::Dword)
                    }
                }      
                                       
                #Set WSUS Client Configuration Options
                $WSUSConfig = $ServerReg.OpenSubKey('Software\Policies\Microsoft\Windows\WindowsUpdate\AU',$True)
                If ($PSBoundParameters['Options']) {
                    If ($pscmdlet.ShouldProcess("Options","Set Value")) {
                        If ($Options = 'Notify') {
                            $WsusConfig.SetValue('AUOptions',2,[Microsoft.Win32.RegistryValueKind]::DWord)
                        } ElseIf ($Options = 'DownloadOnly') {
                            $WsusConfig.SetValue('AUOptions',3,[Microsoft.Win32.RegistryValueKind]::DWord)
                        } ElseIf ($Options = 'DownloadAndInstall') {
                            $WsusConfig.SetValue('AUOptions',4,[Microsoft.Win32.RegistryValueKind]::DWord)
                        } ElseIf ($Options = 'AllowUserConfig') {
                            $WsusConfig.SetValue('AUOptions',5,[Microsoft.Win32.RegistryValueKind]::DWord)
                        }
                    }
                } 
                If ($PSBoundParameters['DetectionFrequency']) {
                    If ($pscmdlet.ShouldProcess("DetectionFrequency","Enable")) {
                        $WsusConfig.SetValue('DetectionFrequencyEnabled',1,[Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                    If ($pscmdlet.ShouldProcess("DetectionFrequency","Set Value")) {
                        $WsusConfig.SetValue('DetectionFrequency',$DetectionFrequency,[Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                }
                If ($PSBoundParameters['DisableDetectionFrequency']) {
                    If ($pscmdlet.ShouldProcess("DetectionFrequency","Disable")) {
                        $WsusConfig.SetValue('DetectionFrequencyEnabled',0,[Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                } 
                If ($PSBoundParameters['RebootWarningTimeout']) {
                    If ($pscmdlet.ShouldProcess("RebootWarningTimeout","Enable")) {
                        $WsusConfig.SetValue('RebootWarningTimeoutEnabled',1,[Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                    If ($pscmdlet.ShouldProcess("RebootWarningTimeout","Set Value")) {
                        $WsusConfig.SetValue('RebootWarningTimeout',$RebootWarningTimeout,[Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                }
                If ($PSBoundParameters['DisableRebootWarningTimeout']) {
                    If ($pscmdlet.ShouldProcess("RebootWarningTimeout","Disable")) {
                        $WsusConfig.SetValue('RebootWarningTimeoutEnabled',0,[Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                }   
                If ($PSBoundParameters['RebootLaunchTimeout']) {
                    If ($pscmdlet.ShouldProcess("RebootLaunchTimeout","Enable")) {
                        $WsusConfig.SetValue('RebootLaunchTimeoutEnabled',1,[Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                    If ($pscmdlet.ShouldProcess("RebootLaunchTimeout","Set Value")) {
                        $WsusConfig.SetValue('RebootLaunchTimeout',$RebootLaunchTimeout,[Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                }
                If ($PSBoundParameters['DisableRebootLaunchTimeout']) {
                    If ($pscmdlet.ShouldProcess("RebootWarningTimeout","Disable")) {
                        $WsusConfig.SetValue('RebootLaunchTimeoutEnabled',0,[Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                } 
                If ($PSBoundParameters['ScheduleInstallDay']) {
                    If ($pscmdlet.ShouldProcess("ScheduledInstallDay","Set Value")) {
                        If ($ScheduleInstallDay = 'EveryDay') {
                            $WsusConfig.SetValue('ScheduledInstallDay',0,[Microsoft.Win32.RegistryValueKind]::DWord)
                        } ElseIf ($ScheduleInstallDay = 'Monday') {
                            $WsusConfig.SetValue('ScheduledInstallDay',1,[Microsoft.Win32.RegistryValueKind]::DWord)
                        } ElseIf ($ScheduleInstallDay = 'Tuesday') {
                            $WsusConfig.SetValue('ScheduledInstallDay',2,[Microsoft.Win32.RegistryValueKind]::DWord)
                        } ElseIf ($ScheduleInstallDay = 'Wednesday') {
                            $WsusConfig.SetValue('ScheduledInstallDay',3,[Microsoft.Win32.RegistryValueKind]::DWord)
                        } ElseIf ($ScheduleInstallDay = 'Thursday') {
                            $WsusConfig.SetValue('ScheduledInstallDay',4,[Microsoft.Win32.RegistryValueKind]::DWord)
                        } ElseIf ($ScheduleInstallDay = 'Friday') {
                            $WsusConfig.SetValue('ScheduledInstallDay',5,[Microsoft.Win32.RegistryValueKind]::DWord)
                        } ElseIf ($ScheduleInstallDay = 'Saturday') {
                            $WsusConfig.SetValue('ScheduledInstallDay',6,[Microsoft.Win32.RegistryValueKind]::DWord)
                        } ElseIf ($ScheduleInstallDay = 'Sunday') {
                            $WsusConfig.SetValue('ScheduledInstallDay',7,[Microsoft.Win32.RegistryValueKind]::DWord)
                        }
                    }
                }   
                If ($PSBoundParameters['RescheduleWaitTime']) {
                    If ($pscmdlet.ShouldProcess("RescheduleWaitTime","Enable")) {
                        $WsusConfig.SetValue('RescheduleWaitTimeEnabled',1,[Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                    If ($pscmdlet.ShouldProcess("RescheduleWaitTime","Set Value")) {
                        $WsusConfig.SetValue('RescheduleWaitTime',$RescheduleWaitTime,[Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                }
                If ($PSBoundParameters['DisableRescheduleWaitTime']) {
                    If ($pscmdlet.ShouldProcess("RescheduleWaitTime","Disable")) {
                        $WsusConfig.SetValue('RescheduleWaitTimeEnabled',0,[Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                    } 
                If ($PSBoundParameters['ScheduleInstallTime']) {
                    If ($pscmdlet.ShouldProcess("ScheduleInstallTime","Set Value")) {
                        $WsusConfig.SetValue('ScheduleInstallTime',$ScheduleInstallTime,[Microsoft.Win32.RegistryValueKind]::DWord)
                    }
                }   
                If ($PSBoundParameters['AllowAutomaticUpdates']) {
                    If ($AllowAutomaticUpdates -eq 'Enable') {
                        If ($pscmdlet.ShouldProcess("AllowAutomaticUpdates","Enable")) {
                            $WsusEnv.SetValue('NoAutoUpdate',1,[Microsoft.Win32.RegistryValueKind]::DWord)
                        }
                    } ElseIf ($AllowAutomaticUpdates -eq 'Disable') {
                        If ($pscmdlet.ShouldProcess("AllowAutomaticUpdates","Disable")) {
                            $WsusEnv.SetValue('NoAutoUpdate',0,[Microsoft.Win32.RegistryValueKind]::DWord)
                        }
                    }
                } 
                If ($PSBoundParameters['UseWSUSServer']) {
                    If ($UseWSUSServer -eq 'Enable') {
                        If ($pscmdlet.ShouldProcess("UseWSUSServer","Enable")) {
                            $WsusEnv.SetValue('UseWUServer',1,[Microsoft.Win32.RegistryValueKind]::DWord)
                        }
                    } ElseIf ($UseWSUSServer -eq 'Disable') {
                        If ($pscmdlet.ShouldProcess("UseWSUSServer","Disable")) {
                            $WsusEnv.SetValue('UseWUServer',0,[Microsoft.Win32.RegistryValueKind]::DWord)
                        }
                    }
                }
                If ($PSBoundParameters['AutoInstallMinorUpdates']) {
                    If ($AutoInstallMinorUpdates -eq 'Enable') {
                        If ($pscmdlet.ShouldProcess("AutoInstallMinorUpdates","Enable")) {
                            $WsusEnv.SetValue('AutoInstallMinorUpdates',1,[Microsoft.Win32.RegistryValueKind]::DWord)
                        }
                    } ElseIf ($AutoInstallMinorUpdates -eq 'Disable') {
                        If ($pscmdlet.ShouldProcess("AutoInstallMinorUpdates","Disable")) {
                            $WsusEnv.SetValue('AutoInstallMinorUpdates',0,[Microsoft.Win32.RegistryValueKind]::DWord)
                        }
                    }
                }  
                If ($PSBoundParameters['AutoRebootWithLoggedOnUsers']) {
                    If ($AutoRebootWithLoggedOnUsers -eq 'Enable') {
                        If ($pscmdlet.ShouldProcess("AutoRebootWithLoggedOnUsers","Enable")) {
                            $WsusEnv.SetValue('NoAutoRebootWithLoggedOnUsers',1,[Microsoft.Win32.RegistryValueKind]::DWord)
                        }
                    } ElseIf ($AutoRebootWithLoggedOnUsers -eq 'Disable') {
                        If ($pscmdlet.ShouldProcess("AutoRebootWithLoggedOnUsers","Disable")) {
                            $WsusEnv.SetValue('NoAutoRebootWithLoggedOnUsers',0,[Microsoft.Win32.RegistryValueKind]::DWord)
                        }
                    }
                }                                                                                                                                          
            } Else {
                Write-Warning ("{0}: Unable to connect!" -f $Computer)
            }
        }
    }
}

##############################################################################

function Set-WindowsUpdates { 
[CmdletBinding()]
        param ()
BEGIN {}
PROCESS {
        $ServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
        $ServiceManager.ClientApplicationID = “My App”
        #add the Microsoft Update Service GUID
        $NewUpdateService = $ServiceManager.AddService2(“7971f918-a847-4430-9279-4a52d1efe18d”,7,”")
        }
END {}
}

##############################################################################

function Disable-UAC { 
[CmdletBinding()]
        param ()
BEGIN {}
PROCESS {
        if($operatingSystem -ne "Microsoft Windows XP Professional")
            {
            Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -Value 0
            }
        }
END {}
}

##############################################################################
      
function Disable-NicPower { 
[CmdletBinding()]
        param ()
BEGIN {}
PROCESS {
        Write-Verbose "Disabling NIC Power"  
        $namespace = "root\WMI"
        $computer = "localhost"
            Get-WmiObject Win32_NetworkAdapter -filter "AdapterTypeId=0" | 
            Foreach-Object {
                $strNetworkAdapterID=$_.PNPDeviceID.ToUpper()
                Get-WmiObject -class MSPower_DeviceEnable -computername $computer -Namespace $namespace | 
                    Foreach-Object {
                    if($_.InstanceName.ToUpper().startsWith($strNetworkAdapterID))
                        {
                        if($_.Enable = $true)
                            {
                            $_.Enable = $false
                            $_.Put() | Out-Null
                            }
                            else
                            {
                            }
                        
                        }
                    }
            }
        }
END {}
}

##############################################################################
      
function Get-NicPower { 
[CmdletBinding()]
        param ()
BEGIN {}
PROCESS {
        $namespace = "root\WMI"
        $status = ''
        Get-WmiObject Win32_NetworkAdapter -filter "AdapterTypeId=0" | where {$_.PhysicalAdapter -eq $true} |
             Foreach-Object {
                $strNetworkAdapterID=$_.PNPDeviceID.ToUpper()
                Get-WmiObject -class MSPower_DeviceEnable -Namespace $namespace |
                     Foreach-Object {
                        if($_.InstanceName.ToUpper().startsWith($strNetworkAdapterID))
                                {
                                if ($_.Enable)
                                    {
                                    $status = $true
                                    }
                                }
                    }
            }

        if ($status)
            {
            return $true
            }
        else
            {
            return $false
            }
        }
END {}
}

##############################################################################

function Set-Firewall { 
[CmdletBinding()]
<#
        
#>
        param (
                        
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [String[]]$RuleGroup
        
        )
BEGIN {}
PROCESS {
    If ($operatingsystem -match "XP")
        {
        Write-Verbose "Disabling Firewall"
        }
    else
        {
        Write-Verbose "Enabling Firewall settings"
        }
        
    $fw = New-Object -ComObject hnetcfg.fwpolicy2 
    $OperatingSystem = (get-wmiobject win32_operatingsystem).caption
    $domain = "1"
    $private = "2"
    $public = "4"
    $all = "2147483647"
    $profiles = $domain,$private,$public,$all

    if($operatingSystem -ne "Microsoft Windows XP Professional")
        {
        foreach($profile in $profiles)
            {
            if($fw.IsRuleGroupEnabled($profile,$RuleGroup))
                {
                Write-Verbose "$RuleGroup is enabled on profile $profile"
                }
            else
                {
                Write-Verbose "Enabling $RuleGroup on profile $profile"
                $fw.EnableRuleGroup($profile,$RuleGroup,$True)
                }
            }
        }
    }
    END {}
}

##############################################################################

function Enable-User { 
[CmdletBinding()]
<#
This function will enable a local user

There are 1 parameters that are all mandatory

--username -- This is the name of the application as it exist in WMI

Example:
Enable-User -username administrator
#>
        param (
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [String[]]$username
        )
BEGIN {}
PROCESS {
        $cn = $env:computername
        $LocalAdministrator = Get-WmiObject win32_useraccount -computername $cn -filter "LocalAccount=True" | where {($_.name -match $username)}
        $LocalAdministrator.Disabled = $false
        $LocalAdministrator.Put()
    
        }
END {}
}

##############################################################################
        
function Set-Power { 
[CmdletBinding()]
        param ()
BEGIN {}
PROCESS {
        Write-Verbose "Set Power Settings"
        if($operatingSystem -ne "Microsoft Windows XP Professional")
            {
            #Get the Active Plan GUID into a variable
            $ActivePlan = Get-WmiObject -Class win32_powerplan -Namespace root\cimv2\power -Filter "isActive='true'"
            $ActivePlanGUID = $ActivePlan.InstanceID.Split("{,}")[1]

            #Place output of power
            $powercfg = powercfg.exe -q

            #Get the Power Buttons and Lids GUID into a varible
            Foreach($item in $powercfg)
                {
                if($item -match "Power buttons and lid")
                    {
                    $SubGroupGUID = $item.Split(" ")[4]
                    }
                }

            #Get the PowerButtonAction GUID into a variable
            Foreach($item in $powercfg)
                {
                if($item -match "Power button act")
                    {
                    $PowerButtonActionGUID = $item.Split(" ")[7]
                    }
                }

            #Set it to Shutdown on the Active Power Plan when you press the power button
            powercfg.exe -setacvalueindex $ActivePlanGUID $SubGroupGUID $PowerButtonActionGUID 003
            powercfg.exe -setdcvalueindex $ActivePlanGUID $SubGroupGUID $PowerButtonActionGUID 003
                
            #other power settings
            powercfg.exe -change -monitor-timeout-ac 30
            powercfg.exe -change -monitor-timeout-dc 30
            powercfg.exe -change -standby-timeout-ac 0
            powercfg.exe -change -standby-timeout-dc 0
            powercfg.exe -change -disk-timeout-ac 0 
            powercfg.exe -change -disk-timeout-dc 0 
            powercfg.exe -change -hibernate-timeout-ac 0
            powercfg.exe -change -hibernate-timeout-dc 0
            powercfg.exe -h off
            }
        else
            {
            powercfg.exe /create custom1
            powercfg.exe /change custom1 /monitor-timeout-ac 30
            powercfg.exe /change custom1 /monitor-timeout-dc 30
            powercfg.exe /change custom1 /standby-timeout-ac 0
            powercfg.exe /change custom1 /standby-timeout-dc 0
            powercfg.exe /change custom1 /disk-timeout-ac 0 
            powercfg.exe /change custom1 /disk-timeout-dc 0 
            powercfg.exe /change custom1 /hibernate-timeout-ac 0 
            powercfg.exe /change custom1 /hibernate-timeout-dc 0 
            powercfg.exe /setactive custom1
            powercfg.exe /hibernate off
            }
        }
END {}
}

##############################################################################

function Start-SystemRestore { 
[CmdletBinding()]
        param ()
BEGIN {}
PROCESS {
        Write-Verbose "Enable and Run System Restore"
        $date = get-date
        Invoke-WmiMethod -namespace "root\default" -class "systemrestore" -name "enable" -argumentlist "c:\"
        Start-Sleep -s 15
        checkpoint-computer -description "$date"
        }
END {}
}

##############################################################################

function Start-WindowsUpdates { 
[CmdletBinding()]
        param (
                
            [Parameter(Mandatory=$True,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)]
            [string[]]$scriptlocation,
        
            [Parameter(Mandatory=$True,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True)]
            [string[]]$script
                
        )
BEGIN {}
PROCESS 
{

    $ServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
    $ServiceManager.ClientApplicationID = “My App”
    #add the Microsoft Update Service GUID
    $NewUpdateService = $ServiceManager.AddService2(“7971f918-a847-4430-9279-4a52d1efe18d”,7,”")

    #Set Windows updates to use internal WSUS
    $ip = ipconfig
    if($ip -match "192.168.40.")
        {
        Write-Verbose "Setting WSUS settings"
        Set-ClientWSUSSetting -UpdateServer "http://192.168.40.102" -UseWSUSServer Enable -AllowAutomaticUpdates Enable -DetectionFrequency 4 -Options DownloadAndInstall -RebootWarningTimeout 15 -ElevateNonAdmins Disable -AutoInstallMinorUpdates Enable -AutoRebootWithLoggedOnUsers Disable
        }
     else
        {
        Write-Verbose "Computer is not on the 192.168.40 network so we are not using WSUS"
        }

     if(test-path 'C:\_Installation_Files\Builds\Progress.txt')
        {
        $stage = Get-Content 'C:\_Installation_Files\Builds\Progress.txt'
        }
     else
        {
        New-Item 'C:\_Installation_Files\Builds\Progress.txt' -itemtype file -value "1"
        $stage = "1"
        }

    if($stage -eq "1")
    {
        do
        {
            function Get-WIAStatusValue($value)
            {
                switch -exact ($value)
                {
                    0   {"NotStarted"}
                    1   {"InProgress"}
                    2   {"Succeeded"}
                    3   {"SucceededWithErrors"}
                    4   {"Failed"}
                    5   {"Aborted"}
                } 
            }
        $needsReboot = $false
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

        
        do{
        $bing = $false
        Write-Verbose " - Searching for Updates"
        $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $availableupdates = @($SearchResult.Updates)

        foreach ($item in $availableupdates){
            if ($item.title -match "Internet Explorer 10"){
                $title = $item.title
                Write-Verbose "Hiding $title"
                $item.ishidden = $true
                }
            elseif($item.title -match "Microsoft Security Essentials"){
                $title = $item.title
                Write-Verbose "Hiding $title"
                $item.ishidden = $true
                }
            elseif($item.title -match "Bing"){
                $title = $item.title
                Write-Verbose "Hiding $title"
                $item.ishidden = $true
                $bing = $true
                }
            elseif($item.title -match "Language Pack"){
                $title = $item.title
                Write-Verbose "Hiding $title"
                $item.ishidden = $true
                }    
            }
         }
         until ($bing -eq $false)   
        
        if($availableupdates.count -eq "0")
            {
            Set-Content 'C:\_Installation_Files\Builds\Progress.txt' -Value "2"
            }

        Write-Verbose " - Found [$($availableupdates.count)] Updates to Download and install"
        $count = $availableupdates.count

            $i = 1

        foreach($Update in $availableupdates)
            {

                # Add Update to Collection
                $UpdatesCollection = New-Object -ComObject Microsoft.Update.UpdateColl
                if ( $Update.EulaAccepted -eq 0 ) { $Update.AcceptEula() }
                $UpdatesCollection.Add($Update) | out-null
      
                # Download
                Write-Verbose " + Downloading Update $i of $count $($Update.Title)"
                $UpdatesDownloader = $UpdateSession.CreateUpdateDownloader()
                $UpdatesDownloader.Updates = $UpdatesCollection
                $DownloadResult = $UpdatesDownloader.Download()
                $Message = "    - Downloaded Update $i of $count $($Update.Title) {0}" -f (Get-WIAStatusValue $DownloadResult.ResultCode)
                Write-Verbose $message   

                $i++
            }

            $i = 1

         foreach($Update in $availableupdates)
            {

            
                # Add Update to Collection
                $UpdatesCollection = New-Object -ComObject Microsoft.Update.UpdateColl
                if ( $Update.EulaAccepted -eq 0 ) { $Update.AcceptEula() }
                $UpdatesCollection.Add($Update) | out-null
      
                # Install
                Write-Verbose "    - Installing Update $i of $count"
                $UpdatesInstaller = $UpdateSession.CreateUpdateInstaller()
                $UpdatesInstaller.Updates = $UpdatesCollection
                $InstallResult = $UpdatesInstaller.Install()
                $Message = "    - Installed Update $i of $count $($Update.Title) {0}" -f (Get-WIAStatusValue $InstallResult.ResultCode)
                Write-Verbose $message
      
       
                if($installResult.rebootRequired)
                    {
                    $needsReboot = $true
                    Write-Verbose "NeedsReboot is set to $needsreboot"
                    }
         
                $i++ 
            }
        
            if($Reboot -eq $true)
                {
                $stage = Get-Content 'C:\_Installation_Files\Builds\Progress.txt' 
                New-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -Name "Test" -Value "$PSHOME\powershell.exe -Command `"& C:\_Installation_Files\Builds\DefaultBuild.ps1`""
                Write-Verbose "Restarting Computer please close all open apps"
                restart-computer
                }  
        $stage = Get-Content 'C:\_Installation_Files\Builds\Progress.txt'     
        }
        until($stage -eq "2")
    }
    elseif($stage -eq "2")
    {
    if(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\Test")
        {
        Remove-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -Name "Test"
        Remove-Item 'C:\_Installation_Files\Builds\Progress.txt'
        }
    }
        }
END {}
}

##############################################################################

function Get-WindowsUpdates {
$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

Write-Verbose " - Searching for Updates"
$SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
$availableupdates = @($SearchResult.Updates)   
$count = $availableupdates.count

$status = $false
if ($count -eq "0")
    {
    $status = $true
    }

return $status

}

##############################################################################

function New-HTMLOutput { 
[CmdletBinding()]
    param (

    [Parameter(ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True)]
    $htmlfile

    )
BEGIN {}
PROCESS {
        $machine_name = gc env:computername
        $output = "
        <html>
        <head>
            <style type=`"text/css`">
            .good {color:green;}
            .bad {color:red;}
            .neutral {color:black;}
            </style>
            <title>Build Report for [$machine_name]</title>
        </head>
        <body>
        <h2 align=center>Build Report for [$machine_name]</h2>
        <table align=center border=1 width=80%>
        <tr>
            <td><b><center>Task</center></b></td>
            <td><b><center>Result (Green=GOOD, Red=BAD, Black=NEUTRAL)</center></b></td>
            <td><b><center>Notes/Fix</center></b></td>
        "
        $output | Out-File -FilePath $htmlfile
        }
END {}
}

##############################################################################

function Set-HTMLOutput {
[CmdletBinding()]
    param (
                
    [Parameter(Mandatory=$True,
    ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True)]
    $task,
        
    [Parameter(ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True)]
    $result,

    [Parameter(ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True)]
    $color = "neutral",

    [Parameter(ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True)]
    $next,
    
    [Parameter(ValueFromPipeline=$True,
    ValueFromPipelineByPropertyName=$True)]
    $htmlfile

    )
BEGIN {}
PROCESS {
        $output = "
        <tr>
        <td>$task</td>
        <td class=$color>$result</td>
        <td class=$color>$next</td>
        </tr>
        "
        $output | out-file -filepath $htmlfile -append
        }
END {}
}

##############################################################################

function Import-WLAN { 
[CmdletBinding()]
        param (
        
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $XmlDirectory
        
        )
BEGIN {}
PROCESS {
        Get-ChildItem $xmldirectory | 
            Where-Object {$_.extension -eq ".xml"} | 
                ForEach-Object {netsh wlan add profile filename=($XmlDirectory+"\"+$_.name) user=all} 
                                           
           
        }
END {}
}

##############################################################################

function New-LocalUser { 
[CmdletBinding()]
        param (
        
        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string[]]$computername,

        [Parameter(Mandatory=$True,
        ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $username,
        
        [Parameter(ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $password,

        [Parameter(ValueFromPipeline=$True,
        ValueFromPipelineByPropertyName=$True)]
        $group
        
        )
BEGIN {}
PROCESS {
        #Connect to local computer LDAP
        $computer = [ADSI]"WinNT://$computername,computer"
        $user = $computer.Create("user", $username)
        $user.SetPassword($password)
        $user.Setinfo()
        # ADS_UF_PASSWD_CANT_CHANGE "65536"+ ADS_UF_DONT_EXPIRE_PASSWD "64
        $user.UserFlags = 65536 + 64
        $user.SetInfo()
        $group = [ADSI]("WinNT://$computername/$group,group")
        $group.add("WinNT://$username,user")
    }
END {}
}

##############################################################################
##############################################################################
##############################################################################
##############################################################################

#################################################################################################
#
#      Create an object to store results
#
#
################################################################################################


$properties = @{
Ticket='';
UsersName='';
Login='';
Client='';
Date='';
Serial='';
CompName='';
Manufacturer='';
Model='';
ExpressServiceCode='';
Domain='';
Image='';
review='';
speak='';
rename='';
labtech='';
uac='';
bios='';
office='';
sysroot='';
drivers='';
nicpower='';
uninstall='';
updates='';
power='';
localfiles='';
bkpcopy='';
clientapps='';
firewall='';
form='';
location=''
adminaccount='';
sysrestore='';
appsfolder='';
reader='';
java='';
autorestart='';
} 


if (test-path -path $buildxml) 
    {
    $build = Import-Clixml $buildxml
    }
else
    {
    $build = NEW-OBJECT PSOBJECT -property $properties
    $build | Export-Clixml $buildxml
    }  


#################################################################################################
#
#      This section is for making changes, installs, and other settings  
#
#
################################################################################################

##############################################################
#      Kaseya

if ($build.labtech -eq 'script')
    {
    }
else
    {
    if (test-path "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall")
    {
    $labtech = Get-ChildItem "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall" |
                    Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "labtech"}
    }
    else
    {
    $labtech = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                    Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "labtech"}
    }
    $labtechver = $labtech.displayversion
    if ($labtech)
        {
        Write-Verbose "labtech version $labtechver is installed"
        $build.labtech = 'script'
        $build | Export-Clixml $buildxml
        }
    else
        {
        Write-Verbose "labtech is NOT installed"
        }
    }

##############################################################
#      Drivers

if ($build.drivers -eq 'script')
    {
    }
else
    {
    $drivers = Get-DeviceStatus
    if ($drivers -eq $true)
        {
        Write-Verbose "All drivers are installed"
        $build.drivers = 'script'
        $build | Export-Clixml $buildxml
        }
    else
        {
        Write-Verbose "Some drivers are NOT installed"
        }
    }


##############################################################
#      Date

if ($build.date -eq 'script')
    {
    }
else
    {
    $date = Get-Date -format MM/dd/yyyy
    $build.date = 'script'
    $build | Export-Clixml $buildxml
    }

##############################################################
#      UAC

if ($build.uac -eq 'script')
    {
    }
else
    {
    Write-Verbose "Checking the status of UAC"
    $result = Get-UAC
    Write-Verbose "UAC status is $result"
    if ($result -eq $false)
        {
        Write-Verbose 'UAC is disabled'
        $build.uac = 'script'
        $build | Export-Clixml $buildxml
        }
    else
        {
        Write-Verbose 'Disabling UAC' 
        Disable-UAC
        $result = ""
        Write-Verbose "Checking the status of UAC"
        $result = Get-UAC
        Write-Verbose "UAC status is $result"
        if ($result -eq $false)
            {
            $build.uac = 'script'
            $build | Export-Clixml $buildxml
            }
        }
    }

$result = ""
########################################################
#    Computer Information

if ($build.manufacturer -ne "" -and $build.serial -ne "")
    {
    }
else
    {
    $bios = get-wmiobject win32_bios
    $manufacturer = $bios.manufacturer
    $serialtag = $bios.serialnumber
    $build.Serial = "$serialtag"
    $build.manufacturer = "$manufacturer"
    $build | Export-Clixml $buildxml
                 
                 
    }
########################################################
#   Express Service Code

if ($build.ExpressServiceCode -ne '')
    {
    }
elseif ($build.manufacturer -match "Dell")
    {
    $expressservicecode = Get-ExpressServiceCode
    $build.ExpressServiceCode = "$expressservicecode"
    $build | Export-Clixml $buildxml
    }
    
########################################################
#   Sys root

if ($build.sysroot -eq 'script')
    {
    }
else
    {
    $sysroot = $env:systemroot
    if ($sysroot -eq "C:\Windows")
        {
        $build.sysroot = 'script'
        }
    $build | Export-Clixml $buildxml
    }

########################################################
#   Computer Name

if ($build.CompName -ne '')
    {
    }
else
    {
    $name = (get-wmiobject win32_computersystem).name
    $build.CompName = "$name"
    $build | Export-Clixml $buildxml
    }    
    
########################################################
#   Model

if ($build.Model -ne '')
    {
    }
else
    {
    $model = (get-wmiobject win32_computersystem).model    
    $build.Model = "$model"
    $build | Export-Clixml $buildxml
    }
    
########################################################
#      Nic Power

if ($build.nicpower -eq 'script')
    {
    }
else
    {
    Write-Verbose "Checking the status of the NICs power"
    $result = Get-NicPower
    Write-Verbose "NICs power status is $result"
    if ($result)
        {
        Write-Verbose 'Disable the NIC power settings'
        Disable-NicPower
        $result = ""
        Write-Verbose "Checking the status of the NICs power"
        $result = Get-NicPower
        Write-Verbose "NICs power status is $result"
        if ($result -eq $false)
            {
            $build.nicpower = 'script'
            $build | Export-Clixml $buildxml
            }
        }
    else
        {
        Write-Verbose 'NIC power is disabled'
        $build.nicpower = 'script'
        $build | Export-Clixml $buildxml
        }
    }

$result = ""

########################################################
#      Computer Power

if ($build.power -eq 'script')
    {
    }
else
    {
    Write-Verbose "Checking the status of power settings"
    $result = Get-Power
    Write-Verbose "power settings status is $result"
    if ($result -eq $false)
        {
        Write-Verbose 'Set the power config and disable hibernate'
        Set-Power
        $result = ""
        Write-Verbose "Checking the status of power settings"
        $result = Get-Power
        Write-Verbose "power settings status is $result"
        if ($result -eq $true)
            {
            $build.power = 'script'
            $build | Export-Clixml $buildxml
            }
        }
    else
        {
        Write-Verbose 'Power config is set and Hibernate is disabled'
        $build.power = 'script'
        $build | Export-Clixml $buildxml
        }
    }

$result = ""

########################################################
#      Enable Local Admin

if ($build.adminaccount -eq 'script')
    {
    }
else
    {
    Write-Verbose 'Enable the local administrator account'
    Enable-User -username Administrator
    $build.adminaccount = 'script'
    $build | Export-Clixml $buildxml
    }

########################################################
#      System Restore

if ($build.sysrestore -eq 'script')
    {
    }
else
    {
    Write-Verbose 'Start system restore and create a restore point'
    Start-SystemRestore
    $build.sysrestore = 'script'
    $build | Export-Clixml $buildxml
    }

########################################################
#    Copying all necessary files to the local drive 

if ($build.appsfolder -eq 'script')
    {
    }
else
    {
    if (Test-Path "C:\_Installation_Files\Apps\Adobe\Reader")
        {
        Write-Verbose '_Installation_Files folder already exist'
        }
    else
        {
        Write-Verbose 'Creating _Installation_Files folder'
        New-Item -path "C:\_Installation_Files\Apps\Adobe\Reader" -ItemType directory
        }

    if (Test-Path "C:\_Installation_Files\Apps\Java")
        {
        Write-Verbose 'Java folder already exist'
        }
    else
        {
        Write-Verbose 'Creating Java folder'
        New-Item -path "C:\_Installation_Files\Apps\Java" -ItemType directory
        }

    $build.appsfolder = 'script'
    $build | Export-Clixml $buildxml
    }
        
##############################################################
#     Install Latest Adobe Reader

if ($build.reader -eq 'script')
{
}
else
{
    $client = $machine_name.Split("-")[0]
    $latestversion = '15.016.20039'
    #source and target files
    
    $source = "ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC/1500920069/AcroRdrDC1501620039_en_US.exe"
    $target = "C:\_Installation_Files\Apps\Adobe\Reader\AcroRdrDC1501620039_en_US.exe"

        
    $acrobat = Get-WmiObject win32_product | where {$_.name -match "adobe" -and $_.name -match "acrobat"}
    if ($acrobat)
    {
        Write-Verbose "Adobe Acrobat is installed and reader is not needed"
        $build.reader = 'script'
        $build | Export-Clixml $buildxml
    }
    elseif ($client -eq 'CSP')
    {
        Write-Verbose "Not installing Adobe Reader due to it being a CSP computer."
        $build.reader = 'script'
        $build | Export-Clixml $buildxml
    }
    elseif ($client -eq "PIC")
    {
        Write-Verbose "Not installing Adobe Reader due to it being a PIC computer."
        $build.reader = 'script'
        $build | Export-Clixml $buildxml
    }
    else
    {
        Write-Verbose "Checking to see if Adobe Reader $latestversion is installed"
        $reader = Get-WmiObject win32_product | where {$_.name -match "adobe" -and $_.name -match "reader"} 
        $readerver = $reader.version
            
        if ($readerver -ne $null)
            {
                Write-Verbose "Reader Version $readerver is installed"
                if ($readerver -eq $latestversion) 
                    {
                        Write-Verbose "Reader version $readerver is the latest version $latestversion"
                        $build.reader = 'script'
                        $build | Export-Clixml $buildxml
                    }
                elseif ($readerver -gt $latestversion)
                    {
                        Write-Verbose "Reader version $readerver is newer than latest version $latestversion"
                        $build.reader = 'script'
                        $build | Export-Clixml $buildxml
                    }
                else
                    {
                        Write-Verbose "Uninstalling previous version of Adobe Reader"
                        $readerguid = (Get-WmiObject win32_product | where {$_.name -match "Adobe Reader"}).IdentifyingNumber
                        $ReaderRemoveCMD = "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall $readerguid /qn`" -wait -passthru).ExitCode"
                        Invoke-Expression $ReaderRemoveCMD
                        $readerafter = Get-WmiObject win32_product | where {$_.name -match "adobe" -and $_.name -match "reader"}
                        
                        if ($readerafter -ne $null)
                            {   
                                Write-Verbose "Adobe Reader $readerver did NOT uninstall properly.  Please uninstall it manually"
                                
                            }
                        else
                            {
                                Write-Verbose "Adobe Reader $readerver has been uninstalled properly"
                                Write-Verbose "Ready to install a fresh copy"
                                if (test-path $target)
                                    {
                                        Write-Verbose "Adobe Reader has already been downloaded"
                                    }
                                else
                                    {
                                        Write-Verbose "Downloading Adobe Reader $latestversion"
                                        Get-HTTPfile $source $target
                                    }
                                Write-Verbose "Installing Adobe Reader $latestversion"    
                                $readercmd = "(Start-Process -FilePath $target -ArgumentList `"/msi /qn`" -wait -passthru).ExitCode"

                                Invoke-Expression $readercmd
                                $readerafter = Get-WmiObject win32_product | where {$_.name -match "adobe" -and $_.name -match "reader"}

                                if ($readerafter.version -ne $latestversion)
                                    {
                                        Write-Verbose "Adobe Reader version $latestversion did NOT install properly.  Please install it manually!"
                                    }
                                else
                                    {
                                        Write-Verbose "Adobe Reader version $latestversion installed"
                                        $build.reader = 'script'
                                        $build | Export-Clixml $buildxml
                                    }
                            }
                    }
            }
        else 
            {
            Write-Verbose "Reader is not installed"
            Write-Verbose "Ready to install a fresh copy"
            if (test-path $target)
                {
                    Write-Verbose "Adobe Reader has already been downloaded"
                }
            else
                {
                    Write-Verbose "Downloading Adobe Reader $latestversion"
                    Get-HTTPfile $source $target
                    Start-Sleep 60
                }
            Write-Verbose "Installing Adobe Reader $latestversion"    
            $readercmd = "(Start-Process -FilePath $target -ArgumentList `"/msi /qn`" -wait -passthru).ExitCode"

            Invoke-Expression $readercmd
            $readerafter = Get-WmiObject win32_product | where {$_.name -match "adobe" -and $_.name -match "reader"}

            if ($readerafter.version -ne $latestversion)
                {
                    Write-Verbose "Adobe Reader version $latestversion did NOT install properly.  Please install it manually!"
                }
            else
                {
                    Write-Verbose "Adobe Reader version $latestversion installed"
                    $build.reader = 'script'
                    $build | Export-Clixml $buildxml
                }
            }
    }        
}       
 


##############################################################
#     Install Java

if ($build.java -eq 'script')
    {
    }
else
    {
    $javalatest = '8.0.910.15'
    $client = $machine_name.Split("-")[0]
    # Java Plugin source and target files
    $javasource = "http://javadl.oracle.com/webapps/download/AutoDL?BundleId=210183"
    
    $javatargetpath = "C:\_Installation_Files\Apps\Java\jre-8u91-windows-i586.exe"
    $javacmd = "C:\_Installation_Files\Apps\Java\jre-8u91-windows-i586.exe /s"
    

    Write-Verbose "Checking to see if java is installed"
    if (test-path "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall")
    {
        $java = Get-ChildItem "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall" |
                    Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
    }
    else
    {
        $java = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                    Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
    }
    $javaver = $java.displayversion

    if ($javaver -eq $null)
    {
        Write-Verbose "java is not installed"
    }
    else
    {
        Write-Verbose "Version $javaver is installed"  
    }

    if ($javaver -eq $javalatest) 
        {
            Write-Verbose "java is already the latest version"
            $build.java = 'script'
            $build | Export-Clixml $buildxml
        }
    elseif ($client -eq 'CSP')
        {
            Write-Verbose "Not installing Java due to it being a CSP computer."
            $build.java = 'script'
            $build | Export-Clixml $buildxml
        }
    elseif ($client -eq "PIC")
        {
            Write-Verbose "Not installing Java due to it being a PIC computer."
            $build.java = 'script'
            $build | Export-Clixml $buildxml
        }
    elseif ($javaver -lt $javalatest -and $javaver -ne $null)
    {
        Write-Verbose "Uninstalling previous version of Java"
        $javaguid = (Get-WmiObject win32_product | where {$_.Name -match "java" -and $_.Name -ne "java auto updater"}).IdentifyingNumber
        $javaRemoveCMD = "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall $javaguid /qn`" -wait -passthru).ExitCode"
        Invoke-Expression $javaRemoveCMD

        if (test-path "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall")
        {
            $javaafter = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
                        Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
        }
        else
        {
            $javaafter = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                        Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
        }    
        
        if ($javaafter -eq $null)
        {
            if (test-path $javatargetpath)
            {
                Write-Verbose "java has already been downloaded"
            }
            else
            {
                Write-Verbose "Downloading java"
                Get-HTTPfile $javasource $javatargetpath
            }
            Write-Verbose "Installing java"
            Invoke-Expression $javacmd
            start-sleep 20
            
            if (test-path "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall")
            {
                $javaafter2 = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
                    Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
            }
            else
            {
                $javaafter2 = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                    Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
            }

            if ($javaafter2 -eq $null)
            {
                Write-Verbose "java did NOT install properly.  Please install it manually!"
            }
            else
            {
                Write-Verbose "java has been installed properly"
                $build.java = 'script'
                $build | Export-Clixml $buildxml
            }
        }
        else
        {
            Write-Verbose "The previous version of java did NOT uninstalled properly.  Please remove it manually!"
        }
    }
    elseif ($java -eq $null)
    {
        if (test-path $javatargetpath)
        {
            Write-Verbose "java has already been downloaded"
        }
        else
        {
            Write-Verbose "Downloading java"
            Get-HTTPfile $javasource $javatargetpath
        }
        
        Write-Verbose "Installing java"
        Invoke-Expression $javacmd
        start-sleep 20
        
        if (test-path "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall")
        {
            $javaafter2 = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
                Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
        }
        else
        {
            $javaafter2 = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
        }
        
        if ($javaafter2 -eq $null)
        {
            Write-Verbose "java did NOT install properly.  Please install it manually!"
        }
        else
        {
            Write-Verbose "java has been installed properly"
            $build.java = 'script'
            $build | Export-Clixml $buildxml
        }
    }
}
        
########################################################


        
########################################################
#      Uninstalling unecessary applications

if ($build.uninstall -eq 'script')
    {
    }
else
    {
        #############################################################
        #       MSIEXEC INSTALLER APPLICATIONS
        #############################################################

        [ARRAY]$msiapps = ("Bing BAR", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} /qn`" -Wait -Passthru).ExitCode"),
        ("Dell Feature Enhancement Pack", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} /qn`" -Wait -Passthru).ExitCode"),
        ("Dell System Manager", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} /qn`" -Wait -Passthru).ExitCode"),
	    ("Trend Micro Client/Server Security Agent", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} /qn`" -Wait -Passthru).ExitCode"),
        ("Trend Micro Titanium Internet Security", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} /qn`" -Wait -Passthru).ExitCode"),
        ("Message Center Plus", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} /qn`" -Wait -Passthru).ExitCode"),
        ("ThinkVantage Active Protection System", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} REBOOT=REALLYSUPPRESS /qn`" -Wait -Passthru).ExitCode"),
        ("AT&T Service Activation", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} /qn`" -Wait -Passthru).ExitCode"),
        ("Sonic Icons for Lenovo", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} /qn`" -Wait -Passthru).ExitCode"),
        ("Client Security Solution", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} REBOOT=REALLYSUPPRESS /qn`" -Wait -Passthru).ExitCode"),
        ("Verizon Wireless Mobile Broadband Self Activation", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} /qn`" -Wait -Passthru).ExitCode"),
        ("Client Security - Password Manager", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} REBOOT=REALLYSUPPRESS /qn`" -Wait -Passthru).ExitCode")
        ("LabTechAD", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} REBOOT=REALLYSUPPRESS /qn`" -Wait -Passthru).ExitCode")
       
        foreach($item in $msiapps)
            {
            Remove-Software -application $item[0] -command $item[1]
            }

        #######################################################
        #   CMD Installer Apps
        #######################################################

        [ARRAY]$cmdapps = ("VNC", "`& `"C:\Program Files\RealVNC\VNC4\unins000.exe`" /SILENT"),
                ("Lenovo Registration", "`& `"C:\Program Files\Lenovo Registration\uninstall.exe`" /qn")

        foreach($item in $cmdapps)
            {
            Remove-Software -application $item[0] -command $item[1]
            }

        #############################################
        #     Check to see if any of the apps are installed

        $appstatus = $true
        foreach($item in $msiapps)
            {
            $name = $item[0]
            Write-Verbose "Checking to see if $name is installed"
            $app = get-wmiobject win32_product | where {$_.name -match $name}
            if ($app)
                {
                Write-Verbose "$name is still installed"
                $appstatus = $false
                }
            else
                {
                Write-Verbose "$name is NOT installed"
                }
            }

        foreach($item in $cmdapps)
            {
            $app = ''
            $name = ''
            $name = $item[0]
            Write-Verbose "Checking to see if $name is installed"
            
            # test path to see if x64 registry location exists
            if (test-path "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall")
            {
                $app = Get-ChildItem "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall" |
                    Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "$name"}
            }
            else
                {
                $app = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                    Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "$name"}
                }

            
            if ($app)
                {
                Write-Verbose "$name is still installed"
                $appstatus = $false
                }
            else
                {
                Write-Verbose "$name is NOT installed"
                }
            }

        if ($appstatus -eq $true) 
            {
            Write-Verbose "All MSI and EXE junk apps are uninstalled." 
            $build.uninstall = 'script'
            $build | Export-Clixml $buildxml

            }      
    }            
            
                
########################################################
#      Set Automatic Restarts on BSOD to disable

if ($build.autorestart -eq 'script')
    {
    }
else
    {
    Set-ItemProperty -Path "hklm:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Value "00000000"
    $build.autorestart = 'script'
    $build | Export-Clixml $buildxml
    }


    
Write-Verbose "The build script ended successfully"

Stop-Transcript

#################################################################################################
#
#      End Script
#
#
################################################################################################ 



  


