Start-Transcript -Path "C:\Windows\LTSvc\Scripts\WorkstationBuild_Transcript.rtf" -append -NoClobber

###############################################################################################
#  Created by Carlos McCray
#  Last Update 6/17/2016

$VerbosePreference = "Continue"
$machine_name = gc env:computername
$htmlfile = "C:\Windows\LTSvc\Scripts\WorkstationBuild_$machine_name.html"
$OperatingSystem = (get-wmiobject win32_operatingsystem).caption
$OSArchitecture = (get-wmiobject win32_operatingsystem).OSArchitecture
$buildxml = 'C:\Windows\LTSvc\Scripts\build.xml'

########################################################
#    Create folder structure for temp install files 

if (Test-Path "C:\Windows\LTSvc\Scripts\Apps\Adobe\Reader"){
    Write-Verbose 'Reader folder already exist'
 } else {
    Write-Verbose 'Creating Reader folder'
    New-Item -path "C:\Windows\LTSvc\Scripts\Apps\Adobe\Reader" -ItemType directory
}

if (Test-Path "C:\Windows\LTSvc\Scripts\Apps\Java"){
    Write-Verbose 'Java folder already exist'
} else {
    Write-Verbose 'Creating Java folder'
    New-Item -path "C:\Windows\LTSvc\Scripts\Apps\Java" -ItemType directory
}

<#
List of available functions

Remove-Software
Get-HTTPFile 
Start-SystemRestore 
Disable-NicPower
Get-NicPower
Get-Power 
Set-Power 

#>

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
 
Function Get-HTTPFile ($url,$file,$username,$password){
$webclient = New-Object System.Net.WebClient
$webclient.Credentials = New-Object System.Net.NetworkCredential($username,$password) 
$webclient.DownloadFile($url,$file)
}

################################################################
 
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

########################################################
#      Setup Object to store results of script for restarts

$properties = @{
uninstall='';
appsfolder='';
reader='';
java='';
sysrestore='';
nicpower='';
power='';

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
	    ("Message Center Plus", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} /qn`" -Wait -Passthru).ExitCode"),
        ("ThinkVantage Active Protection System", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} REBOOT=REALLYSUPPRESS /qn`" -Wait -Passthru).ExitCode"),
        ("AT&T Service Activation", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/X{} /qn`" -Wait -Passthru).ExitCode"),
        ("Sonic Icons for Lenovo", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} /qn`" -Wait -Passthru).ExitCode"),
        ("Client Security Solution", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} REBOOT=REALLYSUPPRESS /qn`" -Wait -Passthru).ExitCode"),
        ("Verizon Wireless Mobile Broadband Self Activation", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} /qn`" -Wait -Passthru).ExitCode"),
        ("Client Security - Password Manager", "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall {} REBOOT=REALLYSUPPRESS /qn`" -Wait -Passthru).ExitCode")
       
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

       
##############################################################
#     Install Latest Adobe Reader

if ($build.reader -eq 'script')
{
}
else
{
    $client = $machine_name.Split("-")[0]
    $latestversion = '15.017.20053'
    #source and target files
    $source = "ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC/1501720050/AcroRdrDC1501720050_en_US.exe"
    $target = "C:\Windows\LTSvc\Scripts\Apps\Adobe\Reader\AcroRdrDC1501720050_en_US.exe"
    $acrobat = Get-WmiObject win32_product | where {$_.name -match "adobe" -and $_.name -match "acrobat"}
    
    if ($acrobat){
        Write-Verbose "Adobe Acrobat is installed and reader is not needed"
        $build.reader = 'script'
        $build | Export-Clixml $buildxml
    } else {
        Write-Verbose "Checking to see if Adobe Reader $latestversion is installed"
        $reader = Get-WmiObject win32_product | where {$_.name -match "adobe" -and $_.name -match "reader"} 
        $readerver = $reader.version
            
        if ($readerver -ne $null) {
            Write-Verbose "Reader Version $readerver is installed"
            if ($readerver -eq $latestversion) {
                Write-Verbose "Reader version $readerver is the latest version $latestversion"
                $build.reader = 'script'
                $build | Export-Clixml $buildxml
            } elseif ($readerver -gt $latestversion) {
                Write-Verbose "Reader version $readerver is newer than latest version $latestversion"
                $build.reader = 'script'
                $build | Export-Clixml $buildxml
            } else {
                Write-Verbose "Uninstalling previous version of Adobe Reader"
                $readerguid = (Get-WmiObject win32_product | where {$_.name -match "Adobe Reader"}).IdentifyingNumber
                $ReaderRemoveCMD = "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall $readerguid /qn`" -wait -passthru).ExitCode"
                Invoke-Expression $ReaderRemoveCMD
                $readerafter = Get-WmiObject win32_product | where {$_.name -match "adobe" -and $_.name -match "reader"}
                        
                if ($readerafter -ne $null){   
                    Write-Verbose "Adobe Reader $readerver did NOT uninstall properly.  Please uninstall it manually"
                } else {
                    Write-Verbose "Adobe Reader $readerver has been uninstalled properly"
                    Write-Verbose "Ready to install a fresh copy"
                    if (test-path $target) {
                        Write-Verbose "Adobe Reader has already been downloaded"
                    } else {
                        Write-Verbose "Downloading Adobe Reader $latestversion"
                        Get-HTTPfile $source $target
                    }
                    Write-Verbose "Installing Adobe Reader $latestversion"    
                    $readercmd = "(Start-Process -FilePath $target -ArgumentList `"/msi /qn`" -wait -passthru).ExitCode"

                    Invoke-Expression $readercmd
                    $readerafter = Get-WmiObject win32_product | where {$_.name -match "adobe" -and $_.name -match "reader"}

                    if ($readerafter.version -ne $latestversion) {
                        Write-Verbose "Adobe Reader version $latestversion did NOT install properly.  Please install it manually!"
                    } else {
                        Write-Verbose "Adobe Reader version $latestversion installed"
                        $build.reader = 'script'
                        $build | Export-Clixml $buildxml
                    }
                }
            }
        } else {
            Write-Verbose "Reader is not installed"
            Write-Verbose "Ready to install a fresh copy"
            if (test-path $target) {
                Write-Verbose "Adobe Reader has already been downloaded"
            } else {
                Write-Verbose "Downloading Adobe Reader $latestversion"
                Get-HTTPfile $source $target
                Start-Sleep 60
            }
            Write-Verbose "Installing Adobe Reader $latestversion"    
            $readercmd = "(Start-Process -FilePath $target -ArgumentList `"/msi /qn`" -wait -passthru).ExitCode"

            Invoke-Expression $readercmd
            $readerafter = Get-WmiObject win32_product | where {$_.name -match "adobe" -and $_.name -match "reader"}

            if ($readerafter.version -ne $latestversion) {
                Write-Verbose "Adobe Reader version $latestversion did NOT install properly.  Please install it manually!"
            } else {
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
    $javalatest = '8.0.1010.13'
    # Java Plugin source and target files

    $javasource = "http://javadl.oracle.com/webapps/download/AutoDL?BundleId=211997"
                    
    $javatargetpath = "C:\Windows\LTSvc\Scripts\Apps\Java\jre-8u101-windows-i586.exe"
    $javacmd = "C:\Windows\LTSvc\Scripts\Apps\Java\jre-8u101-windows-i586.exe /s"
    

    Write-Verbose "Checking to see if java is installed"
    if (test-path "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall") {
        $java = Get-ChildItem "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall" |
                    Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater" -and $_.DisplayName -notmatch "Development" -and $_.DisplayName -notmatch "JavaScript"}
    } else {
        $java = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                    Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater" -and $_.DisplayName -notmatch "Development" -and $_.DisplayName -notmatch "JavaScript"}
    }
    $javaver = $java.displayversion

    if ($javaver -eq $null) {
        Write-Verbose "java is not installed"
    } else {
        Write-Verbose "Version $javaver is installed"  
    }

    if ($javaver -eq $javalatest) {
            Write-Verbose "java is already the latest version"
            $build.java = 'script'
            $build | Export-Clixml $buildxml
    } elseif ($javaver -lt $javalatest -and $javaver -ne $null) {
        Write-Verbose "Uninstalling previous version of Java"
        $javaguid = (Get-WmiObject win32_product | where {$_.Name -match "java" -and $_.Name -ne "java auto updater"}).IdentifyingNumber
        $javaRemoveCMD = "(Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/uninstall $javaguid /qn`" -wait -passthru).ExitCode"
        Invoke-Expression $javaRemoveCMD

        if (test-path "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall") {
            $javaafter = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
                        Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
        } else {
            $javaafter = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                        Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
        }    
        
        if ($javaafter -eq $null) {
            if (test-path $javatargetpath) {
                Write-Verbose "java has already been downloaded"
            } else {
                Write-Verbose "Downloading java"
                Get-HTTPfile $javasource $javatargetpath
            }
            Write-Verbose "Installing java"
            Invoke-Expression $javacmd
            start-sleep 20
            
            if (test-path "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall") {
                $javaafter2 = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
                    Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
            } else {
                $javaafter2 = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                    Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
            }

            if ($javaafter2 -eq $null) {
                Write-Verbose "java did NOT install properly.  Please install it manually!"
            } else {
                Write-Verbose "java has been installed properly"
                $build.java = 'script'
                $build | Export-Clixml $buildxml
            }
        } else {
            Write-Verbose "The previous version of java did NOT uninstalled properly.  Please remove it manually!"
        }
    } elseif ($java -eq $null) {
        if (test-path $javatargetpath) {
            Write-Verbose "java has already been downloaded"
        } else {
            Write-Verbose "Downloading java"
            Get-HTTPfile $javasource $javatargetpath
        }
        
        Write-Verbose "Installing java"
        Invoke-Expression $javacmd
        start-sleep 20
        
        if (test-path "HKLM:\Software\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall") {
            $javaafter2 = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
                Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
        } else {
            $javaafter2 = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "java" -and $_.DisplayName -ne "java auto updater"}
        }
        
        if ($javaafter2 -eq $null) {
            Write-Verbose "java did NOT install properly.  Please install it manually!"
        } else {
            Write-Verbose "java has been installed properly"
            $build.java = 'script'
            $build | Export-Clixml $buildxml
        }
    }
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
        if ($result -eq $false){
            $build.nicpower = 'script'
            $build | Export-Clixml $buildxml
        }
    } else {
        Write-Verbose 'NIC power is disabled'
        $build.nicpower = 'script'
        $build | Export-Clixml $buildxml
    }
}

$result = ""

########################################################
#      Computer Power

if ($build.power -eq 'script'){
} else {
    Write-Verbose "Checking the status of power settings"
    $result = Get-Power
    Write-Verbose "power settings status is $result"
    if ($result -eq $false){
        Write-Verbose 'Set the power config and disable hibernate'
        Set-Power
        $result = ""
        Write-Verbose "Checking the status of power settings"
        $result = Get-Power
        Write-Verbose "power settings status is $result"
        if ($result -eq $true){
            $build.power = 'script'
            $build | Export-Clixml $buildxml
        }
    } else {
        Write-Verbose 'Power config is set and Hibernate is disabled'
        $build.power = 'script'
        $build | Export-Clixml $buildxml
    }
}

$result = ""

########################################################

Write-Verbose "The build script ended successfully"

Stop-Transcript

#################################################################################################
#       End Script




















