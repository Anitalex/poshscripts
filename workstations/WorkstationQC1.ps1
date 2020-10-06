Start-Transcript -Path "C:\Windows\LTSvc\Scripts\WorkstationQC_Transcript.rtf" -append -NoClobber


############################################
# define output file for appending to HTML

$verbosepreference = 'continue'
$os = (gwmi Win32_OperatingSystem -computer localhost).caption
$bios_output
$machine_name = gc env:computername
$WorkstationQC_htmlfile = "C:\Windows\LTSvc\Scripts\WorkstationQC_$machine_name.html"

$WorkstationQCheader = "
<html>
<head>
    <style type=`"text/css`">
    .good {color:green;}
    .bad {color:red;}
    </style>
    <title>Build Quality Control report for [$machine_name]</title>
</head>
<body>
<h2 align=center>Build Quality Control report for [$machine_name]</h2>
<table align=center border=1 width=80%>
<tr>
    <td><b><center>Quality Check Task</center></b></td>
    <td><b><center>Result (Green=GOOD, Red=BAD)</center></b></td>
    <td><b><center>Notes/Fix</center></b></td>
"
$WorkstationQCheader | Out-File -FilePath $WorkstationQC_htmlfile

###############################################
####   Functions

#####################################################
#   Create the license Key Section at the bottom

function LicenseKeySection {
# this just starts a new section near the bottom for license keys as I can decode them
$lk_section = "
</table>
<h2 align=center>Software Licensing</h2>
<table align=center border=1 width=80%>
<tr>
    <td><b><center>Software Package</center></b></td>
    <td><b><center>License Key</center></b></td>
</tr>
"
$lk_section  | Out-File -FilePath $WorkstationQC_htmlfile -append

}

#####################################################
#   Create the Client Section at the bottom

function ClientSection {
# this just starts a new section near the bottom for client specific settings
$lk_section = "
</table>
<h2 align=center>Client Settings and Software Section</h2>
<table align=center border=1 width=80%>
<tr>
    <td><b><center>Client Setting\Software</center></b></td>
    <td><b><center>Result</center></b></td>
</tr>
"
$lk_section  | Out-File -FilePath $WorkstationQC_htmlfile -append

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
    

    $chassis_output = "
        <tr>
            <td>Chassis Type</td>
            <td class=neutral>Chassis is a $chassis</td>
            <td class=neutral>$chassis</td>
        </tr>
        "
    $chassis_output | Out-File -FilePath $WorkstationQC_htmlfile -append
    return $chassis
}

############################################
# Check for what drive Windows is installed on

function OSLocationCheck {
    $sysroot = gc env:systemroot
    
    if($sysroot -match "C:") {    
    $oscheck_output = "
        <tr>
            <td>Operating System install location</td>
            <td class=good>Installed at $sysroot!</td>
            <td class=good>Correct</td>
        </tr>
        "
    } else {
    $oscheck_output = "
        <tr>
            <td>Operating System install location</td>
            <td class=bad>Installed at $sysroot!</td>
            <td class=bad>REBUILD THE MACHINE!</td>
        </tr>
        "
    }
    $oscheck_output | Out-File -FilePath $WorkstationQC_htmlfile -append
}

############################################
# Checking the status of activation

function Get-ActivationStatus {
    $products = Get-WmiObject SoftwareLicensingProduct -Filter "PartialProductKey LIKE '%'" | select description, licensestatus

    foreach ($product in $products) {
        $name = $product.description
        $status = $product.licensestatus

        if ($status -eq 1) {
            $osactiv_output = "
            <tr>
                <td>OS and Office Activation</td>
                <td class=good>$name is activated!</td>
                <td class=good>Correct</td>
            </tr>
            "
        } else {
            $osactiv_output = "
            <tr>
                <td>OS and Office Activation</td>
                <td class=bad>$name needs to be activated!</td>
                <td class=bad>Please activate the $name!</td>
            </tr>
            "
        }
        $osactiv_output | Out-File -FilePath $WorkstationQC_htmlfile -append
    }
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
        
    
            $hw_check_output = "
            <tr>
                <td>Hardware Status Check</td>
                <td class=bad>$dev_desc has an error!</td>
                <td class=bad>Go into Device Manager and fix $dev_devID !</td>
            </tr>
            "
            $hw_check_output | Out-File -FilePath $WorkstationQC_htmlfile -append
        }
    
    } elseif($hw_count -eq 0 -or $hw_count -eq $null) {
        $hw_check_output = "
        <tr>
            <td>Hardware Status Check</td>
            <td class=good>There are no items with errors!</td>
            <td class=good>Correct</td>
        </tr>
        "
        $hw_check_output | Out-File -FilePath $WorkstationQC_htmlfile -append
    }


}

############################################
# Check to see if the Standard VGA driver is being used

function StandardVGACheck {
    
    $name = (Get-WmiObject Win32_videocontroller).name 
    if ($name -match "Standard VGA") {
        $video_check_output = "
        <tr>
            <td>Standard VGA Check</td>
            <td class=bad>The Standard VGA Adapter!</td>
            <td class=bad>Please update the driver!</td>
        </tr>
        "
    } else {
        $video_check_output = "
        <tr>
            <td>Standard VGA Check</td>
            <td class=good>The Standard VGA Adapter is not there!</td>
            <td class=good>Correct!</td>
        </tr>
        "

    }

    $video_check_output | Out-File -FilePath $WorkstationQC_htmlfile -append

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
        $uac_check_output = "
        <tr>
            <td>User Account Control Check</td>
            <td class=good>UAC is enabled.</td>
            <td class=good>Correct because it is Windows 8</td>
        </tr>
        "
        } else {
        $uac_check_output = "
        <tr>
            <td>User Account Control Check</td>
            <td class=bad>UAC is still enabled.</td>
            <td class=bad>Disable UAC!</td>
        </tr>
        "
        }
    } else {
        $uac_check_output = "
        <tr>
            <td>User Account Control Check</td>
            <td class=good>UAC is disabled.</td>
            <td class=good>Correct</td>
        </tr>
        "
    }
    $uac_check_output | Out-File -FilePath $WorkstationQC_htmlfile -append
}

############################################
# Check to see if Labtech is running

function LabTechCheck {

    $LabTechcheck = get-service | where-object {$_.name -match "LTService"}
    if($LabTechcheck.status -match "Running") {
        $LabTech_output = "
        <tr>
            <td>LabTech Agent Check</td>
            <td class=good>LabTech is running.</td>
            <td class=good>Correct</td>
        </tr>
        "
    } else {
        $LabTech_output = "
        <tr>
            <td>LabTech Agent Check</td>
            <td class=bad>LabTech is stopped, paused, or does not exist.</td>
            <td class=bad>Start the agent and ensure checkin.</td>
        </tr>
        "
    }

    $LabTech_output | out-file -filepath $WorkstationQC_htmlfile -append
}

############################################
# Check to see if Adobe Reader or Acrobat is installed and up to date

function AdobeReaderCheck {

    #### set the target version ####
    $target_acrobat_version= "15.017.20053"
    $target_acrobat_version_trim= $target_acrobat_version.Replace(".","")
  
    $reader_check_query = gwmi -class Win32_Product | Where-Object {$_.Name -match "Adobe Reader"}
    $acrobat = Get-WmiObject win32_product | where {$_.name -match "adobe" -and $_.name -match "acrobat"}

    # Checks the version (if it exists) and goes from there.
    $readerVersion = $reader_check_query.Version
    if ($readerVersion -ne $null){
    $readerVerTrimmed = $readerVersion.Replace(".","")
    }

    # If it doesn't exist...
    if(!$readerVersion -and !$acrobat) {
        $reader_check_output = "
    <tr>
        <td>Adobe Reader Check</td>
        <td class=bad>NOT INSTALLED</td>
        <td class=bad>Adobe Reader $target_acrobat_version and Adobe Acrobat not installed!</a></td>
    </tr>

    "
    } elseif($acrobat -and !$readerVersion) {
    $reader_check_output = "
    <tr>
        <td>Adobe Reader Check</td>
        <td class=good>Acrobat $readerVersion is installed</td>
        <td class=good>The full version of Acrobat is installed!</a></td>
    </tr>

    "
    } elseif($readerVerTrimmed -lt $target_acrobat_version_trim) {
    $reader_check_output = "
    <tr>
        <td>Adobe Reader Check</td>
        <td class=bad>Version $readerVersion is not the latest version!</td>
        <td class=bad>Update to Adobe Reader $target_acrobat_version !</a></td>
    </tr>

    "
    } elseif($readerVerTrimmed -eq $target_acrobat_version_trim) {
    $reader_check_output = "
    <tr>
        <td>Adobe Reader Check</td>
        <td class=good>Adobe Reader installed and is version $target_acrobat_version.</td>
        <td class=good>Correct</td>
    </tr>

    "
    } elseif($readerVerTrimmed -gt $target_acrobat_version_trim) {
    $reader_check_output = "
    <tr>
        <td>Adobe Reader Check</td>
        <td class=Neutral>Adobe Reader installed but is version $readerVerTrimmed . $target_acrobat_version is no longer the latest version.</td>
        <td class=Neutral>Update Default Build and QC scripts.</td>
    </tr>

    "
    }
    $reader_check_output | Out-File -FilePath $WorkstationQC_htmlfile -append
}

##############################################################

function JavaCheck {

    #### set target version ####
    $target_java_version= "8.0.1010.13"

    if (test-path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"){
        $java = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
            Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "Java" -and $_.DisplayName -ne "java auto updater"}
    } else {
        $java = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
              Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "Java" -and $_.DisplayName -ne "java auto updater"}
    }
    
    $javaver = $java.displayversion

    # If it doesn't exist...
    if($javaver -eq $null){
        $java_output = "
            <tr>
                <td>Java Check</td>
                <td class=bad>NOT INSTALLED</td>
                <td class=bad>Java $target_java_version not installed!</a></td>
            </tr>
            "
    } elseif($javaver -lt $target_java_version)  {
        $java_output = "
            <tr>
                <td>Java Check</td>
                <td class=bad>Version $javaver is not the latest version!</td>
                <td class=bad>Update to Java $target_java_version !</a></td>
            </tr>
            "
    } elseif($javaver -eq $target_java_version) {
        $java_output = "
            <tr>
                <td>Java Check</td>
                <td class=good>Java installed and is version $target_java_version .</td>
                <td class=good>Correct</td>
            </tr>
            "
    } elseif($javaver -gt $target_java_version) {
        $java_output = "
            <tr>
                <td>Java Check</td>
                <td class=Neutral>Java installed but is version $AirAXver . $target_air_version is no longer the latest version.</td>
                <td class=Neutral>Update Default Build and QC scripts</td>
            </tr>
            "
    }
    $java_output | Out-File -FilePath $WorkstationQC_htmlfile -append
}

############################################
# Check to see if unwanted software is installed

function UninstallCheck {
    $msiapps = (
                "Bing BAR",
                "Dell Feature Enhancement Pack",
                "Dell System Manager",
                "Trend Micro Client/Server Security Agent",
                "Trend Micro Titanium Internet Security",
                "Message Center Plus",
                "ThinkVantage Active Protection System",
                "AT&T Service Activation",
                "Sonic Icons for Lenovo",
                "Client Security Solution",
                "Verizon Wireless Mobile Broadband Self Activation",
                "McAfee AntiVirus Plus",
                "McAfee SiteAdvisor",
                "Client Security - Password Manager"
                )

    foreach ($app in $msiapps){ 
    if (test-path 'c:\program files (x86)\'){
    $application = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
              Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "$app"}
    } else {
    $application = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
              Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "$app"}
    }

        if($application -ne $null) {
            $application_output = "
                <tr>
                    <td>$app Status Check</td>
                    <td class=bad>$app is installed</td>
                    <td>Remove $app!</a></td>
                </tr>

                "
            }
        elseif($application -eq $null) {
            $application_output = "
                <tr>
                    <td>$app Status Check</td>
                    <td class=good>$app is not installed.</td>
                    <td class=good>Correct</td>
                </tr>

                "
            }
    $application_output | Out-File -FilePath $WorkstationQC_htmlfile -append
    }
}

############################################
# check to see if Dell Digital Delivery is installed

function DellDigitalDeliveryCheck {

    $manufacturer = (get-wmiobject win32_computersystem).manufacturer 
    if ($manufacturer -match "Dell"){
        if (test-path 'c:\program files (x86)\'){
        $DellDigitalDelivery = Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" |
                  Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "Dell Digital Delivery"}
        } else {
        $DellDigitalDelivery = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
                  Foreach{gp $_.PSPath} | Where{$_.DisplayName -match "Dell Digital Delivery"}
        }

        if($DellDigitalDelivery -ne $null) 
        {
            $DellDigitalDelivery_output = "
                <tr>
                    <td>Dell Digital Delivery Status Check</td>
                    <td class=bad>Dell Digital Delivery is installed</td>
                    <td class=bad>Make sure you reset it to check for software to download and then uninstall!</a></td>
                </tr>

                "
        }
        elseif($DellDigitalDelivery -eq $null)
        {
            $DellDigitalDelivery_output = "
                <tr>
                    <td>Dell Digital Delivery Status Check</td>
                    <td class=good>Dell Digital Delivery is not installed.</td>
                    <td class=good>Great job!</td>
                </tr>

                "
        }
    }
    else {
        $DellDigitalDelivery_output = "
                <tr>
                    <td>Dell Digital Delivery Status Check</td>
                    <td class=neutral>The computer is not a Dell</td>
                    <td class=neutral>Nothing to do</td>
                </tr>

                "
    }
    $DellDigitalDelivery_output | Out-File -FilePath $WorkstationQC_htmlfile -append
    
}

############################################
# Check to see if the Windows Firewall is configured properly

function FirewallCheck {
    # Do an initial query to see if it's Windows XP or Windows Vista/7
    $oscheck_query = gwmi Win32_OperatingSystem -computer localhost
    $osversion = $oscheck_query.Caption
    if ($osversion -match "Windows XP") 
        {
        $xp_fwcheck = get-service | where-object {$_.displayname -match "Windows Firewall"} | select status
                
        if($xp_fwcheck.status -match "Stopped") {
            $xp_fwcheck_output = "
            <tr>
                <td>XP Firewall Check</td>
                <td class=good>Windows Firewall service is stopped.</td>
                <td class=good>Correct</td>
            </tr>
            "
            }
        else {
            $fwstatus = $xp_fwcheck.status
            $xp_fwcheck_output = "
            <tr>
                <td>XP Firewall Check</td>
                <td class=bad>Windows Firewall service is <b>[$fwstatus]!</b></td>
                <td class=bad>Disable and stop the service.</td>
            </tr>
            "
            }

        # output the info
        $xp_fwcheck_output | out-file -filepath $WorkstationQC_htmlfile -append
        }
    else
        {
        # define and get the list of rules
        $fw = New-Object -ComObject HNetCfg.FwPolicy2
        # gets all current firewall rules.
        $rules = $fw.rules

        # The correct firewall rules to search for are...
        # All CORE NETWORKING, FILE AND PRINT SHARING, NETLOGON SERVICE
        # NETWORK DISCOVERY, REMOTE SERVICES (Admin, Desktop, Mgmt, etc)
        # FIREWALL REMOTE MGMT, WMI, Windows REMOTE Mgmt

        # All of the above must be set to TRUE for the .Enabled property.

        # Define all the groups to check for in followup loop.
        $subgroups = ("Core Networking", "File and Printer Sharing", "Netlogon Service", "Network Discovery", "Remote Administration", "Remote Assistance", "Remote Desktop", "Remote Service Management", "Windows Firewall Remote Management", "Windows Management Instrumentation (WMI)", "Windows Remote Management")

        # Define array for number of incorrectly set rules.
        $fw_data = @()

        foreach($item in $subgroups) {
            # queries the rules for 
            $query = $rules | Where-Object {$_.name -match $item} | select-object name, enabled
            # now, checks the filtered query for any that are false, then notates those in a separate variable if false
            $query | foreach-object {
                $output = "" | Select-Object RuleName, Status
                $output.RuleName = $_.Name
                $output.Status = $_.Enabled
                $ruleEnabled = $_.Enabled
        
                if($ruleEnabled -match "False") {
                    # append $fw_data with a row of incorrect rule
                    $fw_data += $output
                }       
            }
        }

        # check the amount of items in the set of rules.  If > 0 then output the list of rules in the HTML file.
        $failcount = $fw_data.count

        if($failcount -eq 0) {
            $fw_check_output = "
            <tr>
                <td>Windows 7 Firewall Check</td>
                <td class=good>The firewall has the proper set of rules enabled.</td>
                <td class=good>Correct</td>
            </tr>
            "  
            $fw_check_output | Out-File -FilePath $WorkstationQC_htmlfile -append
          
        } elseif($failcount -ge 1) {
            Foreach ($rgroup in $fw_data){
            $ruleName = $rgroup.rulename
            $fw_check_output = "
            <tr>
                <td>Windows 7 Firewall Check</td>
                <td class=bad>$rulename is not enabled.</td>
                <td class=bad>Please check the firewall settings.</td>
            </tr>
            "  
            $fw_check_output | Out-File -FilePath $WorkstationQC_htmlfile -append 
            } 
        }
    }
}

############################################
# Check to see if the current user is a local admin

function LocalAdminExport {

# Set currently logged in user to check for admin group membership
$currentdomain = gc env:userdomain
$currentuser = gc env:username
$loggedinuser = $currentdomain+"\"+$currentuser

# Begin output
$localadmin_output = "
<tr>
    <td>Local Administrator Check</td>
    <td class=good>
"    
# generate the list    
$localadmins = net localgroup Administrators

# strips away the banner text of the command starting with the line number of value $x
$x = 6
# strips away "This command completed successfully"
$end = ($localadmins.count - 2)


do {$localadmin_output += $localadmins[$x]+"<br />`n"; $x++}
until ($x -eq $end)

# this section is for the check on whether the user is in the local admin listing.
$localadmin_check = $localadmin_output | select-string -pattern $currentuser | select-object -expandproperty matches | select-object value

# final output.
if($localadmin_check.value -match $currentuser) {
$localadmin_output += "
</td>
<td class=good>User is a local admin.</td>
</tr>
"
} else {
$localadmin_output += "
</td>
<td class=bad>User is not a local admin.</td>
</tr>
"
}

$localadmin_output | Out-File -FilePath $WorkstationQC_htmlfile -append
}

#################################################################
# Mail the QC Report to 

function Mail_QCReport {
$final = Read-Host "Is everything on the report correct and you are ready to submit it?"
$ticket = ''
$ticketnumber = ''
$ticket_type = ''

    if ($final -match "y")
    {
        
        $tt_correct= $FALSE
        $tn_correct= $FALSE

        while ($tt_correct -eq $FALSE)
        {
            $ticket= (Read-Host "Input ticket TYPE - IN, PR, CO").ToUpper()
            if($ticket -match "IN") 
                {
                    $ticket_type = "IN"; $tt_correct = $TRUE
                }
            elseif($ticket -match "PR") 
                {
                    $ticket_type = "PR"; $tt_correct = $TRUE
                }
            elseif($ticket -match "CO") 
                {
                    $ticket_type = "CO"; $tt_correct = $TRUE
                }
            else 
                {
                    Write-Verbose "Unapproved ticket type.  Please try again."
                }
        }

        while ($tn_correct -eq $FALSE)
        {
            $ticketnumber = Read-Host "Input the ticket NUMBER"
            
            if(($ticket_type -match "IN") -or ($ticket_type -match "PR"))
            {
                # the length should only be 6 characters, all other fail
                if($ticketnumber.length -ne 6)
                {
                    Write-Verbose "An Incident or Problem ticket has 6 characters.  Please reinput the ticket number."
                }
                else
                {
                    $tn_correct = $TRUE  
                }     
            }
            elseif($ticket_type -match "CO")
            {
                # the length used to only be 5 characters, but we are now at 6
                if(($ticketnumber.length -le 4) -or ($ticketnumber.length -ge 7))
                {
                    Write-Verbose "A Change Order has 5 or 6 characters.  Please reinput the ticket number."
                }
                else
                {
                    $tn_correct = $TRUE
                }    
            }   
            
        }

        
        # append ticket number to the QC HTML file
        $ticket_output = "
            <hr>
                <h3 align=center>This build is referenced in ticket [$ticket_type $ticketnumber]</h3>
            "
        $ticket_output | Out-File -FilePath $WorkstationQC_htmlfile -append
        
        $biosquery = gwmi -class Win32_BIOS
        # assign values
        $bios_manu = $biosquery.Manufacturer
        $bios_name = $biosquery.Name
        $bios_sn = $biosquery.SerialNumber
        $bios_ver = $biosquery.Version

        # now with all the data, send it to the public folder with the HTM as an attachment.
        $from = "Workstation QC"
        $to = "Workstation_QC@email.com"
        $subj = "[$ticket_type"+"$ticketnumber] Build Quality Control"
        $body = "
            See the attached document for the output of the Quality Control script.
            Attach it to the ticket before closing.
            
            Ticket: $ticket_type $ticketnumber
            Machine Name: $machine_name
            Manufacturer: $bios_manu
            Serial Number: $bios_sn
            

            "
        $attachment = $WorkstationQC_htmlfile
        $smtpsvr = ""

        Send-MailMessage -from $from -to $to -subject $subj -body $body -smtpserver $smtpsvr -attachments $attachment -priority high

        netsh interface ip set address 'Local Area Connection' dhcp
        netsh interface ip set dns 'Local Area Connection' dhcp
        netsh interface ip set address 'Local Area Connection 2' dhcp
        netsh interface ip set dns 'Local Area Connection 2' dhcp
    }
        
}

############################################
# Check to see if folder redirection is enabled

function FolderRedirectionCheck {

    $network = (Get-Wmiobject Win32_NTDomain).DomainName
    $workgroup = $false

    foreach ($item in $network){
        if ($item.DomainName -eq "WORKGROUP"){
            $workgroup = $true
        }
    }
    

    if ($workgroup -ne $true){
        # get registry path
        $fr_path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        $fr = gp $fr_path
        $cu_path = $fr.personal

        # check path to see if it is local.
        if ($env:userdnsdomain -eq $null){
                $fr_output = "
            <tr>
                <td>Folder Redirection Check</td>
                <td class=good>The machine is on a workgroup called WORKGROUP</br></b></td>
                <td class=good>Correct</td>
            </tr>
            "
        }
        elseif($cu_path -match "C:") {
                $fr_output = "
            <tr>
                <td>Folder Redirection Check</td>
                <td class=bad>My Documents is pointing to:<br>$cu_path</br></b></td>
                <td class=bad>Verify folder redirection is enabled for customer.</td>
            </tr>
            " 
        } else {
            $fr_output = "
            <tr>
                <td>Folder Redirection Check</td>
                <td class=good>My Documents is pointing to:<b><br>$cu_path</br></b></td>
                <td class=good>Correct</td>
            </tr>
        "
        }
    }
    else {
        $fr_output = "
        <tr>
            <td>Folder Redirection Check</td>
            <td class=neutral>The computer is not on the domain</td>
            <td class=neutral>Nothing to do.</td>
        </tr>
        " 
    }
    $fr_output | Out-File -FilePath $WorkstationQC_htmlfile -append
}  

############################################
# Check to see if Webroot is installed and updated.

function WebrootCheck {
    #### set the target version ####
    $Webroot_target_version= "9.12.52"

    # query the version
    $Webrootquery = gwmi -class Win32_Product | where-object {$_.name -match "Webroot"}
    $Webroot_ver = $Webrootquery.version

    ### QUERY AV CLIENT ###
    if($Webrootquery -eq $NULL) {
        $Webroot_output = "
        <tr>
            <td>Webroot Check</td>
            <td class=bad>Webroot SecureAnywhere $Webroot_target_version is not installed!</td>
            <td class=bad>Please install Webroot SecureAnywhere $Webroot_target_version</td>
        </tr>
        "
    } else {
        if($Webrootquery.version -ne $Webroot_target_version){
            $Webroot_output = "
            <tr>
                <td>Webroot Check</td>
                <td class=nuetral>Webroot SecureAnywhere is version: $Webroot_ver.</td>
                <td class=nuetral>Please remove this version and install $Webroot_target_version</td>
            </tr>
            "
        } else {
            $Webroot_output = "
            <tr>
                <td>Webroot Check</td>
                <td class=good>Webroot SecureAnywhere is version: $Webroot_ver.</td>
                <td class=good>Correct</td>
            </tr>
            "
        }  
    }
    $Webroot_output | Out-File -FilePath $WorkstationQC_htmlfile -append
}

############################################
# Check the Bios Version

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

    $bios_output | Out-File -FilePath $WorkstationQC_htmlfile -append
}

#####################################################
#   Get the product key for Windows

function Get-MSWindowsProductKey {
    # create table to convert in base 24 
    $map="BCDFGHJKMPQRTVWXY2346789" 
    # Read registry Key 
    $osver = (get-itemproperty "HKLM:\\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
    $value = (get-itemproperty "HKLM:\\SOFTWARE\Microsoft\Windows NT\CurrentVersion").digitalproductid[0x34..0x42] 
    # Convert in Hexa to show you the Raw Key 
    $hexa = "" 
    $value | foreach { 
        $hexa = $_.ToString("X2") + $hexa 
    } 


    # find the Product Key 
    $ProductKey = "" 
    for ($i = 24; $i -ge 0; $i--) { 
        $r = 0 
        for ($j = 14; $j -ge 0; $j--) { 
            $r = ($r * 256) -bxor $value[$j] 
            $value[$j] = [math]::Floor([double]($r/24)) 
            $r = $r % 24 
        } 
        $ProductKey = $map[$r] + $ProductKey  
        if (($i % 5) -eq 0 -and $i -ne 0) { 
            $ProductKey = "-" + $ProductKey 
        } 
    } 
    #output

    $winkey_output = "`n<tr><td align=center>$osver</td>`n<td align=center>$productkey</td>`n</tr>"
    $winkey_output | Out-File -FilePath $WorkstationQC_htmlfile -append

}

############################################
# Get the Adobe Acrobat Key

function Get-AdobeAcrobatKey {
 
    $AdobeAcrobat = (Get-WmiObject Win32_product | where {$_.name -match "Adobe Acrobat" -and $_.name -notmatch "Reader"}).Caption

        if($AdobeAcrobat -eq $null) {
            } 
        else {
            $acrobatkey = Read-Host "What is the Adobe Acrobat Key on the OEM card?"
            $acrobat_output = "`n<tr><td align=center>$AdobeAcrobat</td>`n<td align=center>$acrobatkey</td>`n</tr>"
            }
        $acrobat_output | Out-File -FilePath $WorkstationQC_htmlfile -append
}

############################################
# Get the Microsoft Office Key

function Get-MSOfficeProductKey {
    $answer = Read-Host "If Office is installed on this computer please type in the full name of the version.  Ie..Microsoft Office 2013 ProPlus x64  If there is no office then please type the word NONE."
    if ($answer -ne "NONE" -and $answer -ne ""){
        $MSOfficekey = Read-Host "What is the key for that version of office."
        $MSOffice_output = "`n<tr><td align=center>$answer</td>`n<td align=center>$MSOfficekey</td>`n</tr>"
    } else {
        $MSOffice_output = "`n<tr><td align=center>$answer</td>`n<td align=center>$MSOfficekey</td>`n</tr>"
    }
    
    $MSOffice_output | Out-File -FilePath $WorkstationQC_htmlfile -append
}

#############################################
#  Get list of updates left

function Get-WindowsUpdates {
    Write-Verbose "Checking for available updates"
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    $availableupdates = $SearchResult.Updates
    $upd_count= $availableupdates.count
    Write-Verbose "There are $upd_count updates available"

    if($upd_count -ge 1) 
        {
        Write-Verbose "Update is available"
        $upd_count_output = "
            <tr>
                <td>Windows Update Status Check</td>
                <td class=bad>$upd_count updates are available!</td>
                <td class=bad>Please run Windows Updates!</td>
            </tr>
            "
        $upd_count_output | Out-File -FilePath $WorkstationQC_htmlfile -append
        } 
    elseif($upd_count -eq 0 -or $upd_count -eq $null) 
        {
        $upd_count_output = "
        <tr>
            <td>Windows Update Status Check</td>
            <td class=good>There are no updates available!</td>
            <td class=good>Correct</td>
        </tr>
        "
        $upd_count_output | Out-File -FilePath $WorkstationQC_htmlfile -append
        }
}

#############################################
#  Get the status of the NIC's power

function Get-NicPower { 
[CmdletBinding()]
        param ()
BEGIN {}
PROCESS {
        $namespace = "root\WMI"
        $status = ''
        $nic_name = ''
        Get-WmiObject Win32_NetworkAdapter -filter "AdapterTypeId=0" | where {$_.PhysicalAdapter -eq $true} |
             Foreach-Object {
                $strNetworkAdapterID=$_.PNPDeviceID.ToUpper()
                $nic_name=$_.Name
                Write-Verbose $nic_name
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
            if ($status -eq $true -and $nic_name -notmatch "Virtual")
                {
                $nicpower_output = "
                <tr>
                    <td>NIC Power Status Check</td>
                    <td class=bad>The power on $nic_name is still enabled!</td>
                    <td class=bad>Please turn off the NIC Power in device manager!</td>
                </tr>
                "
                }
            }

        
        if ($status -eq $FALSE)
            {
            $nicpower_output = "
            <tr>
                <td>NIC Power Status Check</td>
                <td class=good>The NIC power is disabled!</td>
                <td class=good>Correct</td>
            </tr>
            "
            }
            $nicpower_output | Out-File -FilePath $WorkstationQC_htmlfile -append
        }
END {}
}

#############################################
#  Check the power settings

function Get-Power {
$VerbosePreference = "Continue"

$type= Get-Chassis


Write-Verbose "Checking power settings"
#check default power plan
$powerplan= get-wmiobject -namespace "root\cimv2\power" -class Win32_powerplan  
[array]$recommended = $powerplan | Where-Object{$_.isactive -eq $true}
$pp_in_use= ($recommended | select -exp ElementName)
Write-verbose ("using $pp_in_use Power Plan")
$power_plan_in_use_output = "
    <tr>
        <td>Power Plan</td>
        <td class=neutral>Power Plan in use is $pp_in_use</td>
        <td class=neutral>$pp_in_use</td>
    </tr>
    "
$power_plan_in_use_output | Out-File -FilePath $WorkstationQC_htmlfile -append


if ($type -match "Laptop")
    {
        $array = ("Power button action","3","AC"),
            ("Power button action","3","DC"),
            ("Lid close action","1","AC"), 
            ("Lid close action","1","DC"),
            ("Turn off display after","1800","AC"),
            ("Turn off display after","1800","DC"),
            ("Turn off hard disk","0","AC"),
            ("Turn off hard disk","0","DC"),
            ("Hibernate after","0","AC"),
            ("Hibernate after","0","DC")
    }
else
    {
        $array = ("Power button action","3","AC"),
            ("Turn off display after","1800","AC"),
            ("Turn off hard disk","0","AC"),
            ("Hibernate after","0","AC")
    }


#check power settings
$powersettingindexes = get-wmiobject -namespace "root\cimv2\power" -class Win32_powersettingdataindex|where-object {$_.instanceid.contains($recommended[0].instanceid.split("\")[1])}
$powersettingindex= $null
$settings= $null
    foreach ($powersettingindex in $powersettingindexes)
        {
            $powersettings = get-wmiobject -namespace "root\cimv2\power" -class Win32_powersetting|where-object {$_.instanceid.contains($powersettingindex.instanceid.split("\")[3])}
            foreach ($powersetting in $powersettings)
                {
                    $name = $powersetting.ElementName
                    $value = $powersettingindex.settingindexvalue
                    $ac_or_dc = $powersettingindex.instanceid.split("\")[2]   
                    $output = @()
                    $output += "$name","$value","$ac_or_dc"
                    $settings += , $output
#                    Write-Verbose "$ac_or_dc $name is set to $value"
                                        
                }
    
        } 

$item = $null
$s_name = ""
$s_value = ""
$s_ac_or_dc = ""

$setting = $null
$element = ""
$elementvalue = ""
$element_ac_or_dc= ""

# pull out values from our list of defined settings in preparation for comparison
foreach ($item in $array)
    {
    $s_name = $item[0]
    $s_value = $item[1]
    $s_ac_or_dc = $item[2]
#    $Status = 'Correct'
#    write-verbose "setting: $s_ac_or_dc $s_name $s_value"

# pull out values from the existing power settings
    foreach ($setting in $settings)
        {
        $element = $setting[0]
        $elementvalue = $setting[1]
        $element_ac_or_dc= $setting[2]
        
        
        if (($element -match $s_name) -and ($element_ac_or_dc -match $s_ac_or_dc))
            {
 #           write-verbose "element: $element_ac_or_dc $element $elementvalue"
 #          write-verbose "hit!"
            
            if ($elementvalue -ne $s_value)
                {
#                write-verbose "ELEMENT HAS WRONG VALUE"
                $power_output = "
                    <tr>
                        <td>Windows Power Status Check</td>
                        <td class=bad>$s_ac_or_dc $s_name has $elementvalue , should be $s_value</td>
                        <td class=bad>Please check the power settings!</td>
                    </tr>
                    "
                }
            else
                {
#                write-verbose "element has correct value"
                $power_output = "
                    <tr>
                        <td>Windows Power Status Check</td>
                        <td class=good>$s_ac_or_dc $s_name is set correctly to $s_value!</td>
                        <td class=good>Correct</td>
                    </tr>
                    "
                }
            $power_output | Out-File -FilePath $WorkstationQC_htmlfile -append
            } 
            
        }
    }
}  

#############################################
#  Check to see if System Restore is enabled and has a restore point

function SystemRestoreCheck {
$points = Get-ComputerRestorePoint
$points_count = $points.count

if($points.count -ne "0") {
    $points_output = "
    <tr>
        <td>System Restore Check</td>
        <td class=good>System Restore is running and has $points_count restore points created.</td>
        <td class=good>Correct</td>
    </tr>
    "
} else {
    $points_output = "
    <tr>
        <td>System Restore Check</td>
        <td class=bad>System Restore is either not running or has no restore points..</td>
        <td class=good>Start system restore and ensure it works.</td>
    </tr>
    "
}

$points_output | out-file -filepath $WorkstationQC_htmlfile -append
}

#############################################
#  
Function Get-ClientWSUSSetting {
    <#  
    .SYNOPSIS  
        Retrieves the wsus client settings on a local or remove system.

    .DESCRIPTION
        Retrieves the wsus client settings on a local or remove system.
         
    .PARAMETER Computername
        Name of computer to connect to. Can be a collection of computers.

    .PARAMETER ShowEnvironment
        Display only the Environment settings.

    .PARAMETER ShowConfiguration
        Display only the Configuration settings.

    .NOTES  
        Name: Get-WSUSClient
        Author: Boe Prox
        DateCreated: 02DEC2011 
               
    .LINK  
        https://learn-powershell.net
        
    .EXAMPLE
    Get-ClientWSUSSetting -Computer TestServer
    
    RescheduleWaitTime            : NA
    AutoInstallMinorUpdates       : NA
    TargetGroupEnabled            : NA
    ScheduledInstallDay           : NA
    DetectionFrequencyEnabled     : 1
    WUServer                      : http://wsus.com
    Computername                  : TestServer
    RebootWarningTimeoutEnabled   : NA
    ElevateNonAdmins              : NA
    ScheduledInstallTime          : NA
    RebootRelaunchTimeout         : 10
    ScheduleInstallDay            : NA
    RescheduleWaitTimeEnabled     : NA
    DisableWindowsUpdateAccess    : NA
    AUOptions                     : 3
    DetectionFrequency            : 4
    RebootWarningTimeout          : NA
    ScheduleInstallTime           : NA
    WUStatusServer                : http://wsus.com
    TargetGroup                   : NA
    RebootRelaunchTimeoutEnabled  : 1
    UseWUServer                   : 1
    NoAutoRebootWithLoggedOnUsers : 1

    Description
    -----------
    Displays both Environment and Configuration settings for TestServer
    
    .EXAMPLE
    Get-ClientWSUSSetting -Computername Server1 -ShowEnvironment
    
    Computername               : Server1
    TargetGroupEnabled         : NA
    TargetGroup                : NA
    WUStatusServer             : http://wsus.com
    WUServer                   : http://wsus.com
    DisableWindowsUpdateAccess : 1
    ElevateNonAdmins           : 0
    
    Description
    -----------
    Displays the Environment settings for Server1
    
    .Example
    Get-ClientWSUSSetting -Computername Server1 -ShowConfiguration
    
    ScheduledInstallTime          : NA
    AutoInstallMinorUpdates       : 0
    ScheduledInstallDay           : NA
    Computername                  : Server1
    RebootWarningTimeoutEnabled   : NA
    RebootWarningTimeout          : NA
    NoAUAsDefaultShutdownOption   : NA
    RebootRelaunchTimeout         : NA
    DetectionFrequency            : 4
    ScheduleInstallDay            : NA
    RescheduleWaitTime            : NA
    RescheduleWaitTimeEnabled     : 0
    AUOptions                     : 3
    NoAutoRebootWithLoggedOnUsers : 1
    DetectionFrequencyEnabled     : 1
    ScheduleInstallTime           : NA
    NoAUShutdownOption            : NA
    RebootRelaunchTimeoutEnabled  : NA
    UseWUServer                   : 1
    IncludeRecommendedUpdates     : NA  
    
    Description
    -----------
    Displays the Configuration settings for Server1
    #>
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeLine = $True)]
        [string[]]$Computername = $Env:Computername,
        [parameter()]
        [switch]$ShowEnvironment,
        [parameter()]
        [switch]$ShowConfiguration        
    )
    Begin {
        $EnvKeys = "WUServer","WUStatusServer","ElevateNonAdmins","TargetGroupEnabled","TargetGroup","DisableWindowsUpdateAccess"
        $ConfigKeys = "AUOptions","AutoInstallMinorUpdates","DetectionFrequency","DetectionFrequencyEnabled","NoAutoRebootWithLoggedOnUsers",
        "NoAutoUpdate","RebootRelaunchTimeout","RebootRelaunchTimeoutEnabled","RebootWarningTimeout","RebootWarningTimeoutEnabled","RescheduleWaitTime","RescheduleWaitTimeEnabled",
        "ScheduleInstallDay","ScheduleInstallTime","UseWUServer"
    }
    Process {
        $PSBoundParameters.GetEnumerator() | ForEach {
#            Write-Verbose ("{0}" -f $_)
        }
        ForEach ($Computer in $Computername) {
                If (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
                $WSUSEnvhash = @{}
                $WSUSConfigHash = @{}
                $ServerReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$Computer)
                #Get WSUS Client Environment Options
<#MLT EDIT#>    if (!(test-path "HKLM:Software\Policies\Microsoft\Windows\WindowsUpdate"))
<#MLT EDIT#>    {
<#MLT EDIT#>        $WSUSEnv = New-Item -path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\
<#MLT EDIT#>    }
<#MLT EDIT#>    else
<#MLT EDIT#>    {
                    $WSUSEnv = $ServerReg.OpenSubKey('Software\Policies\Microsoft\Windows\WindowsUpdate')
<#MLT EDIT#>    }
                $subkeys = @($WSUSEnv.GetValueNames())
                $NoData = @(Compare-Object -ReferenceObject $EnvKeys -DifferenceObject $subkeys | Select -ExpandProperty InputObject)
                ForEach ($item in $NoData) {
                    $WSUSEnvhash[$item] = 'NA'
                }
                $Data = @(Compare-Object -ReferenceObject $EnvKeys -DifferenceObject $subkeys -IncludeEqual -ExcludeDifferent | Select -ExpandProperty InputObject)
                ForEach ($key in $Data) {
                    If ($key -eq 'WUServer') {
                        $WSUSEnvhash['WUServer'] = $WSUSEnv.GetValue('WUServer')
                    }
                    If ($key -eq 'WUStatusServer') {
                        $WSUSEnvhash['WUStatusServer'] = $WSUSEnv.GetValue('WUStatusServer')
                    }
                    If ($key -eq 'ElevateNonAdmins') {
                        $WSUSEnvhash['ElevateNonAdmins'] = $WSUSEnv.GetValue('ElevateNonAdmins')
                    }
                    If ($key -eq 'TargetGroupEnabled') {
                        $WSUSEnvhash['TargetGroupEnabled'] = $WSUSEnv.GetValue('TargetGroupEnabled')
                    }
                    If ($key -eq 'TargetGroup') {
                        $WSUSEnvhash['TargetGroup'] = $WSUSEnv.GetValue('TargetGroup')
                    }  
                    If ($key -eq 'DisableWindowsUpdateAccess') {
                        $WSUSEnvhash['DisableWindowsUpdateAccess'] = $WSUSEnv.GetValue('DisableWindowsUpdateAccess')
                    }              
                }
                #Get WSUS Client Configuration Options
<#MLT EDIT#>    if (!(test-path "HKLM:Software\Policies\Microsoft\Windows\WindowsUpdate\AU"))
<#MLT EDIT#>    {
<#MLT EDIT#>        $WSUSConfig = New-Item -path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU
<#MLT EDIT#>    }
<#MLT EDIT#>    else
<#MLT EDIT#>    {
                    $WSUSConfig = $ServerReg.OpenSubKey('Software\Policies\Microsoft\Windows\WindowsUpdate\AU')    
<#MLT EDIT#>    }
                    $subkeys = @($WSUSConfig.GetValueNames())
                    $NoData = @(Compare-Object -ReferenceObject $ConfigKeys -DifferenceObject $subkeys | Select -ExpandProperty InputObject)
                ForEach ($item in $NoData) {
                    $WSUSConfighash[$item] = 'NA'
                }            
                $Data = @(Compare-Object -ReferenceObject $ConfigKeys -DifferenceObject $subkeys -IncludeEqual -ExcludeDifferent | Select -ExpandProperty InputObject)
                ForEach ($key in $Data) {
                    If ($key -eq 'AUOptions') {
                        $WSUSConfighash['AUOptions'] = $WSUSConfig.GetValue('AUOptions')
                    }
                    If ($key -eq 'AutoInstallMinorUpdates') {
                        $WSUSConfighash['AutoInstallMinorUpdates'] = $WSUSConfig.GetValue('AutoInstallMinorUpdates')
                    }
                    If ($key -eq 'DetectionFrequency') {
                        $WSUSConfighash['DetectionFrequency'] = $WSUSConfig.GetValue('DetectionFrequency')
                    }
                    If ($key -eq 'DetectionFrequencyEnabled') {
                        $WSUSConfighash['DetectionFrequencyEnabled'] = $WSUSConfig.GetValue('DetectionFrequencyEnabled')
                    }
                    If ($key -eq 'NoAutoRebootWithLoggedOnUsers') {
                        $WSUSConfighash['NoAutoRebootWithLoggedOnUsers'] = $WSUSConfig.GetValue('NoAutoRebootWithLoggedOnUsers')
                    }
                    If ($key -eq 'RebootRelaunchTimeout') {
                        $WSUSConfighash['RebootRelaunchTimeout'] = $WSUSConfig.GetValue('RebootRelaunchTimeout')
                    }
                    If ($key -eq 'RebootRelaunchTimeoutEnabled') {
                        $WSUSConfighash['RebootRelaunchTimeoutEnabled'] = $WSUSConfig.GetValue('RebootRelaunchTimeoutEnabled')
                    }
                    If ($key -eq 'RebootWarningTimeout') {
                        $WSUSConfighash['RebootWarningTimeout'] = $WSUSConfig.GetValue('RebootWarningTimeout')
                    }
                    If ($key -eq 'RebootWarningTimeoutEnabled') {
                        $WSUSConfighash['RebootWarningTimeoutEnabled'] = $WSUSConfig.GetValue('RebootWarningTimeoutEnabled')
                    }
                    If ($key -eq 'RescheduleWaitTime') {
                        $WSUSConfighash['RescheduleWaitTime'] = $WSUSConfig.GetValue('RescheduleWaitTime')
                    }                                                                                                            
                    If ($key -eq 'RescheduleWaitTimeEnabled') {
                        $WSUSConfighash['RescheduleWaitTimeEnabled'] = $WSUSConfig.GetValue('RescheduleWaitTimeEnabled')
                    }  
                    If ($key -eq 'ScheduleInstallDay') {
                        $WSUSConfighash['ScheduleInstallDay'] = $WSUSConfig.GetValue('ScheduleInstallDay')
                    }  
                    If ($key -eq 'ScheduleInstallTime') {
                        $WSUSConfighash['ScheduleInstallTime'] = $WSUSConfig.GetValue('ScheduleInstallTime')
                    }  
                    If ($key -eq 'UseWUServer') {
                        $WSUSConfighash['UseWUServer'] = $WSUSConfig.GetValue('UseWUServer')
                    }                                          
                }
                
                #Display Output
                If ((-Not ($PSBoundParameters['ShowEnvironment'] -OR $PSBoundParameters['ShowConfiguration'])) -OR `
                ($PSBoundParameters['ShowEnvironment'] -AND $PSBoundParameters['ShowConfiguration'])) {
                    #Write-Verbose "Displaying everything"
                    $WSUSHash = ($WSUSEnvHash + $WSUSConfigHash)
                    $WSUSHash['Computername'] = $Computer
                    New-Object PSObject -Property $WSUSHash
                } Else {
                    If ($PSBoundParameters['ShowEnvironment']) {
                        #Write-Verbose "Displaying environment settings"
                        $WSUSEnvHash['Computername'] = $Computer
                        New-Object PSObject -Property $WSUSEnvhash
                    }
                    If ($PSBoundParameters['ShowConfiguration']) {
                        #Write-Verbose "Displaying Configuration settings"
                        $WSUSConfigHash['Computername'] = $Computer
                        New-Object PSObject -Property $WSUSConfigHash
                    }
                }
            } Else {
             #   Write-Warning ("{0}: Unable to connect!" -f $Computer)
            }
        }
    }
}

#############################################
#  
Function Get-CurrentWSUSSetting {
    
    #### set anti-target wsus server ###
    $br_wsus_server= "http://192.168.40.102"
    
    
    $current_wsus_settings= Get-ClientWSUSSetting -ShowEnvironment
    
    if ($current_wsus_settings.WUServer -eq $br_wsus_server)
    {
        $wsus_output= "
            <tr>
                <td>WSUS Server Setting</td>
                <td class=bad>WSUS is pointed to $br_wsus_server</td>
                <td class=bad>Remove Build Room WSUS server!</td>
            </tr>    "    
    }
    elseif ($current_wsus_settings.WUServer -eq "NA")
    {
        $wsus_output= "
            <tr>
                <td>WSUS Server Setting</td>
                <td class=good>No WSUS server defined</td>
                <td class=good>Updates coming from the internet</td>
            </tr> "
    }
    else
    {
        $wsus_output= "
            <tr>
                <td>WSUS Server Setting</td>
                <td class=neutral>Can't read WSUS settings</td>
                <td class=neutral>Reset WSUS & reboot</td>
            </tr> "
    }
    

    
    
    $wsus_output | out-file -filepath $WorkstationQC_htmlfile -append
}

#############################################
#  Client Settings

function ClientSoftware {
    $client = ($env:computername).split("-")[0]
    $serial = (Get-WmiObject win32_bios).serialnumber
    $domain = gc env:userdomain
    if($client -eq "ASC")
        {
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


Write-Verbose (("Checking Computer Info at ") + (get-date))
ComputerInfo

Write-Verbose (("Checking Operating System Location at ") + (get-date))
OSLocationCheck

Write-Verbose (("Checking Operating System and Office Activation at ") + (get-date))
Get-ActivationStatus

Write-Verbose (("Checking Device status at ") + (get-date))
DeviceCheck

Write-Verbose (("Checking Standard VGA adapter status at ") + (get-date))
StandardVGACheck

Write-Verbose (("Checking for unwanted software at ") + (get-date))
UninstallCheck

Write-Verbose (("Checking Labtech's status at ") + (get-date))
LabTechCheck

Write-Verbose (("Checking Webroot at ") + (get-date))
WebrootCheck

Write-Verbose (("Checking for Windows Updates at ") + (get-date))
Get-WindowsUpdates

Write-Verbose (("Checking Adobe Reader Version at ") + (get-date))
AdobeReaderCheck

Write-Verbose (("Checking Java Version at ") + (get-date))
JavaCheck

Write-Verbose (("Checking System Restore at ") + (get-date))
SystemRestoreCheck

Write-Verbose (("Checking NIC power status status at ") + (get-date))
Get-NicPower

Write-Verbose (("Checking Windows power status status at ") + (get-date))
Get-Power

Write-Verbose (("Checking Local Admins group at ") + (get-date))
LocalAdminExport

Write-Verbose (("Checking Folder Redirection settings at ") + (get-date))
FolderRedirectionCheck

###############################

Write-Verbose (("Adding License Key section at ") + (get-date)) 
LicenseKeySection

Write-Verbose (("Getting the Office Product Key at ") + (get-date))
Get-MSOfficeProductKey

Write-Verbose (("Getting the Adobe Acrobat Product Key at ") + (get-date))
Get-AdobeAcrobatKey

###############################

Write-Verbose (("Adding Client section at ") + (get-date)) 
ClientSection

Write-Verbose (("Checking for Client Software and Settings ") + (get-date)) 
ClientSoftware

###############################

Write-Verbose (("Showing the output html at ") + (get-date))
Invoke-Item $WorkstationQC_htmlfile







