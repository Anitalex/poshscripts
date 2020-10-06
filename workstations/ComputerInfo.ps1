Function Get-CompInfo {
      <#
      .SYNOPSIS
      Gets information on the computer
      .DESCRIPTION
      Gets standard information on the computer and creates an .Net object that contains the output
      .EXAMPLE
      Get-Info
      .EXAMPLE
      Once the function is ran you can find the object of $compinfo
      .PARAMETER computername
      There are no parameters
      .PARAMETER logname
      There are no parameters
      #>
    [CmdletBinding(SupportsShouldProcess=$True)]
    param()
    BEGIN {}
    PROCESS { 
            $VerbosePreference = "Continue"
            $sysroot = gc env:systemroot
            $machine_name = gc env:computername
            $OperatingSystem = (get-wmiobject win32_operatingsystem).caption
            $OSArchitecture = (get-wmiobject win32_operatingsystem).OSArchitecture
            $manufacturer = (get-wmiobject win32_computersystem).manufacturer
            $model = (get-wmiobject win32_computersystem).model
            $serial = (get-wmiobject win32_bios).serialnumber 

            #########################################
            #  Express Service Code
            if ($manufacturer -match "Dell")
            {
            $Base = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            $Length = $Serial.Length
            For ($CurrentChar = $Length; $CurrentChar -ge 0; $CurrentChar--) 
                {
                $ExpressServiceCode = $Out + [int64](([Math]::Pow(36, ($CurrentChar - 1)))*($Base.IndexOf($serial[($Length - $CurrentChar)])))
                }
            }
            else
            {
            $ExpressServiceCode = "Computer is not a Dell"
            }

            #########################################
            #  Determine if it is a Laptop or Desktop

            $isLaptop = $false
            if(Get-WmiObject -Class win32_systemenclosure |
                    Where-Object { $_.chassistypes -eq 9 -or $_.chassistypes -eq 10 -or $_.chassistypes -eq 14})
                { 
                $isLaptop = $true 
                }

            if(Get-WmiObject -Class win32_battery)
                { 
                $isLaptop = $true 
                }

            if ($isLaptop)
                {
                $chassis = "Laptop"
                }
            else
                {
                $chassis = "Desktop"
                }

            #########################################
            #  Get Firewall and Device Status

            if ($OperatingSystem -match "Windows XP") 
                {
                #########################################
                #  XP Firewall Status

                $xp_fwcheck = get-service | where-object {$_.displayname -match "Windows Firewall"} | select status
                
                if ($xp_fwcheck.status)
                {
                $firewallStatus = "Enabled"
                }
                else
                {
                $firewallStatus = "Disabled"
                }
        
                #########################################
                #  XP Device Status

                $hw_check = gwmi -class Win32_PnPEntity | Where-Object {$_.status -match "Error"}
                $devicecount = ($hw_check.count)
                $DeviceStatus = "$devicecount devices need drivers"

                }
            else
                {
                #########################################
                #  Windows 7 Firewall Status

                $fw = New-Object -ComObject HNetCfg.FwPolicy2
                # gets all current firewall rules.
                $rules = $fw.rules
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
                        # All of the above must be set to TRUE for the .Enabled property.
                        if($ruleEnabled -match "False") {
                            # append $fw_data with a row of incorrect rule
                            $fw_data += $output
                        }       
                    }
                }

                # check the amount of items in the set of rules.  If > 0 then output the list of rules in the HTML file.
                $failcount = $fw_data.count
                if ($failcount -eq 0) 
                    {
                    $firewallStatus = "Correct"
                    }
                else
                    {
                    $firewallStatus = "Missing $failcount rules"
                    }
        
                #########################################
                #  Windows 7 Device Status

                $hw_check = gwmi -class Win32_PnPEntity | Where-Object {$_.ConfigManagerErrorCode -ne 0}
                $devicecount = ($hw_check.count)
                $DeviceStatus = "$devicecount devices need drivers"

                #########################################
                #  Get UAC Status

                $uac = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                $uacquery = Get-ItemProperty -path $uac -name EnableLUA
                $uacval = $uacquery.EnableLUA
                $uacstatus = ($uacval -eq 1)
            
                }

            #########################################
            #  Return Computer Info Object

            $compinfo = NEW-OBJECT PSOBJECT -property @{SystemRoot='';CompName='';OperatingSystem='';OSArchitecture='';Manufacturer='';Model='';Serial='';ExpressServiceCode='';DeviceStatus='';FirewallStatus='';UACStatus='';Chassis=''} 
      
            $compinfo.SystemRoot = $sysroot
            $compinfo.CompName = $machine_name
            $compinfo.OperatingSystem = $OperatingSystem
            $compinfo.OSArchitecture = $OSArchitecture
            $compinfo.Manufacturer = $manufacturer
            $compinfo.Model = $model
            $compinfo.Serial = $serial
            $compinfo.ExpressServiceCode = $ExpressServiceCode
            $compinfo.DeviceStatus = $DeviceStatus
            $compinfo.FirewallStatus = $firewallStatus
            $compinfo.uacstatus = $uacstatus
            $compinfo.chassis = $chassis

            Return $compinfo
            }
    END {}
}


$a = Get-CompInfo
