 
function Get-Power {
    $VerbosePreference = "Continue"
    Write-Verbose "Checking power settings"
    #check default power plan
    $powerplan=get-wmiobject -namespace "root\cimv2\power" -class Win32_powerplan  
    [array]$recommended = $powerplan | Where-Object{$_.isactive -eq $true}

    #check power settings
    $powersettingindexes=get-wmiobject -namespace "root\cimv2\power" -class Win32_powersettingdataindex | 
        where-object {$_.instanceid.contains($recommended[0].instanceid.split("\")[1])}
    foreach ($powersettingindex in $powersettingindexes){
        $powersettings=get-wmiobject -namespace "root\cimv2\power" -class Win32_powersetting | 
            where-object {$_.instanceid.contains($powersettingindex.instanceid.split("\")[3])}
        foreach ($powersetting in $powersettings){
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
    foreach ($item in $array){
        $name = $item[0]
        $value = $item[1]
        $Status = $true
        foreach ($setting in $settings){
            $element = $setting[0]
            $elementvalue = $setting[1]
            if ($element -match $name -and $elementvalue -ne $value){
                $Status = $false
            }
        }
        Write-Verbose "$name is $status"
        if ($status -eq $false){
            $exit = $false
        }
    }
    Return $exit
}  
 
##############################################################################
        
function Set-Power { 
    Write-Verbose "Set Power Settings"
    if($operatingSystem -ne "Microsoft Windows XP Professional"){
        #Get the Active Plan GUID into a variable
        $ActivePlan = Get-WmiObject -Class win32_powerplan -Namespace root\cimv2\power -Filter "isActive='true'"
        $ActivePlanGUID = $ActivePlan.InstanceID.Split("{,}")[1]

        #Place output of power
        $powercfg = powercfg.exe -q

        #Get the Power Buttons and Lids GUID into a varible
        foreach($item in $powercfg){
            if($item -match "Power buttons and lid"){
                $SubGroupGUID = $item.Split(" ")[4]
            }
        }

        #Get the PowerButtonAction GUID into a variable
        foreach($item in $powercfg){
            if($item -match "Power button act"){
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
    } else {
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

##############################################################################

$pwrresult = Get-Power
if ($pwrresult -eq $false){
    Set-Power
} else {

}










