#############################################################################
#
#    Script to set Power Profile settings
#    Created by Carlos McCray
#    Last Updated on 2/27/12
#
#
#############################################################################



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
powercfg.exe -change -monitor-timeout-dc 15
powercfg.exe -change -standby-timeout-ac 0
powercfg.exe -change -standby-timeout-dc 0
powercfg.exe -change -disk-timeout-ac 0 
powercfg.exe -change -disk-timeout-dc 0 
powercfg.exe -change -hibernate-timeout-ac 0
powercfg.exe -change -hibernate-timeout-dc 0
powercfg.exe -h off