
Function RemoveWSUS {

$VerbosePreference = 'continue'
Write-Verbose "Stopping Windows Update service"
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

Write-Verbose "Starting Windows Update service"
Start-Service wuauserv

}

RemoveWSUS

