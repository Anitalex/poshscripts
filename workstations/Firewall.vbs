option explicit

Dim CurrentProfiles
Dim LowerBound
Dim UpperBound
Dim iterate
Dim excludedinterfacesarray

' Profile Type
'Const NET_FW_PROFILE2_DOMAIN = 1
Const NET_FW_PROFILE2_PRIVATE = 2
Const NET_FW_PROFILE2_PUBLIC = 4
Const CurrentProfile=1

' Action
Const NET_FW_ACTION_BLOCK = 0
Const NET_FW_ACTION_ALLOW = 1

' Create the FwPolicy2 object.

Dim fwPolicy2

Set fwPolicy2 = CreateObject("HNetCfg.FwPolicy2")

 

' Get the Rules object

Dim RulesObject

Set RulesObject = fwPolicy2.Rules

 

'Create a profile object

'Dim CurrentProfile

'CurrentProfile = fwPolicy2.CurrentProfileTypes

 

'Check whether windows management instrumentation (wmi) is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "windows management instrumentation (wmi)") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "windows management instrumentation (wmi)", TRUE


end if

'Check whether windows management instrumentation (wmi) is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "windows management instrumentation (wmi)") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "windows management instrumentation (wmi)", TRUE
end if 

'Check whether windows management instrumentation (wmi) is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PUBLIC, "windows management instrumentation (wmi)") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PUBLIC, "windows management instrumentation (wmi)", TRUE
end if 

'Check whether File and Printer Sharing is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "File and Printer Sharing") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "File and Printer Sharing", TRUE

end if

'Check whether File and Printer Sharing is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "File and Printer Sharing") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "File and Printer Sharing", TRUE
end if 

'Check whether File and Printer Sharing is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PUBLIC, "File and Printer Sharing") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PUBLIC, "File and Printer Sharing", TRUE
end if 

'Check whether Netlogon Service is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "Netlogon Service") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "Netlogon Service", TRUE

end if

'Check whether Netlogon Service is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "Netlogon Service") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "Netlogon Service", TRUE
end if 

'Check whether Netlogon Service is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PUBLIC, "Netlogon Service") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PUBLIC, "Netlogon Service", TRUE 
end if


'Check whether Network Discovery is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "Network Discovery") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "Network Discovery", TRUE

end if

'Check whether Network Discovery is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "Network Discovery") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "Network Discovery", TRUE
end if 

'Check whether Network Discovery is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PUBLIC, "Network Discovery") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PUBLIC, "Network Discovery", TRUE
end if

'Check whether windows firewall remote management is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "windows firewall remote management") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "windows firewall remote management", TRUE

end if

'Check whether windows firewall remote management is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "windows firewall remote management") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "windows firewall remote management", TRUE
end if 

'Check whether windows firewall remote management is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PUBLIC, "windows firewall remote management") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PUBLIC, "windows firewall remote management", TRUE
end if 


'Check whether windows remote management is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "windows remote management") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "windows remote management", TRUE

end if

'Check whether windows remote management is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "windows remote management") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "windows remote management", TRUE
end if 

'Check whether windows remote management is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PUBLIC, "windows remote management") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PUBLIC, "windows remote management", TRUE
end if 


'Check whether core networking is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "Core Networking") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "core networking", TRUE

end if

'Check whether Core Networking is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "Core Networking") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "Core Networking", TRUE
end if 

'Check whether Core Networking is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PUBLIC, "Core Networking") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PUBLIC, "Core Networking", TRUE
end if

'Check whether Remote assistance is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "Remote assistance") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "Remote assistance", TRUE

end if

'Check whether Remote assistance is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "Remote assistance") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "Remote assistance", TRUE
end if 

'Check whether Remote assistance is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PUBLIC, "Remote assistance") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PUBLIC, "Remote assistance", TRUE 
end if


'Check whether Remote desktop is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "Remote desktop") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "Remote desktop", TRUE

end if

'Check whether Remote desktop is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "Remote desktop") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "Remote desktop", TRUE
end if 

'Check whether Remote desktop is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PUBLIC, "Remote desktop") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PUBLIC, "Remote desktop", TRUE
end if

'Check whether Remote event log management is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "Remote event log management") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "Remote event log management", TRUE

end if

'Check whether Remote event log management is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "Remote event log management") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "Remote event log management", TRUE
end if 

'Check whether Remote event log management is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PUBLIC, "Remote event log management") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PUBLIC, "Remote event log management", TRUE
end if

'Check whether Remote scheduled tasks management is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "Remote scheduled tasks management") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "Remote scheduled tasks management", TRUE

end if

'Check whether Remote scheduled tasks management is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "Remote scheduled tasks management") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "Remote scheduled tasks management", TRUE
end if 

'Check whether Remote scheduled tasks management is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PUBLIC, "Remote scheduled tasks management") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PUBLIC, "Remote scheduled tasks management", TRUE 
end if

'Check whether Remote service management is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "Remote service management") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "Remote service management", TRUE

end if

'Check whether Remote service management is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "Remote service management") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "Remote service management", TRUE
end if 

'Check whether Remote service management is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PUBLIC, "Remote service management") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PUBLIC, "Remote service management", TRUE 
end if


'Check whether Remote volume management is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "Remote volume management") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "Remote volume management", TRUE

end if

'Check whether Remote volume management is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "Remote volume management") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "Remote volume management", TRUE
end if 

'Check whether Remote volume management is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_Public, "Remote volume management") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_Public, "Remote volume management", TRUE
end if

'Check whether Remote Administration is on, and turn it on if not

if fwPolicy2.IsRuleGroupEnabled(CurrentProfile, "Remote Administration") <> TRUE then

    fwPolicy2.EnableRuleGroup CurrentProfile, "Remote Administration", TRUE

end if

'Check whether Remote Administration is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_PRIVATE, "Remote Administration") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_PRIVATE, "Remote Administration", TRUE
end if 

'Check whether Remote Administration is on, and turn it on if not
if fwPolicy2.IsRuleGroupEnabled(NET_FW_PROFILE2_Public, "Remote Administration") <> TRUE then
    fwPolicy2.EnableRuleGroup NET_FW_PROFILE2_Public, "Remote Administration", TRUE
end if