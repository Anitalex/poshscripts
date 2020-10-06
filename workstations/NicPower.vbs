Option Explicit

Const HKEY_LOCAL_MACHINE = &H80000002

Dim objReg
Dim strComputer, strKeyPath, arrSubKeys, arrValueTypes, arrValueNames
Dim subkey, i

on error resume next

'Prompt for computer name
'Comment out this line and use strComputer = "." to skip prompting and run the script
'against the local computer only
'strComputer = InputBox("Computer Name or IP Address")
strComputer = "."

'Connect to registry provider
Set objReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\default:StdRegProv")

'Set strKeyPath to the USB controller GUID
strKeyPath = "SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}"

'Build an array of the USB controllers
objReg.EnumKey HKEY_LOCAL_MACHINE, strKeyPath, arrSubKeys

'Loop through each USB controller looking for the HCDISABLESELECTIVESUSPEND entry and setting it to 1 if it exists
For Each subkey In arrSubKeys
        'wscript.echo subkey
        objReg.EnumValues HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey, arrValueNames, arrValueTypes
        for i=0 to ubound(arrValuenames)
         'wscript.echo "Value name: " & arrValueNames(i)
         if arrValueNames(i) = "HcDisableSelectiveSuspend" then
                objReg.SetDWORDValue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey, "HcDisableSelectiveSuspend", 1
         end if
        next
Next

'Set strKeyPath to the network adapter GUID
strKeyPath = "SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}"

'Build an array of the network adapters
objReg.EnumKey HKEY_LOCAL_MACHINE, strKeyPath, arrSubKeys

'Loop through each network adapter looking for the PNPCAPABILITIES entry and setting it to demical value 56
For Each subkey In arrSubKeys
        'wscript.echo subkey
        objReg.EnumValues HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey, arrValueNames, arrValueTypes
        for i=0 to ubound(arrValuenames)
                'wscript.echo "Value Name: " & arrValueNames(i)
                if arrValueNames(i) = "PnPCapabilities" then
                        objReg.SetDWORDValue HKEY_LOCAL_MACHINE, strKeyPath & "\" & subkey, "PnPCapabilities", 56
                End If
        next
Next

Set objReg = nothing