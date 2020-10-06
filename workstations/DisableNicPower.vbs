'********************************************************************************
'Script:To uncheck 'Allow the computer to turn off this device to save power
'This Requires a restart
'Ver :1.0 
'********************************************************************************
on error resume next
Const HKEY_LOCAL_MACHINE = &H80000002
strComputer = "."
Dim objReg, objRegSub, WshShell
Dim strKeyPath
Set objReg    = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\default:StdRegProv")
Set objRegSub = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\default:StdRegProv")
Set WshShell = WScript.CreateObject("Wscript.Shell")
' List all subkeys
objReg.EnumKey HKEY_LOCAL_MACHINE, "SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}", subKeys
' Loop through the list of subkeys
For Each subKey In subKeys
strKeyPath ="SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\" & subKey        
  'List values of a key        
objRegSub.EnumValues HKEY_LOCAL_MACHINE,strKeyPath,arrEntryNames         
  'Loop through values of subkey
For Each entry in arrEntryNames
if entry="DriverDesc" then  
 DriverDescription=WshShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\" & subKey & "\" & entry) 
 if Instr(ucase(DriverDescription),"WIFI")>0 or Instr(ucase(DriverDescription),"WIRELESS")>0 then
 WshShell.regwrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\" & subKey & "\PnPCapabilities", 56, "REG_DWORD"
 end if
end if
Next    
Next
set objRegSub = Nothing
Set objReg = Nothing 
Set WshShell = Nothing

