strComputer = "."
Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
Set colItems = objWMIService.ExecQuery("Select * from Win32_BIOS",,48)
For Each objItem in colItems
strSerial = objItem.SerialNumber
Next

Function Base2Base(InputNumber,InputBase,OutputBase)
Dim J, K, DecimalValue, X, MaxBase, InputNumberLength
Dim NumericBaseData, OutputValue
NumericBaseData = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MaxBase = Len(NumericBaseData)
if (InputBase > MaxBase) OR (OutputBase > MaxBase) then
Base2Base = "N/A"
Exit Function
end if
'Convert InputNumber to Base 10
InputNumberLength = Len(InputNumber)
DecimalValue = 0
for J = 1 to InputNumberLength
for K = 1 to InputBase
if mid(InputNumber, J, 1) = mid(NumericBaseData, K, 1) then
DecimalValue = DecimalValue+int((K-1)*(InputBase^(InputNumberLength-J))+.5)
end if
next
next
'Convert the Base 10 value (DecimalValue) to the desired output base
OutputValue = ""
while DecimalValue > 0
X = int(((DecimalValue/OutputBase)-int(DecimalValue/OutputBase))*OutputBase+1.5)
OutputValue = mid(NumericBaseData, X, 1)+OutputValue
DecimalValue = int(DecimalValue/OutputBase)
Wend
Base2Base = OutputValue
Exit Function
End Function

'Get Make and Model of machine


SystemName = "localhost"

set tmpObj = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & SystemName & "\root\cimv2").InstancesOf ("Win32_ComputerSystem")
for each tmpItem in tmpObj
  MakeModel = trim(tmpItem.Manufacturer) & " " & trim(tmpItem.Model)
next
Set tmpObj = Nothing: Set tmpItem = Nothing


'Get system drive

    Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_LogicalDisk",,48) 
    set fsoObject = WScript.CreateObject("Scripting.FileSystemObject")
    set sysDrv = fsoObject.GetDrive(fsoObject.GetDriveName("c:"))

'Check activation

'Dim objShell
'Set objShell = WScript.CreateObject ("WScript.shell")
'objShell.run "cmd /K CD C:\ & cscript c:\windows\system32\slmgr.vbs /dli & echo %PROCESSOR_ARCHITECTURE%"
'Set objShell = Nothing

'Get computer name

Function GetComputerName()
        On Error Resume Next
        Set OpSysSet = GetObject("winmgmts:\root\cimv2").ExecQuery("select * from Win32_ComputerSystem")
        For each i in OpSysSet
        ' There should only be one anyway, but we'll do this to be sure to be sure.
                GetComputerName = i.Name
        Next
End Function

'Display results

Wscript.Echo "MakeModel:    " & MakeModel & vbNewLine _
& vbNewLine _
 & "Service Tag:     " & strSerial & vbNewLine _
& vbNewLine _
& "ESC:       " & Base2Base(strSerial, 36, 10) & vbNewLine _
& vbNewLine _
 & sysDrv & vbNewLine _
& vbNewLine _
& GetComputerName



