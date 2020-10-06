'Option Explicit


'**********Map Drive to Customer Data**********************

Dim objNetwork
strLocalDrive = "U:"
strRemoteShare = "\\192.168.30.203\CustomerData"
strPer = "FALSE"
strUsr = "br\tech"
strPas = "Lfs123!"
Set objFSO = CreateObject("Scripting.FileSystemObject") 
Set objNetwork = CreateObject("Wscript.Network") 

If (objFSO.DriveExists("U:") = True) Then 
    objNetwork.RemoveNetworkDrive "U:", True, True 
End If 


objNetwork.MapNetworkDrive strLocalDrive, strRemoteShare, strPer, strUsr, strPas


'****************Copy USMT Local*******************************

objSourceFolder = "U:\USMT_XP" 
objDestinationFolder = "C:\" 
  
ObjFSO.CopyFolder (objSourceFolder), (objDestinationFolder), True 


'****************Ask for folder name**************************

Dim Message, Result
Dim Title, Text1
Message = "Please the folder name" & vbCr
Title = "Migrating User"
Text1 = "User Input Cancelled"


'*** Get User Input ***

Dim Userid
Dim FSO, objFolder
Dim wsShell
strServer = "U:\"
result = InputBox(Message, Title)
Set wsShell = wScript.CreateObject ("WSCript.shell")
Set FSO = CreateObject("Scripting.FileSystemObject")
    Userid = result
Set objFolder = FSO.CreateFolder(strServer & Userid)

    
'********************Run Scanstate on machine***********************

WsShell.Run "C:\_usmt\x86\scanstate.exe U:\" & Userid & " /i:C:\_usmt\x86\migdocs.xml /i:C:\_USMT\x86\migapp.xml /nocompress /c"


'******End[/quote]