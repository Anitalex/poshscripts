Dim oMsi,oFso,oWShell

Dim Patches,SumInfo

Dim patch,record,msp

Dim qView

Dim sTargetFolder,sMessage

Const OFFICEID = "000-0000000FF1CE}"

Const PRODUCTCODE_EMPTY = ""

Const MACHINESID = ""

Const MSIINSTALLCONTEXT_MACHINE = 4

Const MSIPATCHSTATE_APPLIED = 1

Const MSIOPENDATABASEMODE_PATCHFILE = 32

Const PID_SUBJECT = 3 'Displayname

Const PID_TEMPLATES = 7 'PatchTargets

Set oMsi = CreateObject("WindowsInstaller.Installer")

Set oFso = CreateObject("Scripting.FileSystemObject")

Set oWShell = CreateObject("Wscript.Shell")

'Create the target folder

sTargetFolder = oWShell.ExpandEnvironmentStrings("%TEMP%")&"\Updates"

If Not oFso.FolderExists(sTargetFolder) Then oFso.CreateFolder sTargetFolder

sMessage = "Patches are being copied to the %Temp%\Updates folder." & vbCrLf & "A Windows Explorer window will open after the script has run."

oWShell.Popup sMessage,20,"Office Patch Collector"

'Get all applied patches

Set Patches = oMsi.PatchesEx(PRODUCTCODE_EMPTY,MACHINESID,MSIINSTALLCONTEXT_MACHINE,MSIPATCHSTATE_APPLIED)

On Error Resume Next

'Enum the patches

For Each patch in Patches

   If Not Err = 0 Then Err.Clear

    'Connect to the patch file

    Set msp = oMsi.OpenDatabase(patch.PatchProperty("LocalPackage"),MSIOPENDATABASEMODE_PATCHFILE)

    Set SumInfo = msp.SummaryInformation

    If Err = 0 Then

        If InStr(SumInfo.Property(PID_TEMPLATES),OFFICEID)>0 Then

            'Get the original patch name

            Set qView = msp.OpenView("SELECT `Property`,`Value` FROM MsiPatchMetadata WHERE `Property`='StdPackageName'")

            qView.Execute : Set record = qView.Fetch()

            'Copy and rename the patch to the original file name

            oFso.CopyFile patch.PatchProperty("LocalPackage"),sTargetFolder&"\"&record.StringData(2),TRUE

        End If

    End If 'Err = 0

Next 'patch

oWShell.Run "explorer /e,"&chr(34)&sTargetFolder&chr(34)

