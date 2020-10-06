Dim objShell
Set objShell = WScript.CreateObject ("WScript.shell")
objShell.run "cmd /K CD C:\ & cscript c:\windows\system32\slmgr.vbs /dli"
Set objShell = Nothing
