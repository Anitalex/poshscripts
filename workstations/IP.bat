net use x: \\192.168.40.103\Utility
powershell.exe set-executionpolicy bypass
powershell.exe -file "x:\Scripts\IP.ps1"
net use x: /delete