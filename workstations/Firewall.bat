net use x: \\192.168.40.103\Utility
powershell.exe set-executionpolicy unrestricted
powershell.exe -file "x:\Scripts\Archived Scripts\Firewall.ps1"
net use x: /delete