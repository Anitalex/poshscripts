net use x: \\192.168.80.103\Utility
powershell.exe set-executionpolicy unrestricted
powershell.exe -file x:\Scripts\Export-WLAN.ps1
net use x: /delete