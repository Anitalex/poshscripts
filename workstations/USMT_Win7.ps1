xcopy "\\192.168.30.203\Utility\USMT Windows 7\*" c:\
$store = read-host "What is the name of the folder you want to create to store the data?"
$folder = md "\\192.168.30.203\CustomerData\$store"
c:\usmt\x86\scanstate.exe "$folder" /i:c:\usmt\x86\migdocs.xml /i:C:\USMT\x86\migapp.xml /config:c:\USMT\x86\config.xml /nocompress /c
