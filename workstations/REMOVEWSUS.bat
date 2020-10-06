Net Stop "wuauserv"
Echo Importing WSUS.reg
%windir%\Regedit.exe /s \\192.168.80.103\Utility\Scripts\REMOVEWSUS.reg
Echo WSUS.reg imported succesfully
Net Start "wuauserv"
Echo Forcing update detection
wuauclt /detectnow