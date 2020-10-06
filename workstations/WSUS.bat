
Net Stop "wuauserv"
Echo Importing WSUS.reg
%windir%\Regedit.exe /s .\WSUS.reg
Echo WSUS.reg imported succesfully
Net Start "wuauserv"
Echo Forcing update detection
wuauclt /detectnow
