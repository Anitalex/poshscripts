REM @echo off
REM ::
REM Echo Save the batch file as "WSUS.bat". This batch file will do the following:
REM Echo 1.    Stops the Automatic Update Service (wuauserv) service.
REM Echo 2.    Imports WUA settings for workstations in workgroup to detect/download/install updates from WSUS.
REM Echo 3.    Starts the Automatic Update Service (wuauserv) service.
REM Echo 4.    Force update detection.
REM Echo 5.    More information on http://msmvps.com/Athif

%windir%\Regedit.exe /s %systemdrive%\LFSoftware\dlbuble.reg.reg
