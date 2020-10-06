cmdow @ /HID
@echo off

SET KEY=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx

REG ADD %KEY% /V TITLE /D "Leapfrog is now installing software..." /f

REG ADD %KEY%\002 /VE /D "Java Runtime Environment" /f
REG ADD %KEY%\002 /V 1 /D "%systemdrive%\LFSoftware\Java\jre-6u18-windows-i586-s.exe /qn IEXPLORER=1 MOZILLA=1 REBOOT=Suppress JAVAUPDATE=0 EULA=0" /f

REG ADD %KEY%\003 /VE /D "Propalms Client" /f
REG ADD %KEY%\003 /V 1 /D "msiexec.exe /i \"%systemdrive%\LFSoftware\Propalms\PROPALMS-TSE-Client_6041.msi\" /TRANSFORMS=\"%systemdrive%\LFSoftware\Propalms\oac_propalms.mst\" /qn /norestart" /f

REG ADD %KEY%\004 /VE /D ".NET Framework Complete" /f
rem REG ADD %KEY%\004 /V 1 /D "%systemdrive%\LFSoftware\dotnet11.exe /q:a /c:\"install.exe /qn /l\"" /f
rem REG ADD %KEY%\004 /V 2 /D "%systemdrive%\LFSoftware\dotnet11sp1.exe /qn" /f
REG ADD %KEY%\004 /V 3 /D "%systemdrive%\LFSoftware\net\dotnet20sp1.exe /q /norestart" /f
REG ADD %KEY%\004 /V 4 /D "%systemdrive%\LFSoftware\net\dotnet30.exe /q /norestart" /f
REG ADD %KEY%\004 /V 5 /D "%systemdrive%\LFSoftware\net\dotnet35.exe /q /norestart" /f
REG ADD %KEY%\004 /V 6 /D "%systemdrive%\LFSoftware\net\dotnet35sp1.exe /quiet /norestart" /f

REG ADD %KEY%\006 /VE /D "Microsoft Office 2007 with SP2" /f
REG ADD %KEY%\006 /V 1 /D "%systemdrive%\LFSoftware\Office2007ProPlus\setup.exe /adminfile OAC-Office2007Settings.MSP" /f

REG ADD %KEY%\007 /VE /D "Powershell 1.0 for Windows XP" /f
REG ADD %KEY%\007 /V 1 /D "%systemdrive%\LFSoftware\powershell-xp.exe /quiet /norestart" /f
REG ADD %KEY%\007 /V 2 /D "%systemdrive%\LFSoftware\powershell-xp-mui.exe /quiet /norestart" /f

REG ADD %KEY%\008 /VE /D "Windows Media Player 11" /f
REG ADD %KEY%\008 /V 1 /D "%systemdrive%\LFSoftware\wmp11\setup_wm.exe /Q:A /R:N /DisallowSystemRestore" /f

REG ADD %KEY%\009 /VE /D "Adobe Acrobat Reader 9.3.1" /f
REG ADD %KEY%\009 /V 1 /D "msiexec /i \"%systemdrive%\LFSoftware\Reader\AcroRead.msi\" /qn" /f

REG ADD %KEY%\010 /VE /D "Optiplex 520 Drivers" /f
REG ADD %KEY%\010 /V 1 /D "msiexec.exe /i \"%systemdrive%\Drivers\Opti520\R97582\BDrvInst.msi\" /qn" /f
REG ADD %KEY%\010 /V 2 /D "%systemdrive%\Drivers\Opti520\R121089\setup.exe -s" /f
REG ADD %KEY%\010 /V 3 /D "%systemdrive%\Drivers\Opti520\R126542\setup.exe -nolic -s" /f
REG ADD %KEY%\010 /V 4 /D "%systemdrive%\Drivers\Opti520\R132254\setup.exe /s /v/qn" /f
REG ADD %KEY%\010 /V 5 /D "%systemdrive%\Drivers\Opti520\R132539\setup.exe -s" /f

REG ADD %KEY%\015 /VE /D "Kaspersky Network Agent" /f
REG ADD %KEY%\015 /V 1 /D "%systemdrive%\LFSoftware\KAV\oac-kavnetagent.exe /s" /f

REG ADD %KEY%\016 /VE /D "Kaspersky Antivirus MP4" /f
REG ADD %KEY%\016 /V 1 /D "%systemdrive%\LFSoftware\KAV\kav-mp4.exe /s" /f

exit

