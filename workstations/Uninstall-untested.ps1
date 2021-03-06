#############################################################
#       MSIEXEC INSTALLER APPLICATIONS
#############################################################




#Uninstall J2SE Runtime Environment 5.0 Update 6 
$J2SE = get-wmiobject win32_product | where {$_.name -match "J2SE Runtime Environment"}
$J2SEid = $J2SE.IdentifyingNumber
if($J2SE.name -match "J2SE Runtime Environment"){
(Start-Process -FilePath "msiexec.exe" -ArgumentList "/uninstall $J2SEid /qn" -Wait -Passthru).ExitCode
}

#Uninstall Java(TM) 
$Java = get-wmiobject win32_product | where {$_.name -match "Java(TM)"}
$Javaid = $Java.IdentifyingNumber
if($Java.name -match "Java(TM)"){
(Start-Process -FilePath "msiexec.exe" -ArgumentList "/X$Javaid /qn" -Wait -Passthru).ExitCode
}

#Uninstall System Migration Assistant  
$SysMigAssist  = get-wmiobject win32_product | where {$_.name -match "System Migration Assistant"}
$SysMigAssistid = $SysMigAssist.IdentifyingNumber
if($SysMigAssist.name -match "System Migration Assistant"){
(Start-Process -FilePath "msiexec.exe" -ArgumentList "/X$SysMigAssistid /qn" -Wait -Passthru).ExitCode
}


#Uninstall ThinkVantage System Update    
$TVSU   = get-wmiobject win32_product | where {$_.name -match "ThinkVantage System Update"}
$TVSUid = $TVSU.IdentifyingNumber
if($TVSU.name -match "ThinkVantage System Update"){
(Start-Process -FilePath "msiexec.exe" -ArgumentList "/X$TVSUid /qn" -Wait -Passthru).ExitCode
}


#Uninstall Diskeeper Lite     
$DiskKeep   = get-wmiobject win32_product | where {$_.name -match "Diskeeper Lite"}
$DiskKeepid = $DiskKeep.IdentifyingNumber
if($DiskKeep.name -match "Diskeeper Lite"){
(Start-Process -FilePath "msiexec.exe" -ArgumentList "/X$DiskKeepid /qn" -Wait -Passthru).ExitCode
}



#Uninstall Online Data Backup
$OnlineBackup = get-wmiobject win32_product | where {$_.name -match "Online Data Backup"}
$OnlineBackupid = $OnlineBackup.IdentifyingNumber
if($OnlineBackup.name -match "Online Data Backup"){
(Start-Process -FilePath "msiexec.exe" -ArgumentList "/uninstall $OnlineBackupid /qn" -Wait -Passthru).ExitCode
}



#######################################################
#   CMD Installer Apps
#######################################################



#Uninstall Maintenance Manager  
$MaintenanceMgr   = get-wmiobject win32_product | where {$_.name -match "Maintenance Manager"}
if($MaintenanceMgr.name -match "Maintenance Manager"){
CMD /S "Rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 C:\WINDOWS\INF\AWAYTASK.INF"
Exit}

##################################################################
#         CMD INSTALLER APPLICATIONS WITH RUNDLL32
##################################################################


#Uninstall ThinkPad FullScreen Magnifier   
$MaintenanceMgr   = get-wmiobject win32_product | where {$_.name -match "ThinkPad FullScreen Magnifier"}
if($MaintenanceMgr.name -match "ThinkPad FullScreen Magnifier"){
CMD /S "rundll32.exe ‘C:\Program Files\Lenovo\ZOOM\cleanup.dll’,InfUninstall DefaultUninstall 132 C:\Program Files\Lenovo\Zoom\TpScrex.inf"
Exit}

#Uninstall Lenovo help center
$LenovoHelpCenter = get-wmiobject win32_product | where {$_.name -match "Lenovo help center"}
$LenovoHelpCenterid = $LenovoHelpCenter.IdentifyingNumber
if($LenovoHelpCenter.name -match "Lenovo help center"){
Copy-Item -path 'C:\Leapfrog Installation Files\Custom\LenovoUninstalls\HelpCenter\Uninst.iss' -destination 'C:\Program Files\InstallShield Installation Information\$LenovoHelpCenterid\'
CMD /S "RunDll32 C:\PROGRA~1\COMMON~1\INSTAL~1\engine\6\INTEL3~1\Ctor.dll,LaunchSetup 'C:\Program Files\InstallShield Installation Information\$LenovoHelpCenterid\Setup.exe' /s -l0x9 -AddRemove -f1'C:\Program Files\InstallShield Installation Information\$LenovoHelpCenterid\uninst.iss' anything -f2x"
EXIT}

#Uninstall Message Center
$MessageCenter = get-wmiobject win32_product | where {$_.name -match "Message Center"}
$MessageCenterid = $MessageCenter.IdentifyingNumber
if($MessageCenter.name -match "Message Center"){
Copy-Item -path 'C:\Leapfrog Installation Files\Custom\LenovoUninstalls\MessageCenter\Uninst.iss' -destination 'C:\Program Files\InstallShield Installation Information\$MessageCenterid\'
CMD.exe \s “RunDll32 C:\PROGRA~1\COMMON~1\INSTAL~1\engine\6\INTEL3~1\Ctor.dll,LaunchSetup ‘C:\Program Files\InstallShield Installation Information\$MessageCenterid\Setup.exe’ /s -l0x9 -AddRemove -f1’C:\Program Files\InstallShield Installation Information$MessageCenterid\uninst.iss’ anything -f2x”
EXIT}

#Uninstall Presentation Director
$PresentationDirector = get-wmiobject win32_product | where {$_.name -match "Presentation Director"}
$PresentationDirectorid = $PresentationDirector.IdentifyingNumber
if($PresentationDirector.name -match "Presentation Director"){
Copy-Item -path 'C:\Leapfrog Installation Files\Custom\LenovoUninstalls\PresentationDirector\Uninst.iss' -destination 'C:\Program Files\InstallShield Installation Information\$PresentationDirectorid\'
CMD.exe \s “RunDll32 C:\PROGRA~1\COMMON~1\INSTAL~1\engine\6\INTEL3~1\Ctor.dll,LaunchSetup ‘C:\Program Files\InstallShield Installation Information\$PresentationDirectorid\Setup.exe’ /s -l0x9 -AddRemove -f1’C:\Program Files\InstallShield Installation Information\$PresentationDirectorid\uninst.iss’ anything -f2x”
EXIT}

#Uninstall Productivity Center Supplement for ThinkPad
$ProductCenterSup = get-wmiobject win32_product | where {$_.name -match "Productivity Center Supplement for ThinkPad"}
$ProductCenterSupid = $ProductCenterSup.IdentifyingNumber
if($ProductCenterSup.name -match "Productivity Center Supplement for ThinkPad"){
Copy-Item -path 'C:\Leapfrog Installation Files\Custom\LenovoUninstalls\ProductivityCenterforThinkpad\Uninst.iss' -destination 'C:\Program Files\InstallShield Installation Information\$ProductCenterSupid\'
CMD.exe \s “RunDll32 C:\PROGRA~1\COMMON~1\INSTAL~1\engine\6\INTEL3~1\Ctor.dll,LaunchSetup ‘C:\Program Files\InstallShield Installation Information\$ProductCenterSupid\Setup.exe’ /s -l0x9 -AddRemove -f1’C:\Program Files\InstallShield Installation Information\$ProductCenterSupid\uninst.iss’ anything -f2x”
EXIT}

#Uninstall ThinkPad Power Manager
$ThinkPadPowerMgr = get-wmiobject win32_product | where {$_.name -match "ThinkPad Power Manager"}
$ThinkPadPowerMgrid = $ThinkPadPowerMgr.IdentifyingNumber
if($ThinkPadPowerMgr.name -match "ThinkPad Power Manager"){
Copy-Item -path 'C:\Leapfrog Installation Files\Custom\LenovoUninstalls\ThinkvantagePowerManager\Uninst.iss' -destination 'C:\Program Files\InstallShield Installation Information\$ThinkPadPowerMgrid\'
CMD.exe \s “RunDll32 C:\PROGRA~1\COMMON~1\INSTAL~1\engine\6\INTEL3~1\Ctor.dll,LaunchSetup ‘C:\Program Files\InstallShield Installation Information\$ThinkPadPowerMgrid\Setup.exe’ /s -l0x9 -AddRemove -f1’C:\Program Files\InstallShield Installation Information\$ThinkPadPowerMgrid\uninst.iss’ anything -f2x”
EXIT}

#Uninstall ThinkVantage Productivity Center
$TVantageProductCenter = get-wmiobject win32_product | where {$_.name -match "ThinkVantage Productivity Center"}
$TVantageProductCenterid = $TVantageProductCenter.IdentifyingNumber
if($TVantageProductCenter.name -match "ThinkVantage Productivity Center"){
Copy-Item -path 'C:\Leapfrog Installation Files\Custom\LenovoUninstalls\ThinkVantageProductivityCenter\Uninst.iss' -destination 'C:\Program Files\InstallShield Installation Information\$TVantageProductCenterid\'
CMD.exe \s “RunDll32 C:\PROGRA~1\COMMON~1\INSTAL~1\engine\6\INTEL3~1\Ctor.dll,LaunchSetup ‘C:\Program Files\InstallShield Installation Information\$TVantageProductCenterid\Setup.exe’ /s -l0x9 -AddRemove -f1’C:\Program Files\InstallShield Installation Information\$TVantageProductCenterid\uninst.iss’ anything -f2x”
EXIT}

#Uninstall ThinkPad EasyEject Utility 
$EasyEject = get-wmiobject win32_product | where {$_.name -match "Presentation Director"}
$EasyEjectid = $EasyEject.IdentifyingNumber
if($EasyEject.name -match "Presentation Director"){
Copy-Item -path 'C:\Leapfrog Installation Files\Custom\LenovoUninstalls\ThinkpadEasyEjectUtility\Uninst.iss' -destination 'C:\Program Files\InstallShield Installation Information\$EasyEjectid\'
CMD.exe \s “RunDll32 C:\PROGRA~1\COMMON~1\INSTAL~1\engine\6\INTEL3~1\Ctor.dll,LaunchSetup ‘C:\Program Files\InstallShield Installation Information\$EasyEjectid\Setup.exe’ /s -l0x9 -AddRemove -f1’C:\Program Files\InstallShield Installation Information\$EasyEjectid\uninst.iss’ anything -f2x”
EXIT}

