#Get the client's directory
$Xml = Read-Host "What is the name of the client's customer specific folder?" 

#check to see if the Wireless folder is in the client's directory and create it if it isn't
if (test-path "\\192.168.80.103\Utility\CustomerSpecific\$Xml\Wireless"){
}
else{
new-item "\\192.168.80.103\Utility\CustomerSpecific\$Xml\Wireless" -type directory
}

#Select the Wirless directory
$XmlDirectory = "\\192.168.80.103\Utility\CustomerSpecific\$Xml\Wireless"
 
#Export all WLAN profiles to specified directory 
$wlans = netsh wlan show profiles | Select-String -Pattern "All User Profile" | 
    Foreach-Object {$_.ToString()} 
$exportdata = $wlans | Foreach-Object {$_.Replace("    All User Profile     : ",$null)} 
$exportdata | ForEach-Object {netsh wlan export profile $_ $XmlDirectory key=clear} 
