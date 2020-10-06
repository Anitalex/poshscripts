                ############################################################
                #             Script created change the active dhcp enabled adapter to the support
                #             center IP subnet
                #             Created by Carlos McCray 
                #             Last edited 2/8/2012
                #
                #             
                ############################################################
#Search WMI for network adapters that are IPEnabled and DHCPEnabled
$Nics = Get-WMIObject -Class win32_networkadapterconfiguration -Filter "IPEnabled='TRUE' AND DHCPEnabled='TRUE'" |
    Where {$_.IPAddress -match "192.168.40."}

#Get the IP address of that network adapter
$IP = $Nics.IPAddress[0]

#Parse the IP to get the last octet
$hostip = $IP.split(".")[3]

#Set the adapter to static on the Support Center subnet with the same last octet.
Foreach($NIC in $NICs){
$Nic.enablestatic("10.1.3.$hostip","255.255.255.0")
$Nic.SetGateways("10.1.3.1")
$DNSServers = "10.10.2.38","10.10.2.50","10.10.2.45","10.1.100.103"
$Nic.SetDNSServerSearchOrder($DNSServers)
$NIC.SetDynamicDNSRegistration($TRUE)
}
