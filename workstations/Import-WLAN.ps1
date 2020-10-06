$XmlDirectory = "C:\Installation_Files\client\Wireless\"
#Import all WLAN Xml-files from specified directory 
Get-ChildItem $XmlDirectory | Where-Object {$_.extension -eq ".xml"} | ForEach-Object {netsh wlan add profile filename=($XmlDirectory+"\"+$_.name) user=all} 


