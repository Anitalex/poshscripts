$namespace = "root\WMI"
$computer = "localhost"
Get-WmiObject Win32_NetworkAdapter -filter "AdapterTypeId=0" | % {
  $strNetworkAdapterID=$_.PNPDeviceID.ToUpper()
  Get-WmiObject -class MSPower_DeviceEnable -computername $computer -Namespace $namespace | % {
    if($_.InstanceName.ToUpper().startsWith($strNetworkAdapterID)){
      $_.Enable = $false
      $_.Put() | Out-Null
    }
  }
}