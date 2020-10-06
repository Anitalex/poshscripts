$ip = (Get-NetIPConfiguration).IPv4Address.IPAddress
$dns = (Test-DnsServer $ip).result
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters'

if ($dns -eq 'Success'){
   New-ItemProperty -path $key -name TcpReceivePacketSize -PropertyType DWORD -value '0xFF00'
   $test = Get-ItemProperty -path $key -name TcpReceivePacketSize
   if ($test -eq $null){
        $result = $false
   }else{
        $result = $true
   }
   return $result
}