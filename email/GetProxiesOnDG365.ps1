$dls = Get-UnifiedGroup

foreach ($dl in $dls){
    $name = $dl.DisplayName
    $proxies = $dl.EmailAddresses
    foreach($proxy in $proxies){
        $output = "$name  $proxy"
        $output | out-file c:\temp\DLProxies.txt -Append
    }
}

