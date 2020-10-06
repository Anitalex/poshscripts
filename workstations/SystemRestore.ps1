

Write-Verbose "Enable and Run System Restore"
$date = get-date
Invoke-WmiMethod -namespace "root\default" -class "systemrestore" -name "enable" -argumentlist "c:\"
Start-Sleep -s 15
checkpoint-computer -description "$date"









