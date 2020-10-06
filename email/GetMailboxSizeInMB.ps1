Get-MailboxStatistics -Server 'SERVERNAME' | where {$_.ObjectClass -eq �Mailbox�} | Sort-Object TotalItemSize -Descending | ft @{label=�User�;expression={$_.DisplayName}},@{label=�Total Size (MB)�;expression={$_.TotalItemSize.Value.ToMB()}}  -auto >> �c:\Temp\mailbox_size.txt�