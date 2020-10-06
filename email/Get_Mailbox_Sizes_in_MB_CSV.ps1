Add-PSSnapin Microsoft.Exchange.Management.Powershell.Admin;



Get-Mailbox | Get-MailboxStatistics | Select-Object DisplayName, {$_.TotalItemSize.Value.ToMB()} | Export-Csv c:\temp\mailbox_stats.csv