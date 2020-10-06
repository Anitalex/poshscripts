$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
Import-PSSession $Session

Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
Get-Mailbox | Set-Mailbox -AuditEnabled:$true -AuditOwner MailboxLogin