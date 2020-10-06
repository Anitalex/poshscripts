$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
Import-PSSession $Session





Get-TransportRule | Disable-TransportRule -Confirm:$false
Enable-TransportRule "Block Non-Proofpoint Inbound" 



# The below comand will enable the smarthost for proofpoint in Office 365

Set-OutboundConnector "Proofpoint - Outbound" -Enabled $true 

Remove-PSSession $Session
