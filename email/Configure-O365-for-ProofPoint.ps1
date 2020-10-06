$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
Import-PSSession $Session

## IP Allow Range for ProofPoint US1, US3, and US4 WITHOUT Archiving
$allowedIPs = ("67.231.144.0/24","67.231.145.0/24","67.231.146.0/24","67.231.147.0/24","67.231.148.0/24","67.231.152.0/24",
"67.231.153.0/24","67.231.154.0/24","67.231.155.0/24","67.231.156.0/24","148.163.128.0/24","148.163.129.0/24","148.163.130.0/24",
"148.163.131.0/24","148.163.132.0/24","148.163.133.0/24","148.163.134.0/24","148.163.135.0/24","148.163.136.0/24","148.163.137.0/24",
"148.163.138.0/24","148.163.139.0/24","148.163.140.0/24","148.163.141.0/24","148.163.142.0/24","148.163.143.0/24","148.163.144.0/24",
"148.163.145.0/24","148.163.146.0/24","148.163.147.0/24","148.163.148.0/24","148.163.149.0/24","148.163.150.0/24","148.163.151.0/24",
"148.163.152.0/24","148.163.153.0/24","148.163.154.0/24","148.163.155.0/24","148.163.156.0/24","148.163.157.0/24","148.163.158.0/24","148.163.159.0/24")

#Add with Archiving 34.192.199.2,52.55.243.18,52.54.85.198

# This adds ProofPoint transport rules and outbound connector
New-TransportRule -Name "Block Non-Proofpoint Inbound" -Enabled $false -FromScope NotInOrganization -DeleteMessage $true -ExceptIfSenderIpRanges $allowedIPs -ExceptIfRecipientDomainIs $tennantDomain

New-OutboundConnector -Name "Proofpoint - Outbound" -Enabled $false -UseMXRecord $false -RecipientDomains * -SmartHosts ("outbound-us1.ppe-hosted.com") -TlsSettings EncryptionOnly

#Add Proofpoint to the inbound connection filter
Set-HostedConnectionFilterPolicy Default -IPAllowList @{Add=$allowedIPs}

Remove-PSSession $Session
