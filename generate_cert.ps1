# PowerShell script to generate a self-signed certificate for localhost
# Run this as Administrator

# Generate self-signed certificate for localhost
$cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(1) -FriendlyName "Cenap Localhost Certificate"

# Export certificate to file
$certPath = "cert:\LocalMachine\My\$($cert.Thumbprint)"
Export-Certificate -Cert $certPath -FilePath "localhost.crt"

# Export private key
$password = ConvertTo-SecureString -String "password" -Force -AsPlainText
Export-PfxCertificate -Cert $certPath -FilePath "localhost.pfx" -Password $password

Write-Host "Certificate generated successfully!"
Write-Host "Certificate file: localhost.crt"
Write-Host "Private key file: localhost.pfx"
Write-Host ""
Write-Host "To trust this certificate:"
Write-Host "1. Double-click on localhost.crt"
Write-Host "2. Click 'Install Certificate'"
Write-Host "3. Choose 'Local Machine'"
Write-Host "4. Select 'Place all certificates in the following store'"
Write-Host "5. Browse and select 'Trusted Root Certification Authorities'"
Write-Host "6. Click OK and Finish" 