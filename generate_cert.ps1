# PowerShell script to generate a self-signed certificate for localhost
# Run this as Administrator

# Create a self-signed certificate for localhost
$cert = New-SelfSignedCertificate -DnsName "localhost", "127.0.0.1", "::1" -CertStoreLocation "cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(1) -KeyUsage DigitalSignature, KeyEncipherment -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")

# Export the certificate to files
$certPath = ".\localhost.crt"
$keyPath = ".\localhost.key"

# Export certificate
Export-Certificate -Cert $cert -FilePath $certPath -Type CERT

# Export private key (requires conversion)
$certWithKey = Get-ChildItem -Path "cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
$keyBytes = $certWithKey.PrivateKey.ExportCspBlob($true)
[System.IO.File]::WriteAllBytes($keyPath, $keyBytes)

Write-Host "Certificate generated successfully!"
Write-Host "Certificate: $certPath"
Write-Host "Private Key: $keyPath"
Write-Host ""
Write-Host "To trust this certificate:"
Write-Host "1. Double-click on localhost.crt"
Write-Host "2. Click 'Install Certificate'"
Write-Host "3. Choose 'Local Machine'"
Write-Host "4. Select 'Place all certificates in the following store'"
Write-Host "5. Browse and select 'Trusted Root Certification Authorities'"
Write-Host "6. Click OK and Finish" 