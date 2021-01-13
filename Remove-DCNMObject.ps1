function Remove-DCNMObject           {
    <#
 .SYNOPSIS
Deletes an object from the REST API
 .DESCRIPTION
This cmdlet will invoke a REST delete against the DCNM API path
 .EXAMPLE
$uri = https://dcnm.dcloud.cisco.com/rest/control/fabrics
Get-DCNMObject -uri $uri
 .PARAMETER uri
Resource location
 .PARAMETER AuthAccessToken
Session Authentication Access Token
/#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$uri,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$Global:DCNMAuthToken"
    )
Begin   {
if ($PSEdition -eq 'Core') {$IsCore=$true} else {
$IsCore=$false
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
 }
}
Process {

$headers = @{ 'dcnm-token' = "$AuthToken" ; 'content-type' = "application/x-www-form-urlencoded" ; 'cache-control' = "no-cache"}
#try {
  if ($IsCore -eq $true) {
  $response = Invoke-RestMethod -SkipCertificateCheck -Method Delete -Uri $uri -Headers $headers
  } else { $response = Invoke-RestMethod -Method Delete -Uri $uri -Headers $headers }
 #} catch {
 # $message = $_.Exception.Message
 # if ($message -eq 'Invalid URI: The hostname could not be parsed.') {
 # Write-Host $message -ForegroundColor Yellow
 # New-DCNMAuthToken
 #  }  
 # if ($message -eq 'Response status code does not indicate success: 401 (Unauthorized).') {
 # Write-Host $message -ForegroundColor Yellow
 # New-DCNMAuthToken -DCNMHost $env:DCNMHost
 #  }  
 #}

        }
End     {
$response
        }
}