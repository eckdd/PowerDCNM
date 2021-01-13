function New-DCNMObject              {
<#
 .SYNOPSIS
Post a new object to the REST API
 .DESCRIPTION
This cmdlet will invoke a REST post against the DCNM API containing custom data
 .EXAMPLE
$uri = https://dcnm.dcloud.cisco.com/rest/interface
New-DCNMObject -uri $uri -object ($body | ConvertTo-Json)
 .PARAMETER uri
Resource location
 .PARAMETER object
JSON data
 .PARAMETER AuthAccessToken
Session Authentication Access Token
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$uri,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$object,
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
$headers = @{ 'dcnm-token' = "$AuthToken" ; 'content-type' = "application/json" ; 'Accept' = "application/json"}
if ($body) {
  if ($IsCore -eq $true) {
  $response = Invoke-RestMethod -SkipCertificateCheck -Method Post -Uri $uri -Headers $headers -Body $object
  } else { $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $object }
 } else {
  if ($IsCore -eq $true) {
  $response = Invoke-RestMethod -SkipCertificateCheck -Method Post -Uri $uri -Headers $headers
  } else { $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers }
 }
        }
End     {
$response
        }
}
