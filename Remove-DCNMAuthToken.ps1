function Remove-DCNMAuthToken        {
<#
 .SYNOPSIS
Logs out of the DCNM API
 .DESCRIPTION
This cmdlet will invoke a REST post against the DCNM API, that will destroy the AuthToken generated
from the New-DCNMAuthentication function, and log the user out 
 .EXAMPLE
Remove-DCNMAuthToken
 .PARAMETER dcnmHost
Base URL of DCNM
 .PARAMETER token
Dcnm-Token value
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$DCNMHost=$Global:DCNMHost,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$token=$Global:DCNMAuthToken

    )
Begin {
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
$uri = "$DCNMHost/rest/logout"
$headers = @{ 'Dcnm-Token' = "$env:DCNMAuthToken" ; 'Content-Type' = 'application/json' ; Accept = 'application/json' }

if ($IsCore -eq $true) {
$AuthResponse = Invoke-WebRequest -SkipCertificateCheck -Uri $uri -Headers $headers -Method Post
} else {$AuthResponse = Invoke-WebRequest -Uri $uri -Headers $headers -Method Post -Body
}
 $AuthResponse     
        }
End {Remove-Variable -Name DCNM* -Scope Global}
}
