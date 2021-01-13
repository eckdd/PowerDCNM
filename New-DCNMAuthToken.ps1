function New-DCNMAuthToken           {
<#
 .SYNOPSIS
Obtains Domain UUID and X-auth-access-token
 .DESCRIPTION
This cmdlet will invoke a REST post against the DCNM API, authenticate, and provide an X-auth-access-token and
Domain UUID for use in other functions
 .EXAMPLE
New-DCNMAuthToken -dcnmHost 'https://dcnm.dcloud.cisco.com' -username 'davdecke' -password 'YDgQ7CBR'
 .PARAMETER dcnmHost
Base URL of DCNM
 .PARAMETER username
REST account username
 .PARAMETER password
REST account password
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$DCNMHost=$Global:DCNMHost,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Time='60',
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Username,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            $Password=(Get-Credential -UserName $Username -Message "Enter Credentials for $DCNMHost").GetNetworkCredential().password

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
$expirationTime=[timespan]::FromMinutes("$Time").TotalMilliseconds
$credPair = "$($username):$($password)"
$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
$body = New-Object -TypeName psobject 
$body | Add-Member -MemberType NoteProperty -Name expirationTime -Value $expirationTime
$uri = "$DCNMHost/rest/logon"
$headers = @{ Authorization = "Basic $encodedCredentials" ; 'Content-Type' = 'application/json' ; Accept = 'application/json' }
try {
 if ($IsCore -eq $true) {
 $AuthResponse = Invoke-WebRequest -SkipCertificateCheck -Uri $uri -Headers $headers -Method Post -Body ($body | ConvertTo-Json) -ErrorAction Stop
 } else {$AuthResponse = Invoke-WebRequest -Uri $uri -Headers $headers -Method Post -Body ($body | ConvertTo-Json) -ErrorAction Stop
 }
} catch {
  Write-Host $_.ErrorDetails.Message -ForegroundColor Yellow} 

$AuthToken = ($AuthResponse.Content.Trim('{|}').Split(':'))[1].Trim('"')

$output = New-Object -TypeName psobject
$output | Add-Member -MemberType NoteProperty -Name dcnmHost           -Value $DCNMHost
$output | Add-Member -MemberType NoteProperty -Name dcnmToken          -Value $AuthToken
$Global:DCNMHost      = $output.dcnmHost
$Global:DCNMAuthToken = $output.dcnmToken
$output        
        }
End {Remove-Variable -Name DCNM_*,DCNMSwitch* -Scope Global}
}