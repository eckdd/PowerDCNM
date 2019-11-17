###### Authentication Functions ######
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
End {Remove-Variable -Name DCNM_* -Scope Global}
}
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

###### Primordial Functions ######
function Get-DCNMObject              {
    <#
 .SYNOPSIS
Retrieves a new object to the REST API
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API path
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
  $response = Invoke-RestMethod -SkipCertificateCheck -Method Get -Uri $uri -Headers $headers
  } else { $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers }
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
function Set-DCNMObject              {
<#
 .SYNOPSIS
Updates a new object to the REST API
 .DESCRIPTION
This cmdlet will invoke a REST put against the DCNM API containing custom data
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
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
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
$headers = @{ 'dcnm-token' = "$AuthToken" ; 'content-type' = "application/x-www-form-urlencoded" ; 'cache-control' = "no-cache"}

 try {
  if ($IsCore -eq $true) {
  $response = Invoke-RestMethod -SkipCertificateCheck -Method Put -Uri $uri -Headers $headers -Body $object
  } else { $response = Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -Body $object }
 } catch {
  $message = $_.Exception.Message
  if ($message -eq 'Invalid URI: The hostname could not be parsed.') {
  Write-Host $message -ForegroundColor Yellow
  New-DCNMAuthToken
   }  
  if ($message -eq 'Response status code does not indicate success: 401 (Unauthorized).') {
  Write-Host $message -ForegroundColor Yellow
  New-DCNMAuthToken -DCNMHost $env:DCNMHost
   }  
 }

        }
End     {
$response
        }
}
function Remove-DCNMObject           {
        <#
 .SYNOPSIS
Removes an object via the REST API
 .DESCRIPTION
This cmdlet will invoke a REST delete method against a URI
 .EXAMPLE
$uri = https://dcnm.dcloud.cisco.com/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/005056BB-0B24-0ed3-0000-399431961128/accessrules/005056BB-0B24-0ed3-0000-000268479706
Remove-DCNMObject -uri $uri
 .PARAMETER uri
Resource location
 .PARAMETER AuthAccessToken
Session Authentication Access Token
/#>
param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
            [string]$uri,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthToken="$env:DCNMAuthToken",
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
            $Object
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
if ($Object) { $uri = $Object.links.self }
$headers = @{ "X-auth-access-token" = "$AuthToken" }

try {
 if ($IsCore -eq $true) {
 $response = Invoke-RestMethod -SkipCertificateCheck -Method Delete -Uri $uri -Headers $headers
 } else { $response = Invoke-RestMethod -Method Delete -Uri $uri -Headers $headers }
} catch {
  $message = $_.Exception.Message
  if ($message -eq 'Invalid URI: The hostname could not be parsed.') {
  Write-Host $message -ForegroundColor Yellow
  New-DCNMAuthToken
   }  
  if ($message -eq 'Response status code does not indicate success: 401 (Unauthorized).') {
  Write-Host $message -ForegroundColor Yellow
  New-DCNMAuthToken -DCNMHost $env:DCNMHost
   }  
 }

$response
        }
End {Remove-Variable -Name DCNM_* -Scope Global}
}

###### Core Functions ######
function Get-DCNMFabric              {
    <#
 .SYNOPSIS
Retrieve list of fabrics
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Control - Fabrics path
 .EXAMPLE
Get-DCNMFabric
 .EXAMPLE
Get-DCNMFabric -name T*
 .PARAMETER name
Name of a fabric
/#>
param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
            [string]$name="*"
    )
Begin   {}
Process {
$uri = "$Global:DCNMHost/rest/control/fabrics"
$response = Get-DCNMObject -uri $uri
$response = $response | Where-Object -Property fabricName -Like $name
        }
End     {
$response
        }
}
function Get-DCNMSwitch              {
    <#
 .SYNOPSIS
Retrieve list of switches within a fabric
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Control - Inventory path
 .EXAMPLE
Get-DCNMObject
 .EXAMPLE
Get-DCNMObject -name TST
 .PARAMETER name
Name of a fabric
/#>
param
    (
        [Parameter(Mandatory=$false)]
            [string]$SwitchName="*",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$fabricName
    )
Begin   {}
Process {
$uri = "$Global:DCNMHost/rest/control/fabrics/$FabricName/inventory"
$response = Get-DCNMObject -uri $uri
$response = $response | Where-Object -Property logicalName -Like $SwitchName
        }
End     {
New-Variable -Scope Global -Name DCNMSwitch_$fabricName -Value $response -Force
$response
        }
}
function Get-DCNMInterface           {
    <#
 .SYNOPSIS
Retrieve list of interfaces on switches
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Control - Interface Service
 .EXAMPLE
Get-DCNMSwitch -fabric TST | Get-DCNMInterface
 .EXAMPLE
Get-DCNMSwitch -fabric TST -SwitchName Leaf-1 | Get-DCNMInterface -Name 'Ethernet1/10'
 .PARAMETER name
Name of an interface
/#>
param
    (
        [Parameter(Mandatory=$false)]
            [string]$Name="*",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$serialNumber
    )
Begin   {
$responses=@()
}
Process {
$uri = "$Global:DCNMHost/rest/interface/detail?serialNumber=$serialNumber"
$response  = Get-DCNMObject -uri $uri
$responses+= $response | Where-Object -Property ifName -Like $Name
        }
End     {
$responses
        }
}
function Set-DCNMInterface           {
    <#
 .SYNOPSIS
Retrieve list of interfaces on switches
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Control - Interface Service
 .EXAMPLE
Get-DCNMSwitch -fabric TST | Get-DCNMInterface
 .EXAMPLE
Get-DCNMSwitch -fabric TST -SwitchName Leaf-1 | Get-DCNMInterface -Name 'Ethernet1/10'
 .PARAMETER name
Name of an interface
/#>
param
    (
        [Parameter(Mandatory=$false)]
            [string]$Name="*",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$serialNumber
    )
Begin   {
$responses=@()
}
Process {
$uri = "$Global:DCNMHost/rest/interface/detail?serialNumber=$serialNumber"
$response  = Get-DCNMObject -uri $uri
$responses+= $response | Where-Object -Property ifName -Like $Name
        }
End     {
$responses
        }
}
function Get-DCNMNetwork             {
    <#
 .SYNOPSIS
Retrieve list of networks
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Top Down LAN Network Operations
 .EXAMPLE
Get-DCNMNetwork -Fabric SITE-3
 .EXAMPLE
Get-DCNMNetwork -Name *30001 -Fabric SITE-3
 .PARAMETER Fabric
Name of a fabric
 .PARAMETER Name
Name of a network
/#>
param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
            [string]$Name="*",
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$Fabric
    )
Begin   {}
Process {
$uri = "$Global:DCNMHost/rest/top-down/fabrics/$Fabric/networks"
$response = Get-DCNMObject -uri $uri
$response = $response | Where-Object -Property networkName -Like $name
        }
End     {
$response
        }
}
function Get-DCNMNetworkAttachments  {
    <#
 .SYNOPSIS
Retrieve list of networks attachments
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Top Down LAN Network Operations
 .EXAMPLE
Get-DCNMNetwork -Fabric SITE-3 -Network MyNetwork_30001
 .PARAMETER Fabric
Name of a fabric
 .PARAMETER Network
Name of a network
/#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$Network,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$Fabric
    )
Begin   {}
Process {
$uri = "$Global:DCNMHost/rest/top-down/fabrics/$Fabric/networks/attachments?network-names=$Network"
$response = Get-DCNMObject -uri $uri
        }
End     {
$response.lanAttachList
        }
}
function Deploy-DCNMNetwork          {
    <#
 .SYNOPSIS
Deploy pending changes to networks
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Top Down LAN Network Operations
 .EXAMPLE
Deploy-DCNMNetwork -Fabric SITE-3 -Network SHUTDOWN
 .EXAMPLE

 .PARAMETER Fabric
Name of a fabric
 .PARAMETER Network
Name of a network
/#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$Network,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$Fabric,
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {}
Process {
$uri  = "$Global:DCNMHost/rest/top-down/fabrics/$Fabric/networks/deployments"
$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -Name networkNames -Value $Network
   if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
    $response = New-DCNMObject -uri $uri -object ($body | ConvertTo-Json) ; $response}
        }
End     {}
}
function Deploy-DCNMFabric           {
    <#
 .SYNOPSIS
Deploy pending changes to a fabric
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Control - Fabric Operations
 .EXAMPLE
Deploy-DCNMFabric -Fabric SITE-3
 .PARAMETER Fabric
Name of a fabric
/#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$Fabric,
        [Parameter(Mandatory=$false)]
            [switch]$NoSync,
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {}
Process {
if ($NoSync) {$SyncFlag = 'false'} else {$SyncFlag = 'true'}
$uri  = "$Global:DCNMHost/rest/control/fabrics/$Fabric/config-deploy?forceShowRun=$SyncFlag"
   if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
    $response = New-DCNMObject -uri $uri ; $response}
        }
End     {}
}
function Set-DCNMNetwork             {
    <#
 .SYNOPSIS
Attaches/Removes networks to switches
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM API Top Down LAN Network Operations
 .EXAMPLE
Set-DCNMNetwork -Fabric SITE-3 -Network MyNetwork_30001 -Switch Leaf2 -Interface Ethernet1/10
 .EXAMPLE
Set-DCNMNetwork -Fabric SITE-3 -Network MyNetwork_30001 -Switch Leaf2 -DetatchInterface Ethernet1/10
 .EXAMPLE
Set-DCNMNetwork -Network SHUTDOWN -Fabric SITE-3 -Switch Leaf2 -RemoveNetwork
 .PARAMETER Network
Name of the Network
 .PARAMETER Fabric
Name of the Fabric
 .PARAMETER Switch
Name of the Leaf switch
 .PARAMETER Interface
Name of optional interface to attach to network 
 .PARAMETER DetatchInterface
Name of interface to remove from network
 .PARAMETER Untagged
Specifiy tagged or untagged
 .PARAMETER AccessVLAN
Set different VLAN id
 .PARAMETER TrunkVLAN
802.1q VLAN
 .PARAMETER RemoveNetwork
Removes network from switch
 .PARAMETER DoNotDeploy
Leaves changes pending deployment
/#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Network,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Fabric,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Switch,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Interface,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$DetatchInterface,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [bool]$Untagged=$false,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4094)]
            [int]$AccessVLAN=0,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4094)]
            [int]$TrunkVLAN,
        [Parameter(Mandatory=$false)]
            [switch]$RemoveNetwork,
        [Parameter(Mandatory=$false)]
            [switch]$DoNotDeploy,
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {
$lanAttachList = @()
}
Process {
if (!(Get-Variable DCNMSwitch_$Fabric)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}

$lanAttach = New-Object -TypeName psobject
$lanAttach | Add-Member -Type NoteProperty -Name fabric       -Value $Fabric
$lanAttach | Add-Member -Type NoteProperty -Name networkName  -Value $Network
$lanAttach | Add-Member -Type NoteProperty -Name serialNumber -Value ((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $Switch).serialNumber
$lanAttach | Add-Member -Type NoteProperty -Name switchPorts        -Value $Interface
$lanAttach | Add-Member -Type NoteProperty -Name detachSwitchPorts  -Value $DetatchInterface
$lanAttach | Add-Member -Type NoteProperty -Name vlan               -Value $AccessVLAN
$lanAttach | Add-Member -Type NoteProperty -Name dot1QVlan          -Value $TrunkVLAN
$lanAttach | Add-Member -Type NoteProperty -Name untagged           -Value $Untagged
$lanAttach | Add-Member -Type NoteProperty -Name deployment         -Value (!$RemoveNetwork)

$lanAttachList += $lanAttach
        }
End     {
$Fabrics  = $lanAttachList.fabric      | Get-Unique
foreach ($fab in $Fabrics) {
  $body     = @()  
  $Networks = @()
  $fabItems = @()
  $uri      = "$Global:DCNMHost/rest/top-down/fabrics/$fab/networks/attachments"
  $fabItems = $lanAttachList | Where-Object {$_.fabric -EQ $fab}
  $Networks = $fabItems.networkName | Get-Unique
  foreach ($net in $Networks) {
   $item = New-Object -TypeName psobject
   $item | Add-Member -MemberType NoteProperty -Name networkName   -Value $net

   $netItems = @()
   foreach ($fabItem in ($fabItems | Where-Object {$_.networkName -EQ $net})) {
    $netItems += $fabItem
   }
   $item | Add-Member -MemberType NoteProperty -Name lanAttachList   -Value $netItems
   $body += $item
  }
   if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject @($body) -Depth 10) ; $Global:DCNM_JSON} else {
    $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject @($body) -Depth 10) ; $response 
    if ((select -InputObject $response -ExpandProperty *) -eq 'SUCCESS' -and !$DoNotDeploy) {
     foreach ($net in $body.networkName) {
      Deploy-DCNMNetwork -Network $net -Fabric $fab
     }
    }
   }
 }
}
}
