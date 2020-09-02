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
End {Remove-Variable -Name DCNM_*,DCNMSwitch* -Scope Global}
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
$response | Where-Object -Property logicalName -Like $SwitchName
        }
End     {
if ($response) {New-Variable -Scope Global -Name DCNMSwitch_$fabricName -Value $response -Force}
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
Configures Ethernet interfaces
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM API Global Interface
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName SPINE-4 -Interface eth1/19 -Description test -Speed 100Gb -Mode Routed -Prefix 30.30.30.30/24 -Tag 76894 -VRF myvrf

# Configure eth1/19 as a routed port, add description of "test", set the speed to 100Gb, configure 30.30.30.30/24 as the IP Address
# Set a tag of 76894, and place in the VRF "myvrf"
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName LEAF-6 -Interface 'eth1/40-45,eth1/50-55,eth1/100' -Mode Access -AccessVLAN 2020

# Configure eth1/40-45,eth1/50-55,eth1/100 as access ports in VLAN 2020
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName LEAF-6 -Interface 'eth1/40-45,eth1/50-55,eth1/100' -Mode Trunk -Enabled true -AllowedVLANs none

# Configure eth1/40-45,eth1/50-55,eth1/100 as trunk ports with no allowed VLANs. 
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName LEAF-6 -Interface 'eth1/101,eth1/105-110' -Mode Freeform -CliFreeform @"
>> description Unnumbered Links
>> no switchport
>> medium p2p
>> ip unnumbered loopback70
>> "@ -Enabled true

# Use the freeform template to create an unnumbered routed interface
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName LEAF-6 -Interface eth1/10 -Mode Monitor

# Use the monitor template on eth1/10 to prevent DCNM from enforcing configuration complaince on that interface
 .EXAMPLE
(Import-Csv .\Book2.csv)[2..4] | Set-DCNMInterface

# Use a CSV file with headers corresponding to parameters to bulk-import interface configurations
 .PARAMETER Fabric
Name of the fabric
 .PARAMETER SwitchName
Name of the switch
 .PARAMETER Interface
List of ethernet interfaces. Must begin with eth{slot}/{port} or eth{fex}/{slot}/{port}
 .PARAMETER Description
Interface description
 .PARAMETER Enabled
Enables or disables the interfaces; true or false
 .PARAMETER Freeform
Specifies the freeform template to be used
 .PARAMETER Speed
Interface speed
 .PARAMETER Enabled
Enable or disable interface after creation
 .PARAMETER BPDUGuard
Enables or disables BPDUGuard
 .PARAMETER MTU_L2
MTU for Access or Trunk ports; can be Jumbo (9216) or default (1500)
 .PARAMETER PortFast
Enable/disable spanning-tree port-fast
 .PARAMETER Mode
Specifies whether to use the access, trunk, routed, or monitor template
 .PARAMETER AccessVLAN
Access port VLAN 
 .PARAMETER AllowedVLANs
Configures allowed VLAN list for trunk port-channels.
Options include "all", "none", ranges, or comma-separated values
 .PARAMETER MTU_L3
MTU size for layer-3 ports
 .PARAMETER VRF
Sets the VRF of a layer3
 .PARAMETER Prefix
Sets the IP and netmask
 .PARAMETER Tag
Configrues a numeric route tag value (0-4294967295) for a layer3 port 
 .PARAMETER CliFreeform
Freeform interfaces configuration 
 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("fabricName")]
            [string]$Fabric,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("sysName","logicalName")]
            [string]$SwitchName,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("ifName")]
            [string]$Interface,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description="",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
            [string]$Enabled="true",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Auto","100Mb","1Gb","10Gb","25Gb","40Gb","100Gb")]
            [string]$Speed="Auto",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false","no")]
           [string]$BPDUGuard="true",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("jumbo","default")]
            [string]$MTU_L2="jumbo",
   
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
            [string]$PortFast="true",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Access","Trunk","Routed","Freeform","Monitor")]
            [string]$Mode,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4094)]
            [int]$AccessVLAN,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AllowedVLANs,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(576,9216)]
            [int]$MTU_L3="9216",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$VRF="",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [AllowNull()] 
        [AllowEmptyCollection()]
        [ValidatePattern('(\d+\.){3}\d+\/\d+')]
            [string]$Prefix,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(0,4294967295)]
            [string]$Tag="",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$CliFreeform="",
         
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {
}
Process {
[string]$Interface = $Interface.ToLower().Replace('ethernet','eth')

    $ifNames = @()
    foreach ($EthMod in $Interface.split('eth', [System.StringSplitOptions]::RemoveEmptyEntries)) {
        if ($EthMod.Split('/')[2]) {
            $fexN = $EthMod.split('/')[0]
            $slot = $EthMod.split('/')[1]
            $port = $EthMod.split('/')[2]
            } else {
            $slot = $EthMod.split('/')[0]
            $port = $EthMod.split('/')[1]
            }
        $port = $port.split(',', [System.StringSplitOptions]::RemoveEmptyEntries)
         foreach ($p in $port) {
            if ($p -match '^\d+$') {
                if ($fexN) {
                    $ifNames += 'Ethernet'+$fexN+'/'+$slot+'/'+$p
                } else {
                $ifNames += 'Ethernet'+$slot+'/'+$p
                }
            } elseif ($p -match '\d+\-\d+') {
                $p = $p.split('-')[0]..$p.split('-')[1]
                $p | ForEach-Object {
                    if ($fexN) {
                        $ifNames += 'Ethernet'+$fexN+'/'+$slot+'/'+$_
                    } else {
                    $ifNames += 'Ethernet'+$slot+'/'+$_
                    }
                }
               } 
        Remove-Variable p,slot,port,fexN -ErrorAction Ignore
            }
    }

if ($ifNames.Length -eq 1) {$MultiEdit = 'false'} else {$MultiEdit = 'true'}
$uri      = "$Global:DCNMHost/rest/globalInterface/pti?isMultiEdit=$MultiEdit"
if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}
$body    = New-Object -TypeName psobject
$nvPairs = New-Object -TypeName psobject
$nvPairs | Add-Member -Type NoteProperty -Name CONF                       -Value $CliFreeform
$nvPairs | Add-Member -Type NoteProperty -Name ADMIN_STATE                -Value $Enabled.ToLower()


if ($Mode -eq 'Access')  {
    $body    | Add-Member -Type NoteProperty -Name policy                   -Value 'int_access_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name SPEED                    -Value $Speed
    $nvPairs | Add-Member -Type NoteProperty -Name DESC                     -Value $Description
    $nvPairs | Add-Member -Type NoteProperty -Name BPDUGUARD_ENABLED        -Value $BPDUGuard
    $nvPairs | Add-Member -Type NoteProperty -Name PORTTYPE_FAST_ENABLED    -Value $PortFast
    $nvPairs | Add-Member -Type NoteProperty -Name MTU                      -Value $MTU_L2
    $nvPairs | Add-Member -Type NoteProperty -Name ACCESS_VLAN              -Value $AccessVLAN
    }

if ($Mode -eq 'Trunk')   {
    $body    | Add-Member -Type NoteProperty -Name policy                   -Value 'int_trunk_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name SPEED                    -Value $Speed
    $nvPairs | Add-Member -Type NoteProperty -Name DESC                     -Value $Description
    $nvPairs | Add-Member -Type NoteProperty -Name BPDUGUARD_ENABLED        -Value $BPDUGuard
    $nvPairs | Add-Member -Type NoteProperty -Name PORTTYPE_FAST_ENABLED    -Value $PortFast
    $nvPairs | Add-Member -Type NoteProperty -Name MTU                      -Value $MTU_L2
    $nvPairs | Add-Member -Type NoteProperty -Name ALLOWED_VLANS            -Value $AllowedVLANs.Replace(' ','')
    }

if ($Mode -eq 'Routed')  {
    $body    | Add-Member -Type NoteProperty -Name policy                   -Value 'int_routed_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name SPEED                    -Value $Speed
    $nvPairs | Add-Member -Type NoteProperty -Name DESC                     -Value $Description
    $nvPairs | Add-Member -Type NoteProperty -Name INTF_VRF                 -Value $VRF
    $nvPairs | Add-Member -Type NoteProperty -Name IP                       -Value ($Prefix.Split('/')[0])
    $nvPairs | Add-Member -Type NoteProperty -Name PREFIX                   -Value ($Prefix.Split('/')[1])
    $nvPairs | Add-Member -Type NoteProperty -Name ROUTING_TAG              -Value $Tag
    $nvPairs | Add-Member -Type NoteProperty -Name MTU                      -Value $MTU_L3
    }

if ($Mode -eq 'Freeform') {
    $body    | Add-Member -Type NoteProperty -Name policy                   -Value 'int_freeform'
}

if ($Mode -eq 'Monitor') {
    $body    | Add-Member -Type NoteProperty -Name policy                   -Value 'int_monitor_ethernet_11_1'
}

$ints=@()
ForEach ($ifName in $ifNames) {
$int = New-Object -TypeName psobject
$nvp = $nvPairs.psobject.copy()
$int | Add-Member -Type NoteProperty -Name serialNumber        -Value (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $SwitchName).serialNumber)
$int | Add-Member -Type NoteProperty -name interfaceType       -Value 'INTERFACE_ETHERNET'
$int | Add-Member -Type NoteProperty -name ifName              -Value $ifName
$int | Add-Member -Type NoteProperty -name fabricName          -Value $Fabric
$nvp | Add-Member -Type NoteProperty -name INTF_NAME           -Value $ifName 
$int | Add-Member -Type NoteProperty -name nvPairs             -Value $nvp
$ints += $int
}

$body | Add-Member -Type NoteProperty -Name interfaces -Value $ints

    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}

Remove-Variable -Name nvPairs,body -ErrorAction SilentlyContinue
#Remove-Variable -Name BPDUGuard,Speed,Fabric,Description,MTU_L3,MTU_L2,Enabled     -ErrorAction SilentlyContinue
#Remove-Variable -Name VRF,Prefix,Tag,AllowedVLANs,AccessVLAN,PortFast              -ErrorAction SilentlyContinue
#Remove-Variable -Name interface,interfaces,nvPairs,body,Mode                       -ErrorAction SilentlyContinue
$calls++
while ($calls -ge 80) {
    Start-Sleep -Seconds 10 
    [int]$calls = 0
    }
}    

End     {}
 
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
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$fabricName,
        [Parameter(Mandatory=$false)]
            [switch]$NoSync,
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {}
Process {
if ($NoSync) {$SyncFlag = 'false'} else {$SyncFlag = 'true'}
$uri  = "$Global:DCNMHost/rest/control/fabrics/$fabricName/config-deploy?forceShowRun=$SyncFlag"
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
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Network,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("fabricName")]
            [string]$Fabric,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("logicalName")]
            [string]$Switch,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Interface,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
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
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$CliFreeform,

        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {
$lanAttachList = @()
}
Process {
if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}

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
$lanAttach | Add-Member -Type NoteProperty -Name freeformConfig     -Value $CliFreeform

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
    if ((Select-Object -InputObject $response -ExpandProperty * -ErrorAction SilentlyContinue) -eq 'SUCCESS' -and !$DoNotDeploy) {
     foreach ($net in $body.networkName) {
      Deploy-DCNMNetwork -Network $net -Fabric $fab
     }
    }
   }
 }
}
}
function Get-DCNMPolicy              {
    <#
 .SYNOPSIS
Retrieve a DCNM policy object
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Control - Policies
 .EXAMPLE

 .EXAMPLE

 .PARAMETER Fabric

 .PARAMETER Name

 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string]$PolicyName
    )
Begin   {}
Process {
$uri = "$Global:DCNMHost/rest/control/policies/$PolicyName"
$response = Get-DCNMObject -uri $uri
        }
End     {
$response
        }
}
function New-DCNMPortChannel         {
    <#
 .SYNOPSIS
Creates a new port-channel interface
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM API Control - Policies
 .EXAMPLE
New-DCNMPortChannel -Fabric TST -SwitchName LEAF-1 -ID 300 -Members Eth1/10-14 -Mode Active -BPDUGuard true -PortFast true -MTU default -Description Server1 -Enabled true -Access -AccessVLAN 10
 .EXAMPLE
New-DCNMPortChannel -Fabric TST -SwitchName LEAF-1 -ID 301 -Members Eth1/20-24 -Mode Passive -BPDUGuard false -PortFast false -MTU jumbo -Description Switch1 -Enabled true -Trunk -AllowedVLANs '100,200,300-310'
 .EXAMPLE
New-DCNMPortChannel -Fabric TST -SwitchName Leaf-1 -ID 302 -Members Eth1/50-54 -Mode On -BPDUGuard true -PortFast true -MTU default -Description Firewall1 -Enabled true -Layer3 -VRF PROD -Prefix 10.100.30.1/24 -Tag 100
 .EXAMPLE
(Import-Csv .\Book2.csv)[2..4] | New-DCNMPortChannel -Access
 .PARAMETER Fabric
Name of the fabric
 .PARAMETER SwitchName
Name of the switch to create the port-channel on
 .PARAMETER ID
Port-channel identifier
 .PARAMETER Members
Member interfaces 
 .PARAMETER Mode
Operating mode of the port-channel (Active, Passive, On)
 .PARAMETER BPDUGuard
Enables or disabled the BPDU Guard feature on port-channel
 .PARAMETER PortFast
Enables or disabled the portfast feature on port-channel
 .PARAMETER MTU
Sets either the default (1500) MTU size, or jumbo frame MTU (9216)
 .PARAMETER Description
Interface description
 .PARAMETER Enabled
Enable or disable interface after creation
 .PARAMETER PortType
Configure port as access, trunk, or routed
 .PARAMETER AccessVLAN
Sets the access port VLAN for an access port-channel
 .PARAMETER AllowedVLANs
Configures allowed VLAN list for trunk port-channels.
Options include "all", "none", ranges, or comma-separated values
 .PARAMETER VRF
Sets the VRF of a layer3 port-channel
 .PARAMETER Prefix
Sets the IP and netmask of a layer3 port-channel
 .PARAMETER Tag
Configrues a numeric route tag value (0-4294967295) for a layer3 port-channel prefix 
 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Fabric,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$SwitchName,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4096)]
            [int]$ID,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Members,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Access","Monitor","Routed","Trunk")]
            [string]$PortType,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4094)]
            [int]$AccessVLAN,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AllowedVLANs,
            
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$VRF,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern('(\d+\.){3}\d+\/\d+')]
            [string]$Prefix,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(0,4294967295)]
            [string]$Tag,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Active","Passive","On")]
                [string]$Mode="Active",
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
               [string]$BPDUGuard="true",
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
                  [string]$PortFast="true",
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("jumbo","default")]
                [string]$MTU="jumbo",
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
                [string]$Description="",
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
                [string]$Enabled="true",
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$CliFreeform,
         
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {
}
Process {
$uri      = "$Global:DCNMHost/rest/control/policies"
if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}
$nvPairs = New-Object -TypeName psobject
$body    = New-Object -TypeName psobject

if ($PortType -eq 'Monitor') {
    $templateName = 'int_monitor_port_channel_11_1'
    }
if ($PortType -eq 'Access')  {
    $templateName = 'int_port_channel_access_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name ACCESS_VLAN -Value $AccessVLAN
    }
if ($PortType -eq 'Trunk')   {
    $templateName = 'int_port_channel_trunk_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name ALLOWED_VLANS -Value $AllowedVLANs.Replace(' ','')
    }
if ($PortType -eq 'Routed')  {
    $templateName = 'int_l3_port_channel'
    if ($VRF){
    $nvPairs | Add-Member -Type NoteProperty -Name INTF_VRF      -Value $VRF}
    $nvPairs | Add-Member -Type NoteProperty -Name IP            -Value ($Prefix.Split('/')[0])
    $nvPairs | Add-Member -Type NoteProperty -Name PREFIX        -Value ($Prefix.Split('/')[1])
    if ($Tag){
    $nvPairs | Add-Member -Type NoteProperty -Name ROUTING_TAG   -Value $Tag}
    if ($MTU -eq 'default') {[int]$MTU = '1500'} elseif ($MTU -eq 'jumbo') {[int]$MTU = '9216'}     
    }


$nvPairs | Add-Member -Type NoteProperty -Name BPDUGUARD_ENABLED      -Value $BPDUGuard
$nvPairs | Add-Member -Type NoteProperty -Name PC_MODE                -Value $Mode.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name FABRIC_NAME            -Value $Fabric
$nvPairs | Add-Member -Type NoteProperty -Name DESC                   -Value $Description
$nvPairs | Add-Member -Type NoteProperty -Name PORTTYPE_FAST_ENABLED  -Value $PortFast
$nvPairs | Add-Member -Type NoteProperty -Name MTU                    -Value $MTU
$nvPairs | Add-Member -Type NoteProperty -Name MEMBER_INTERFACES      -Value $Members
$nvPairs | Add-Member -Type NoteProperty -Name PO_ID                  -Value "Port-channel$ID"
$nvPairs | Add-Member -Type NoteProperty -Name ADMIN_STATE            -Value $Enabled.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name CONF                   -Value $CliFreeform




$body | Add-Member -Type NoteProperty -Name serialNumber        -Value (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $SwitchName).serialNumber)
$body | Add-Member -Type NoteProperty -name entityType          -Value 'INTERFACE'
$body | Add-Member -Type NoteProperty -name entityName          -Value "port-channel$ID"
$body | Add-Member -Type NoteProperty -name templateName        -Value $templateName
$body | Add-Member -Type NoteProperty -name templateContentType -Value 'PYTHON'
$body | Add-Member -Type NoteProperty -name nvPairs             -Value $nvPairs

    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
    
Remove-Variable -Name BPDUGuard,Mode,Fabric,Description,PortFast,MTU,Members,Enabled     -ErrorAction SilentlyContinue
Remove-Variable -Name VRF,Prefix,Tag,AllowedVLANs,AccessVLAN                             -ErrorAction SilentlyContinue
Remove-Variable -Name ID,templateName,nvPairs,body                                       -ErrorAction SilentlyContinue
}    

End     {}
 
}
function New-DCNMSubinterface        {
    <#
 .SYNOPSIS
Creates a new subinterface interface
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM API Control - Policies
 .EXAMPLE
New-DCNMSubinterface -Fabric TST -SwitchName LEAF-1 -ParentInterface port-channel502 -SubinterfaceID 2011 -VlanID 2011 -Prefix 30.30.30.1/30
 .EXAMPLE
Import-Csv .\Book2.csv | New-DCNMSubinterface
 .EXAMPLE
New-DCNMSubinterface -Fabric TST -SwitchName LEAF-1 -ParentInterface port-channel333 -SubinterfaceID 33 -VlanID 33 -Prefix 33.33.33.1/24 -CliFreeform @"
>> ip ospf network point-to-point
>> delay 13131
>> ip ospf cost 1414
>> "@
 .PARAMETER Fabric
Name of the fabric
 .PARAMETER SwitchName
Name of the switch to create the subinterface on
 .PARAMETER ParentInterface
Parent interface for the subinterface
 .PARAMETER SubinterfaceID
Subinterface number
 .PARAMETER VlanID
Set the dot1q VLAN ID
 .PARAMETER Prefix
Configure an IPv4 address and length
 .PARAMETER IPv6Prefix
Configure an IPv6 address and length
 .PARAMETER VRF
Sets the VRF of a layer3 subinterface
 .PARAMETER MTU
Sets either the default (1500) MTU size, or jumbo frame MTU (9216)
 .PARAMETER Description
Interface description
 .PARAMETER Enabled
Enable or disable interface after creation
 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Fabric,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$SwitchName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$ParentInterface,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4093)]
            [int]$SubinterfaceID,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,3967)]
            [int]$VlanID,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern('(\d+\.){3}\d+\/\d+')]
            [string]$Prefix,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$IPv6Prefix,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='Layer3')]
            [string]$VRF,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("jumbo","default")]
            [string]$MTU="jumbo",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
            [string]$Enabled="true",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$CliFreeform,
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {}
Process {
$uri      = "$Global:DCNMHost/rest/control/policies"
if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}
$nvPairs    = New-Object -TypeName psobject
$body       = New-Object -TypeName psobject

if ($MTU -eq 'default') {[int]$MTU = '1500'} elseif ($MTU -eq 'jumbo') {[int]$MTU = '9216'}     

if ($IPv6Prefix){
$nvPairs | Add-Member -Type NoteProperty -Name IPv6                   -Value ($IPv6Prefix.Split('/')[0])
$nvPairs | Add-Member -Type NoteProperty -Name IPv6_PREFIX            -Value ($IPv6Prefix.Split('/')[1])}
if ($Prefix){
$nvPairs | Add-Member -Type NoteProperty -Name IP                     -Value ($Prefix.Split('/')[0])
$nvPairs | Add-Member -Type NoteProperty -Name PREFIX                 -Value ($Prefix.Split('/')[1])}
$nvPairs | Add-Member -Type NoteProperty -Name VLAN                   -Value $VlanID
$nvPairs | Add-Member -Type NoteProperty -Name FABRIC_NAME            -Value $Fabric
$nvPairs | Add-Member -Type NoteProperty -Name DESC                   -Value $Description
$nvPairs | Add-Member -Type NoteProperty -Name INTF_NAME              -Value ($ParentInterface + '.' + $SubinterfaceID)
$nvPairs | Add-Member -Type NoteProperty -Name MTU                    -Value $MTU
$nvPairs | Add-Member -Type NoteProperty -Name ADMIN_STATE            -Value $Enabled.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name INTF_VRF               -Value $VRF
$nvPairs | Add-Member -Type NoteProperty -Name CONF                   -Value $CliFreeform

$body | Add-Member -Type NoteProperty -Name serialNumber        -Value (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $SwitchName).serialNumber)
$body | Add-Member -Type NoteProperty -name entityType          -Value 'INTERFACE'
$body | Add-Member -Type NoteProperty -name entityName          -Value ($ParentInterface + '.' + $SubinterfaceID)
$body | Add-Member -Type NoteProperty -name templateName        -Value 'int_subif_11_1'
$body | Add-Member -Type NoteProperty -name templateContentType -Value 'PYTHON'
$body | Add-Member -Type NoteProperty -name nvPairs             -Value $nvPairs

    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}

Remove-Variable nvPairs,body,IPv6Prefix,Prefix,VlanID,Fabric,description,ParentInterface,subinterface,MTU,Enable -ErrorAction SilentlyContinue
}    

End     {}
 
}
function Get-DCNMSwitchPolicy        {
    <#
 .SYNOPSIS
Retrieve a policies applied to switches
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Control - Policies
 .EXAMPLE

 .EXAMPLE

 .PARAMETER Fabric

 .PARAMETER Name

 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$serialNumber,
            [Parameter(Mandatory=$false, ValueFromPipeline=$false)]
            [string]$Description="*"
    )
Begin   {
$response=@()
}
Process {
$uri = "$Global:DCNMHost/rest/control/policies/switches/$serialNumber"
$response += Get-DCNMObject -uri $uri | Where-Object {($_.nvPairs.POLICY_DESC -like "$Description") -or ($_.description -like "$Description")}
        }
End     {
$response
        }
}
function Remove-DCNMPolicy           {
    <#
 .SYNOPSIS
Remove a policies
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Control - Policies
 .EXAMPLE
Remove-DCNMPolicy -policyId POLICY-245910
 .EXAMPLE
Get-DCNMSwitch -fabricName site1 -SwitchName LEAF-1 | Get-DCNMSwitchPolicy | ? {$_.deleted -eq $true} | Remove-DCNMPolicy -Purge
 .PARAMETER Fabric

 .PARAMETER Name

 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
            [string]$policyId,
            [Parameter(Mandatory=$false)]
            [switch]$Purge
    )
Begin   {
$response=@()}
Process {
   if ($Purge) {
                $uri = "$Global:DCNMHost/rest/control/policies/$policyId"
                $response += Remove-DCNMObject -uri $uri} else {
                $uri = "$Global:DCNMHost/rest/control/policies/$policyId/mark-delete"
                $response += Set-DCNMObject -uri $uri
               } 
              }
End     {
$response
        }
}

function New-DCNMNetwork           {
    <#
 .SYNOPSIS
Creates a network in a fabric
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM Top Down LAN Network Operations API
 .EXAMPLE
New-DCNMNetwork -Fabric site1 -vrf myVRF1 -Name myNetwork1 -VNI 30001 -VlanID -VlanName test -GatewayIPv4 '10.10.10.1' 
 .EXAMPLE
(Import-Csv .\Book2.csv) | New-DCNMNetwork
 .PARAMETER Fabric
Fabric name
 .PARAMETER Name
Network name
 .PARAMETER VNI
VNI number
 .PARAMETER GatewayIPv4
IPv4 gateway address
 .PARAMETER GatewayIPv6
IPv6 gateway address
 .PARAMETER VlanName
VLAN name 
 .PARAMETER Description
Interface description for gateway SVI
 .PARAMETER MTU
MTU size for gateway SVI (68-9216)
 .PARAMETER SecondaryGW1
Primary IP for gateway SVI
 .PARAMETER SecondaryGW2
Secondary IP for gateway SVI
 .PARAMETER SuppressARP
Enable ARP suppression; true or false
 .PARAMETER RTBothAuto
Use route-target both in configuration profile
 .PARAMETER EnableL3onBorder
Create gateway SVI on border leaf switches; true or false
 .PARAMETER DhcpServer1
First DHCP server
 .PARAMETER DhcpServer2
Second DHCP server
 .PARAMETER DhcpVRF
VRF of DHCP relay source
 .PARAMETER DhcpLoopbackID
Loopback ID for DHCP relay source (0-1023)
 .PARAMETER Tag
Route tag for the gateway subnet
 .PARAMETER IsLayer2Only
Specify network is L2; will not create a gateway
 .PARAMETER IR
Enable Ingress Replication; true or false
 .PARAMETER TRM
Enable Tenent Routed Multicast; true or false
 .PARAMETER VlanID
VLAN ID to be associated with VNI or L3 SVI
 .PARAMETER MulticastGroup
Multicast group address for BUM traffic
 /#>
param
    (
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Fabric,
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Name,            
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [int]$VNI,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$GatewayIPv4,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$GatewayIPv6,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$VlanName,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$Description,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(68,9216)]
        [int]$MTU=9216,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$SecondaryGW1,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$SecondaryGW2,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$SuppressARP="false",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$RTBothAuto="false",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$EnableL3onBorder="false",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$DhcpServer1,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$DhcpServer2,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$DhcpVRF,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$DhcpLoopbackID,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(0,4294967295)]
        [int]$Tag=12345,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$VRF,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$MulticastGroup,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$IsLayer2Only="false",  
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$IR="false",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$TRM="false",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(2,3967)]
        [int]$VlanID,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$networkTemplate="Default_Network_Universal",
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$networkExtensionTemplate="Default_Network_Extension_Universal",
    [Parameter(Mandatory=$false, DontShow)]
        [switch]$JSON
    )
Begin   {
$response=@()
$uri    = "$Global:DCNMHost/rest/top-down/bulk-create/networks"
$body   =@()
}
Process {
    if ($IsLayer2Only -eq 'true') {$VRF = 'NA'}

    $netconfig  = @()
    $netconfig += "`"gatewayIpAddress`":`"$GatewayIPv4`","
    $netconfig += "`"gatewayIpV6Address`":`"$GatewayIPv6`","
    $netconfig += "`"vlanName`":`"$VlanName`","
    $netconfig += "`"intfDescription`":`"$Description`","
    $netconfig += "`"mtu`":`"$MTU`","
    $netconfig += "`"secondaryGW1`":`"$SecondaryGW1`","
    $netconfig += "`"secondaryGW2`":`"$SecondaryGW2`","
    $netconfig += "`"suppressArp`":$SuppressARP,"
    $netconfig += "`"enableIR`":$IR,"
    $netconfig += "`"trmEnabled`":$TRM,"
    $netconfig += "`"rtBothAuto`":$RTBothAuto,"
    $netconfig += "`"enableL3OnBorder`":$EnableL3onBorder,"
    $netconfig += "`"mcastGroup`":`"$MulticastGroup`","
    $netconfig += "`"dhcpServerAddr1`":`"$DhcpServer1`","
    $netconfig += "`"dhcpServerAddr2`":`"$DhcpServer2`","
    $netconfig += "`"vrfDhcp`":`"$DhcpVRF`","
    $netconfig += "`"loopbackId`":`"$DhcpLoopbackID`","
    $netconfig += "`"tag`":`"$tag`","
    $netconfig += "`"vrfName`":`"$VRF`","
    $netconfig += "`"isLayer2Only`":$IsLayer2Only,"
    $netconfig += "`"nveId`":1,"
    $netconfig += "`"vlanId`":`"$VlanID`","
    $netconfig += "`"segmentId`":`"$VNI`","
    $netconfig += "`"networkName`":`"$name`""
    $netconfig  = $netconfig -join ''

    $LanNet = New-Object -TypeName psobject
    $LanNet | Add-Member -Type NoteProperty -Name 'fabric'                      -Value $Fabric
    $LanNet | Add-Member -Type NoteProperty -Name 'vrf'                         -Value $VRF
    $LanNet | Add-Member -Type NoteProperty -Name 'networkName'                 -Value $Name
    $LanNet | Add-Member -Type NoteProperty -Name 'displayName'                 -Value $Name
    $LanNet | Add-Member -Type NoteProperty -Name 'networkId'                   -Value "$VNI"
    $LanNet | Add-Member -Type NoteProperty -Name 'networkTemplateConfig'       -Value "`{$netconfig`}"
    $LanNet | Add-Member -Type NoteProperty -Name 'networkTemplate'             -Value $networkTemplate
    $LanNet | Add-Member -Type NoteProperty -Name 'networkExtensionTemplate'    -Value $networkExtensionTemplate
    $LanNet | Add-Member -Type NoteProperty -Name 'source'                      -Value $null
    $LanNet | Add-Member -Type NoteProperty -Name 'serviceNetworkTemplate'      -Value $null

    $body += $LanNet
        }
End     {
    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
        }
}
function New-DCNMvPC         {
    <#
 .SYNOPSIS
Creates a new virtual port-channel interface
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM API Control - Policies
 .EXAMPLE
New-DCNMvPC -Fabric site3 -Switch1 leaf-8 -Switch2 leaf-9 -ID 66 -MembersSwitch1 eth1/4-6 -MembersSwitch2 eth1/4-6 -Mode Passive -PortType trunk -BPDUGuard true -PortFast true -MTU default -Peer1Description "to some server e1/1" -Peer2Description "to some server e1/2" -AllowedVLANs 55-66
 .EXAMPLE
(Import-Csv .\Book2.csv)[2..4] | New-DCNMvPC
 .PARAMETER Fabric
Name of the fabric
 .PARAMETER Switch1
Name of first peer in vPC
 .PARAMETER Switch2
Name of second peer in vPC
 .PARAMETER ID
Port-channel identifier
 .PARAMETER MembersSwitch1
Member interfaces on first peer
 .PARAMETER MembersSwitch2
Member interfaces on second peer
 .PARAMETER Mode
Operating mode of the port-channel (Active, Passive, On)
 .PARAMETER PortType
Trunk/Access port
 .PARAMETER BPDUGuard
Enables or disabled the BPDU Guard feature on port-channel
 .PARAMETER PortFast
Enables or disabled the portfast feature on port-channel
 .PARAMETER MTU
Sets either the default (1500) MTU size, or jumbo frame MTU (9216)
 .PARAMETER Peer1Description
Port-channel interface description on first peer
 .PARAMETER Peer2Description
Port-channel interface description on second peer
 .PARAMETER AccessVLAN
Sets the access port VLAN for an access port-channel
 .PARAMETER AllowedVLANs
Configures allowed VLAN list for trunk port-channels.
Options include "all", "none", ranges, or comma-separated values
 .PARAMETER Enabled
Enable or disable interface after creation
 .PARAMETER Peer1CliFreeform
CLI freeform configuration for port-channel on first peer
 .PARAMETER Peer2CliFreeform
CLI freeform configuration for port-channel on second peer
 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Fabric,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Switch1,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Switch2,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4096)]
            [int]$ID,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$MembersSwitch1,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$MembersSwitch2,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Active","Passive","On")]
            [string]$Mode="Active",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Access","Trunk")]
            [string]$PortType,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
           [string]$BPDUGuard="true",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
              [string]$PortFast="true",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("jumbo","default")]
            [string]$MTU="jumbo",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Peer1Description="",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Peer2Description="",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4094)]
            [int]$AccessVLAN,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='Trunk')]
            [string]$AllowedVLANs,
            
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Peer1CliFreeform="",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Peer2CliFreeform="",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
            [string]$Enabled="true",
             
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {
}
Process {
$uri      = "$Global:DCNMHost/rest/globalInterface"
if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}
$nvPairs = New-Object -TypeName psobject
$int     = New-Object -TypeName psobject
$body    = New-Object -TypeName psobject

$nvPairs | Add-Member -Type NoteProperty -Name PEER1_PCID                   -Value $ID
$nvPairs | Add-Member -Type NoteProperty -Name PEER2_PCID                   -Value $ID
$nvPairs | Add-Member -Type NoteProperty -Name PEER1_MEMBER_INTERFACES      -Value $MembersSwitch1
$nvPairs | Add-Member -Type NoteProperty -Name PEER2_MEMBER_INTERFACES      -Value $MembersSwitch2
$nvPairs | Add-Member -Type NoteProperty -Name PC_MODE                      -Value $Mode.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name BPDUGUARD_ENABLED            -Value $BPDUGuard.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name PORTTYPE_FAST_ENABLED        -Value $PortFast.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name MTU                          -Value $MTU.ToLower()


if ($PortType -eq 'Access')  {
    $templateName = 'int_vpc_access_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name PEER1_ACCESS_VLAN -Value $AccessVLAN
    $nvPairs | Add-Member -Type NoteProperty -Name PEER2_ACCESS_VLAN -Value $AccessVLAN
    }
if ($PortType -eq 'Trunk')   {
    $templateName = 'int_vpc_trunk_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name PEER1_ALLOWED_VLANS -Value $AllowedVLANs.Replace(' ','')
    $nvPairs | Add-Member -Type NoteProperty -Name PEER2_ALLOWED_VLANS -Value $AllowedVLANs.Replace(' ','')
    }

$nvPairs | Add-Member -Type NoteProperty -Name PEER1_PO_DESC           -Value $Peer1Description
$nvPairs | Add-Member -Type NoteProperty -Name PEER2_PO_DESC           -Value $Peer2Description
$nvPairs | Add-Member -Type NoteProperty -Name PEER1_PO_CONF           -Value $Peer1CliFreeform
$nvPairs | Add-Member -Type NoteProperty -Name PEER2_PO_CONF           -Value $Peer2CliFreeform
$nvPairs | Add-Member -Type NoteProperty -Name ADMIN_STATE             -Value $Enabled.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name INTF_NAME               -Value "vPC$ID"

$Sw1sn = (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $Switch1).serialNumber)
$Sw2sn = (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $Switch2).serialNumber)

$int      | Add-Member -Type NoteProperty -Name serialNumber  -Value "$Sw1sn~$Sw2sn"
$int      | Add-Member -Type NoteProperty -Name interfaceType -Value 'INTERFACE_VPC'
$int      | Add-Member -Type NoteProperty -Name ifName        -Value "vPC$ID"
$int      | Add-Member -Type NoteProperty -Name fabricName    -Value $Fabric
$int      | Add-Member -Type NoteProperty -Name nvPairs       -Value $nvPairs
$ifs  = @()
$ifs += $int


$body | Add-Member -Type NoteProperty -name policy           -Value $templateName
$body | Add-Member -Type NoteProperty -name interfaceType    -Value 'INTERFACE_VPC'
$body | Add-Member -Type NoteProperty -Name interfaces       -Value $ifs


    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
    
Remove-Variable -Name int,ifs,nvpairs,body -ErrorAction SilentlyContinue
}    

End     {}
 
}

function Set-DCNMInterfaceAdminState         {
    <#
 .SYNOPSIS
Perform a shutdown/no shutdonw on interfaces
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM Interface adminstatus
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName SPINE-4 -Interface ethernet1/19 -Enabled false
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName LEAF-12 -Interface vlan100 -Enabled true
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName AG-2 -Interface vlan100,vlan200,eth1/100 -Enabled false
 .PARAMETER Fabric
Name of the fabric
 .PARAMETER SwitchName
Name of the switch
 .PARAMETER Interface
Full interface name
 .PARAMETER Enabled
Enables or disables the interfaces; true or false
 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("fabricName")]
            [string]$Fabric,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("sysName","logicalName")]
            [string]$SwitchName,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("ifName")]
            [string]$Interface,

        [Parameter(Mandatory=$false)]
        [ValidateSet("true","false")]
            [string]$Enabled,

        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {
    $ifShut = @()
    $ifNoSh = @()
}
Process {

    $uri      = "$Global:DCNMHost/rest/interface/adminstatus"
    if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric}
    $serial = ((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $SwitchName).serialNumber
    [string]$Interface = $Interface.Split(',')
    foreach ($i in $Interface) {
        $i = $i.ToLower().Replace('eth','ethernet')
        $ifName = New-Object -TypeName psobject
        $ifName | Add-Member -Type NoteProperty -Name serialNumber  -Value $serial
        $ifName | Add-Member -Type NoteProperty -Name ifName        -Value $i
        if ($Enabled -eq 'true')  {$ifNoSh += $ifName}
        if ($Enabled -eq 'false') {$ifShut += $ifName}

 }
}    

End     {

    if ($ifNoSh) {
        $body = New-Object -TypeName psobject
        $body | Add-Member -Type NoteProperty -Name operation  -Value noshut
        $body | Add-Member -Type NoteProperty -Name interfaces -Value $ifNosh
        if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
            $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
    }
    if ($ifShut) {
        $body = New-Object -TypeName psobject
        $body | Add-Member -Type NoteProperty -Name operation  -Value shut
        $body | Add-Member -Type NoteProperty -Name interfaces -Value $ifShut
        if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
            $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
    }

}
 
}
