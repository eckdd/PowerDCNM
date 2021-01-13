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