function Get-DCNMNetworkAttachment    {
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
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("networkName")]
            [string]$Network,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("fabricName")]
            [string]$Fabric
    )
Begin   {}
Process {
$uri = "$Global:DCNMHost/rest/top-down/fabrics/$Fabric/networks/attachments?network-names=$Network"
$response = Get-DCNMObject -uri $uri
        }
End     {
$response.lanAttachList | Where-Object -Property isLanAttached -EQ -Value 'True'
        }
}