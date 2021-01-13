function Get-DCNMPolicy              {
    <#
 .SYNOPSIS
Retrieve a DCNM policy object
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Control - Policies
 .EXAMPLE
Get-DCNMPolicy -Fabric DC1
 .PARAMETER Fabric
Name of Fabic
 .PARAMETER PolicyName
Policy Name
 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias('policyId')]
            [string]$PolicyName,
        [Parameter(Mandatory=$false)]
            [switch]$IntentConfig
    )
Begin   {}
Process {
if ($IntentConfig) {$uri = "$Global:DCNMHost/rest/control/policies/$PolicyName/intent-config"} else {
$uri = "$Global:DCNMHost/rest/control/policies/$PolicyName"}

Get-DCNMObject -uri $uri
        }
End     {}
}