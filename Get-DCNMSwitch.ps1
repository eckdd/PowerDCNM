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
        [Parameter(Mandatory=$false)]
        [ValidateSet("Spine","Leaf","Border","Border Spine","Border Gateway","Border Gateway Spine","Super Spine","Border Super Spine","Border Gateway Super Spine","Access","Aggregation","Edge Router","Core Router","ToR","*")]
            [string]$SwitchRole="*",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$fabricName
    )
Begin   {}
Process {
$uri = "$Global:DCNMHost/rest/control/fabrics/$FabricName/inventory"
$response = Get-DCNMObject -uri $uri
$response | Where-Object {($_.switchName -like $SwitchName -and $_.switchRole -like $SwitchRole.ToLower())}
        }
End     {
if ($response) {New-Variable -Scope Global -Name DCNMSwitch_$fabricName -Value $response -Force}
        }
}