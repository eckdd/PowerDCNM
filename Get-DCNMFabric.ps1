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
if ($response) {New-Variable -Scope Global -Name DCNMFabrics -Value $response -Force}
        }
End     {
$response | Where-Object -Property fabricName -Like $name
        }
}