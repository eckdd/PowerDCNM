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