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