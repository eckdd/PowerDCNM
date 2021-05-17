function Deploy-DCNMFabric           {
    <#
 .SYNOPSIS
Executes a command on switches
 .DESCRIPTION
This cmdlet will invoke a REST POST against Config Deployer API using the exec_freeform template
 .EXAMPLE
Get-DCNMSwitch -Fabric DC1 -SwitchRole Leaf | Invoke-DCNMCliCommand -CliFreeform "show nve peers"
 .PARAMETER serialNumber
Serial number of switch(es)
 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$serialNumber,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
            [string]$CliFreeform,
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {
    $uri  = "$Global:DCNMHost/rest/config/delivery/exec_freeform/exec"
    $deviceList = @()
}
Process {
    $deviceList += $serialNumber
        }
End     {
    $cli  = New-Object -Type [PSCustomObject]@{
        CLI = $CliFreeform
    }
    $body = New-Object -Type [PSCustomObject]@{
        deviceList      = $deviceList
        paramValueMap   = $cli
    }

    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
}
}