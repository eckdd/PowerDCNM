function Invoke-DCNMCliCommand              {
    <#
 .SYNOPSIS
Executes a command on switches
 .DESCRIPTION
This cmdlet will invoke a REST POST against Config Deployer API using the exec_freeform template
 .EXAMPLE
Get-DCNMSwitch -Fabric DC1 -SwitchRole Leaf | Invoke-DCNMCliCommand -ExecFreeform "show nve peers"
 .PARAMETER serialNumber
Serial number of switch(es)
 .PARAMETER ExecFreeform
Exec level command line
 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$serialNumber,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$ExecFreeform,
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
    $cli = New-Object -TypeName psobject
    $cli | Add-Member -Type NoteProperty -Name CLI -Value $ExecFreeform

    $body = New-Object -TypeName psobject
    $body | Add-Member -Type NoteProperty -Name deviceList    -Value $deviceList
    $body | Add-Member -Type NoteProperty -Name paramValueMap -Value $cli

    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
        }
}