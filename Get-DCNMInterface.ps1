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