function Get-DCNMSwitchPolicy        {
    <#
 .SYNOPSIS
Retrieve a policies applied to switches
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Control - Policies
 .EXAMPLE

 .EXAMPLE

 .PARAMETER Fabric

 .PARAMETER Name

 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$serialNumber,
        [Parameter(Mandatory=$false, ValueFromPipeline=$false)]
            [string]$Description="*"
    )
Begin   {
$response=@()
}
Process {
$uri = "$Global:DCNMHost/rest/control/policies/switches/$serialNumber"
$response += Get-DCNMObject -uri $uri | Where-Object {($_.nvPairs.POLICY_DESC -like "$Description") -or ($_.description -like "$Description")}
        }
End     {
$response
        }
}