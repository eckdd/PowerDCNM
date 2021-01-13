function Remove-DCNMPolicy           {
    <#
 .SYNOPSIS
Remove a policies
 .DESCRIPTION
This cmdlet will invoke a REST get against the DCNM API Control - Policies
 .EXAMPLE
Remove-DCNMPolicy -policyId POLICY-245910
 .EXAMPLE
Get-DCNMSwitch -fabricName site1 -SwitchName LEAF-1 | Get-DCNMSwitchPolicy | ? {$_.deleted -eq $true} | Remove-DCNMPolicy -Purge
 .PARAMETER Fabric

 .PARAMETER Name

 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
            [string]$policyId,
        [Parameter(Mandatory=$false)]
            [switch]$Purge
    )
Begin   {
$response=@()}
Process {
   if ($Purge) {
                $uri = "$Global:DCNMHost/rest/control/policies/$policyId"
                $response += Remove-DCNMObject -uri $uri} else {
                $uri = "$Global:DCNMHost/rest/control/policies/$policyId/mark-delete"
                $response += Set-DCNMObject -uri $uri
               } 
              }
End     {
$response
        }
}