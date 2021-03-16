function Push-DCNMPolicy              {
<#
 .SYNOPSIS
Initiates a push of a DCNM policy to the device it is assign to
 .DESCRIPTION
This cmdlet will invoke a REST post against the policies/deploy DCNM API
 .EXAMPLE
Deploy-DCNMPolicy -PolicyID POLICY-212380
 .EXAMPLE
Get-DCNMSwitch -fabricName Access | Get-DCNMSwitchPolicy | ? {$_.templateName -eq "nfm_switch_user"} | Deploy-DCNMPolicy
 .PARAMETER PolicyID
PolicyID
/#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
            [string]$PolicyID,
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {
    $uri  = "$Global:DCNMHost/rest/control/policies/deploy"
    $body = @()
}
      
Process {
    $body += $PolicyID
        }
End     {
    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
        }
}