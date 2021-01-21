function Set-DCNMInterfaceAdminState {
    <#
 .SYNOPSIS
Perform a shutdown/no shutdonw on interfaces
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM Interface adminstatus
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName SPINE-4 -Interface ethernet1/19 -Enabled false
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName LEAF-12 -Interface vlan100 -Enabled true
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName AG-2 -Interface vlan100,vlan200,eth1/100 -Enabled false
 .PARAMETER Fabric
Name of the fabric
 .PARAMETER SwitchName
Name of the switch
 .PARAMETER Interface
Full interface name
 .PARAMETER Enabled
Enables or disables the interfaces; true or false
 /#>
param
    (
        [Parameter(Mandatory=$false)]
        [ValidateSet("true","false")]
            [string]$Enabled,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("fabricName")]
            [string]$Fabric,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("sysName","logicalName")]
            [string]$SwitchName,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias("ifName")]
            [string]$Interface,

        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {
    $ifShut = @()
    $ifNoSh = @()
}
Process {

    $uri      = "$Global:DCNMHost/rest/interface/adminstatus"
    if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}
    $serial = ((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $SwitchName).serialNumber
    [string]$Interface = $Interface.Split(',')
    foreach ($i in $Interface) {
        $i = $i.ToLower().Replace('eth','ethernet')
        $ifName = New-Object -TypeName psobject
        $ifName | Add-Member -Type NoteProperty -Name serialNumber  -Value $serial
        $ifName | Add-Member -Type NoteProperty -Name ifName        -Value $i
        if ($Enabled -eq 'true')  {$ifNoSh += $ifName}
        if ($Enabled -eq 'false') {$ifShut += $ifName}

 }
}    

End     {

    if ($ifNoSh) {
        $body = New-Object -TypeName psobject
        $body | Add-Member -Type NoteProperty -Name operation  -Value noshut
        $body | Add-Member -Type NoteProperty -Name interfaces -Value $ifNosh
        if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
            $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
    }
    if ($ifShut) {
        $body = New-Object -TypeName psobject
        $body | Add-Member -Type NoteProperty -Name operation  -Value shut
        $body | Add-Member -Type NoteProperty -Name interfaces -Value $ifShut
        if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
            $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
    }

}
 
}