function New-DCNMVlan                 {
    <#
 .SYNOPSIS
Creates a new VLAN
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM policies > bulk-create API
 .EXAMPLE
New-DCNMVlan -Fabric site1 -SwitchName SW-1 -VlanName TEST_VLAN -VlanID 1126
 .EXAMPLE
New-DCNMVlan -Fabric site2 -SwitchName 'Leaf-2,Leaf-3' -VlanName TEST_VLAN2 -VlanID 101 -VNI 30303
 .EXAMPLE
Get-DCNMSwitch -fabricName site3 -SwitchRole Leaf | New-DCNMVlan -VlanName SomeVlan -VlanID 2020 -Mode FabricPath
 .PARAMETER Fabric
Fabric name
 .PARAMETER Name
VLAN name
 .PARAMETER VNI
VNI number
 .PARAMETER Mode
Classic Ethernet (CE) or FabricPath
 /#>
param
    (
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias("fabricName")]
        [string]$Fabric,

    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias("logicalName")]
        [string]$SwitchName,

    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$VlanName,     

    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(2,3967)]
        [int]$VlanID,  
        
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(1,16777214)]
        [int]$VNI,     
            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("CE","FABRICPATH")]
        [string]$VlanMode="CE",     

    [Parameter(Mandatory=$false, DontShow)]
        [switch]$JSON
    )
Begin   {}
Process {
    $response=@()
    $uri        = "$Global:DCNMHost/rest/control/policies/bulk-create"
    $body       =@()
    $nvPairs    =@()
    if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}
    
    $SwitchList = @()
    $SwitchName.Split(',') | ForEach-Object {
        $SwitchList += (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $_).serialNumber)
    }
    $nvPairs = New-Object -TypeName psobject
    $nvPairs | Add-Member -Type NoteProperty -Name 'VLAN'  -Value $VlanId.ToString()
    $nvPairs | Add-Member -Type NoteProperty -Name 'NAME'  -Value $VlanName
    $nvPairs | Add-Member -Type NoteProperty -Name 'MODE'  -Value $VlanMode
    if (!$VNI) {$nvPairs | Add-Member -Type NoteProperty -Name 'VNI'   -Value ''} else {
        $nvPairs | Add-Member -Type NoteProperty -Name 'VNI'   -Value $VNI.ToString()}

    $body = New-Object -TypeName psobject
    $body | Add-Member -Type NoteProperty -Name 'source'        -Value ''
    $body | Add-Member -Type NoteProperty -Name 'serialNumber'  -Value ($SwitchList -join ',')
    $body | Add-Member -Type NoteProperty -Name 'entityType'    -Value "SWITCH"
    $body | Add-Member -Type NoteProperty -Name 'entityName'    -Value "SWITCH"
    $body | Add-Member -Type NoteProperty -Name 'templateName'  -Value "create_vlan"
    $body | Add-Member -Type NoteProperty -Name 'priority'      -Value "500"
    $body | Add-Member -Type NoteProperty -Name 'description'   -Value $VlanName
    $body | Add-Member -Type NoteProperty -Name 'nvPairs'       -Value $nvPairs

    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}

}
End     {}
}
