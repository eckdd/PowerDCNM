function New-DCNMvPC                 {
    <#
 .SYNOPSIS
Creates a new virtual port-channel interface
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM API Control - Policies
 .EXAMPLE
New-DCNMvPC -Fabric site3 -Switch1 leaf-8 -Switch2 leaf-9 -ID 66 -MembersSwitch1 eth1/4-6 -MembersSwitch2 eth1/4-6 -Mode Passive -PortType trunk -BPDUGuard true -PortFast true -MTU default -Peer1Description "to some server e1/1" -Peer2Description "to some server e1/2" -AllowedVLANs 55-66
 .EXAMPLE
(Import-Csv .\Book2.csv)[2..4] | New-DCNMvPC
 .PARAMETER Fabric
Name of the fabric
 .PARAMETER Switch1
Name of first peer in vPC
 .PARAMETER Switch2
Name of second peer in vPC
 .PARAMETER ID
Port-channel identifier
 .PARAMETER MembersSwitch1
Member interfaces on first peer
 .PARAMETER MembersSwitch2
Member interfaces on second peer
 .PARAMETER Mode
Operating mode of the port-channel (Active, Passive, On)
 .PARAMETER PortType
Trunk/Access port
 .PARAMETER BPDUGuard
Enables or disabled the BPDU Guard feature on port-channel
 .PARAMETER PortFast
Enables or disabled the portfast feature on port-channel
 .PARAMETER MTU
Sets either the default (1500) MTU size, or jumbo frame MTU (9216)
 .PARAMETER Peer1Description
Port-channel interface description on first peer
 .PARAMETER Peer2Description
Port-channel interface description on second peer
 .PARAMETER AccessVLAN
Sets the access port VLAN for an access port-channel
 .PARAMETER AllowedVLANs
Configures allowed VLAN list for trunk port-channels.
Options include "all", "none", ranges, or comma-separated values
 .PARAMETER Enabled
Enable or disable interface after creation
 .PARAMETER Peer1CliFreeform
CLI freeform configuration for port-channel on first peer
 .PARAMETER Peer2CliFreeform
CLI freeform configuration for port-channel on second peer
 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Fabric,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Switch1,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Switch2,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4096)]
            [int]$ID,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$MembersSwitch1,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$MembersSwitch2,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Active","Passive","On")]
            [string]$Mode="Active",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Access","Trunk")]
            [string]$PortType,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
           [string]$BPDUGuard="true",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
              [string]$PortFast="true",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("jumbo","default")]
            [string]$MTU="jumbo",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Peer1Description="",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Peer2Description="",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4094)]
            [int]$AccessVLAN,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='Trunk')]
            [string]$AllowedVLANs='none',
            
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Peer1CliFreeform="",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Peer2CliFreeform="",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
            [string]$Enabled="true",
             
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {
}
Process {
$uri      = "$Global:DCNMHost/rest/globalInterface"
if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}
$nvPairs = New-Object -TypeName psobject
$int     = New-Object -TypeName psobject
$body    = New-Object -TypeName psobject

$nvPairs | Add-Member -Type NoteProperty -Name PEER1_PCID                   -Value $ID
$nvPairs | Add-Member -Type NoteProperty -Name PEER2_PCID                   -Value $ID
$nvPairs | Add-Member -Type NoteProperty -Name PEER1_MEMBER_INTERFACES      -Value $MembersSwitch1
$nvPairs | Add-Member -Type NoteProperty -Name PEER2_MEMBER_INTERFACES      -Value $MembersSwitch2
$nvPairs | Add-Member -Type NoteProperty -Name PC_MODE                      -Value $Mode.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name BPDUGUARD_ENABLED            -Value $BPDUGuard.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name PORTTYPE_FAST_ENABLED        -Value $PortFast.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name MTU                          -Value $MTU.ToLower()


if ($PortType -eq 'Access')  {
    $templateName = 'int_vpc_access_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name PEER1_ACCESS_VLAN -Value $AccessVLAN
    $nvPairs | Add-Member -Type NoteProperty -Name PEER2_ACCESS_VLAN -Value $AccessVLAN
    }
if ($PortType -eq 'Trunk')   {
    $templateName = 'int_vpc_trunk_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name PEER1_ALLOWED_VLANS -Value $AllowedVLANs.Replace(' ','')
    $nvPairs | Add-Member -Type NoteProperty -Name PEER2_ALLOWED_VLANS -Value $AllowedVLANs.Replace(' ','')
    }

$nvPairs | Add-Member -Type NoteProperty -Name PEER1_PO_DESC           -Value $Peer1Description
$nvPairs | Add-Member -Type NoteProperty -Name PEER2_PO_DESC           -Value $Peer2Description
$nvPairs | Add-Member -Type NoteProperty -Name PEER1_PO_CONF           -Value $Peer1CliFreeform
$nvPairs | Add-Member -Type NoteProperty -Name PEER2_PO_CONF           -Value $Peer2CliFreeform
$nvPairs | Add-Member -Type NoteProperty -Name ADMIN_STATE             -Value $Enabled.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name INTF_NAME               -Value "vPC$ID"

$Sw1sn = (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $Switch1).serialNumber)
$Sw2sn = (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $Switch2).serialNumber)

$int      | Add-Member -Type NoteProperty -Name serialNumber  -Value "$Sw1sn~$Sw2sn"
$int      | Add-Member -Type NoteProperty -Name interfaceType -Value 'INTERFACE_VPC'
$int      | Add-Member -Type NoteProperty -Name ifName        -Value "vPC$ID"
$int      | Add-Member -Type NoteProperty -Name fabricName    -Value $Fabric
$int      | Add-Member -Type NoteProperty -Name nvPairs       -Value $nvPairs
$ifs  = @()
$ifs += $int


$body | Add-Member -Type NoteProperty -name policy           -Value $templateName
$body | Add-Member -Type NoteProperty -name interfaceType    -Value 'INTERFACE_VPC'
$body | Add-Member -Type NoteProperty -Name interfaces       -Value $ifs


    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
    
Remove-Variable -Name int,ifs,nvpairs,body -ErrorAction SilentlyContinue
}    

End     {}
 
}