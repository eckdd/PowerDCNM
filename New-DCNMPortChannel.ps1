function New-DCNMPortChannel         {
    <#
 .SYNOPSIS
Creates a new port-channel interface
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM API Control - Policies
 .EXAMPLE
New-DCNMPortChannel -Fabric TST -SwitchName LEAF-1 -ID 300 -Members Eth1/10-14 -Mode Active -BPDUGuard true -PortFast true -MTU default -Description Server1 -Enabled true -Access -AccessVLAN 10
 .EXAMPLE
New-DCNMPortChannel -Fabric TST -SwitchName LEAF-1 -ID 301 -Members Eth1/20-24 -Mode Passive -BPDUGuard false -PortFast false -MTU jumbo -Description Switch1 -Enabled true -Trunk -AllowedVLANs '100,200,300-310'
 .EXAMPLE
New-DCNMPortChannel -Fabric TST -SwitchName Leaf-1 -ID 302 -Members Eth1/50-54 -Mode On -BPDUGuard true -PortFast true -MTU default -Description Firewall1 -Enabled true -Layer3 -VRF PROD -Prefix 10.100.30.1/24 -Tag 100
 .EXAMPLE
(Import-Csv .\Book2.csv)[2..4] | New-DCNMPortChannel -Access
 .PARAMETER Fabric
Name of the fabric
 .PARAMETER SwitchName
Name of the switch to create the port-channel on
 .PARAMETER ID
Port-channel identifier
 .PARAMETER Members
Member interfaces 
 .PARAMETER Mode
Operating mode of the port-channel (Active, Passive, On)
 .PARAMETER BPDUGuard
Enables or disabled the BPDU Guard feature on port-channel
 .PARAMETER PortFast
Enables or disabled the portfast feature on port-channel
 .PARAMETER MTU
Sets either the default (1500) MTU size, or jumbo frame MTU (9216)
 .PARAMETER Description
Interface description
 .PARAMETER Enabled
Enable or disable interface after creation
 .PARAMETER PortType
Configure port as access, trunk, or routed
 .PARAMETER AccessVLAN
Sets the access port VLAN for an access port-channel
 .PARAMETER AllowedVLANs
Configures allowed VLAN list for trunk port-channels.
Options include "all", "none", ranges, or comma-separated values
 .PARAMETER VRF
Sets the VRF of a layer3 port-channel
 .PARAMETER Prefix
Sets the IP and netmask of a layer3 port-channel
 .PARAMETER Tag
Configrues a numeric route tag value (0-4294967295) for a layer3 port-channel prefix 
 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Fabric,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$SwitchName,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4096)]
            [int]$ID,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Members,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Access","Monitor","Routed","Trunk")]
            [string]$PortType,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4094)]
            [int]$AccessVLAN,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AllowedVLANs,
            
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$VRF,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern('(\d+\.){3}\d+\/\d+')]
            [string]$Prefix,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(0,4294967295)]
            [string]$Tag,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Active","Passive","On")]
                [string]$Mode="Active",
    
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
                [string]$Description="",
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
                [string]$Enabled="true",
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$CliFreeform,
         
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {
}
Process {
$uri      = "$Global:DCNMHost/rest/control/policies"
[string]$PortFast  = $PortFast.ToLower()

if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}
$nvPairs = New-Object -TypeName psobject
$body    = New-Object -TypeName psobject

if ($PortType -eq 'Monitor') {
    $templateName = 'int_monitor_port_channel_11_1'
    }
if ($PortType -eq 'Access')  {
    $templateName = 'int_port_channel_access_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name ACCESS_VLAN -Value $AccessVLAN
    }
if ($PortType -eq 'Trunk')   {
    $templateName = 'int_port_channel_trunk_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name ALLOWED_VLANS -Value $AllowedVLANs.Replace(' ','')
    }
if ($PortType -eq 'Routed')  {
    $templateName = 'int_l3_port_channel'
    if ($VRF){
    $nvPairs | Add-Member -Type NoteProperty -Name INTF_VRF      -Value $VRF}
    $nvPairs | Add-Member -Type NoteProperty -Name IP            -Value ($Prefix.Split('/')[0])
    $nvPairs | Add-Member -Type NoteProperty -Name PREFIX        -Value ($Prefix.Split('/')[1])
    if ($Tag){
    $nvPairs | Add-Member -Type NoteProperty -Name ROUTING_TAG   -Value $Tag}
    if ($MTU -eq 'default') {[int]$MTU = '1500'} elseif ($MTU -eq 'jumbo') {[int]$MTU = '9216'}     
    }


$nvPairs | Add-Member -Type NoteProperty -Name BPDUGUARD_ENABLED      -Value $BPDUGuard
$nvPairs | Add-Member -Type NoteProperty -Name PC_MODE                -Value $Mode.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name FABRIC_NAME            -Value $Fabric
$nvPairs | Add-Member -Type NoteProperty -Name DESC                   -Value $Description
$nvPairs | Add-Member -Type NoteProperty -Name PORTTYPE_FAST_ENABLED  -Value $PortFast
$nvPairs | Add-Member -Type NoteProperty -Name MTU                    -Value $MTU
$nvPairs | Add-Member -Type NoteProperty -Name MEMBER_INTERFACES      -Value $Members
$nvPairs | Add-Member -Type NoteProperty -Name PO_ID                  -Value "Port-channel$ID"
$nvPairs | Add-Member -Type NoteProperty -Name ADMIN_STATE            -Value $Enabled.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name CONF                   -Value $CliFreeform




$body | Add-Member -Type NoteProperty -Name serialNumber        -Value (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $SwitchName).serialNumber)
$body | Add-Member -Type NoteProperty -name entityType          -Value 'INTERFACE'
$body | Add-Member -Type NoteProperty -name entityName          -Value "port-channel$ID"
$body | Add-Member -Type NoteProperty -name templateName        -Value $templateName
$body | Add-Member -Type NoteProperty -name templateContentType -Value 'PYTHON'
$body | Add-Member -Type NoteProperty -name nvPairs             -Value $nvPairs

    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
    
Remove-Variable -Name BPDUGuard,Mode,Fabric,Description,PortFast,MTU,Members,Enabled     -ErrorAction SilentlyContinue
Remove-Variable -Name VRF,Prefix,Tag,AllowedVLANs,AccessVLAN                             -ErrorAction SilentlyContinue
Remove-Variable -Name ID,templateName,nvPairs,body                                       -ErrorAction SilentlyContinue
}    

End     {}
 
}