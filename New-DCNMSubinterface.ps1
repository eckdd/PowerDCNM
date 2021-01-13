function New-DCNMSubinterface        {
    <#
 .SYNOPSIS
Creates a new subinterface interface
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM API Control - Policies
 .EXAMPLE
New-DCNMSubinterface -Fabric TST -SwitchName LEAF-1 -ParentInterface port-channel502 -SubinterfaceID 2011 -VlanID 2011 -Prefix 30.30.30.1/30
 .EXAMPLE
Import-Csv .\Book2.csv | New-DCNMSubinterface
 .EXAMPLE
New-DCNMSubinterface -Fabric TST -SwitchName LEAF-1 -ParentInterface port-channel333 -SubinterfaceID 33 -VlanID 33 -Prefix 33.33.33.1/24 -CliFreeform @"
>> ip ospf network point-to-point
>> delay 13131
>> ip ospf cost 1414
>> "@
 .PARAMETER Fabric
Name of the fabric
 .PARAMETER SwitchName
Name of the switch to create the subinterface on
 .PARAMETER ParentInterface
Parent interface for the subinterface
 .PARAMETER SubinterfaceID
Subinterface number
 .PARAMETER VlanID
Set the dot1q VLAN ID
 .PARAMETER Prefix
Configure an IPv4 address and length
 .PARAMETER IPv6Prefix
Configure an IPv6 address and length
 .PARAMETER VRF
Sets the VRF of a layer3 subinterface
 .PARAMETER MTU
Sets either the default (1500) MTU size, or jumbo frame MTU (9216)
 .PARAMETER Description
Interface description
 .PARAMETER Enabled
Enable or disable interface after creation
 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Fabric,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$SwitchName,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$ParentInterface,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4093)]
            [int]$SubinterfaceID,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,3967)]
            [int]$VlanID,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern('(\d+\.){3}\d+\/\d+')]
            [string]$Prefix,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$IPv6Prefix,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='Layer3')]
            [string]$VRF,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("jumbo","default")]
            [string]$MTU="jumbo",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
            [string]$Enabled="true",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$CliFreeform,
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {}
Process {
$uri      = "$Global:DCNMHost/rest/control/policies"
if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}
$nvPairs    = New-Object -TypeName psobject
$body       = New-Object -TypeName psobject

if ($MTU -eq 'default') {[int]$MTU = '1500'} elseif ($MTU -eq 'jumbo') {[int]$MTU = '9216'}     

if ($IPv6Prefix){
$nvPairs | Add-Member -Type NoteProperty -Name IPv6                   -Value ($IPv6Prefix.Split('/')[0])
$nvPairs | Add-Member -Type NoteProperty -Name IPv6_PREFIX            -Value ($IPv6Prefix.Split('/')[1])}
if ($Prefix){
$nvPairs | Add-Member -Type NoteProperty -Name IP                     -Value ($Prefix.Split('/')[0])
$nvPairs | Add-Member -Type NoteProperty -Name PREFIX                 -Value ($Prefix.Split('/')[1])}
$nvPairs | Add-Member -Type NoteProperty -Name VLAN                   -Value $VlanID
$nvPairs | Add-Member -Type NoteProperty -Name FABRIC_NAME            -Value $Fabric
$nvPairs | Add-Member -Type NoteProperty -Name DESC                   -Value $Description
$nvPairs | Add-Member -Type NoteProperty -Name INTF_NAME              -Value ($ParentInterface + '.' + $SubinterfaceID)
$nvPairs | Add-Member -Type NoteProperty -Name MTU                    -Value $MTU
$nvPairs | Add-Member -Type NoteProperty -Name ADMIN_STATE            -Value $Enabled.ToLower()
$nvPairs | Add-Member -Type NoteProperty -Name INTF_VRF               -Value $VRF
$nvPairs | Add-Member -Type NoteProperty -Name CONF                   -Value $CliFreeform

$body | Add-Member -Type NoteProperty -Name serialNumber        -Value (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $SwitchName).serialNumber)
$body | Add-Member -Type NoteProperty -name entityType          -Value 'INTERFACE'
$body | Add-Member -Type NoteProperty -name entityName          -Value ($ParentInterface + '.' + $SubinterfaceID)
$body | Add-Member -Type NoteProperty -name templateName        -Value 'int_subif_11_1'
$body | Add-Member -Type NoteProperty -name templateContentType -Value 'PYTHON'
$body | Add-Member -Type NoteProperty -name nvPairs             -Value $nvPairs

    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}

Remove-Variable nvPairs,body,IPv6Prefix,Prefix,VlanID,Fabric,description,ParentInterface,subinterface,MTU,Enable -ErrorAction SilentlyContinue
}    

End     {}
 
}