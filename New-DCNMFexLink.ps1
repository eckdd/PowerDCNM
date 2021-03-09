function New-DCNMFexLink         {
    <#
 .SYNOPSIS
Creates downlink configuration for a FEX
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM API Control - Policies
 .EXAMPLE
New-DCNMFexLink -Fabric FAB-1 -Switch SW-3 -PortChannelID 103 -FexID 103 -FexDescription FEX_103 -MemberInterfaces 'eth1/30-31,eth40-41' -MTU jumbo -PortChannelDescription 'Downlink to FEX 103' -Enabled false
 .EXAMPLE
New-DCNMFexLink -Fabric FAB-1 -Switch SW-5 -Switch2 SW-6 -PortChannelID 103 -FexID 103 -FexDescription FEX_103 -MemberInterfaces eth1/30 -MTU jumbo -PortChannelDescription 'Downlink to FEX 103' -Enabled false
 .EXAMPLE
(Import-Csv .\Book2.csv)[2..4] | New-DCNMFexLink 
 .PARAMETER Fabric
Name of the fabric
 .PARAMETER Switch
Name of the first switch (Active-Active) or only switch (Straight-Through) switch
 .PARAMETER Switch2
Name of the second switch in an Active-Active configuration
 .PARAMETER PortChannelID
Port-channel identifier
 .PARAMETER FexID
FEX identifier
 .PARAMETER MemberInterfaces
Member interfaces 
 .PARAMETER MTU
Sets either the default (1500) MTU size, or jumbo frame MTU (9216)
 .PARAMETER FexDescription
FEX configuration description
 .PARAMETER PortChannelDescription
Port-channel interface description
 .PARAMETER Enabled
Enable or disable FEX port-channel after creation
 .PARAMETER CliFreeform
Port-channel interface freeform configuration
 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Fabric,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Switch,
        
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Switch2,
        
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4096)]
            [int]$PortChannelID,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(101,199)]
            [int]$FexID,
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$MemberInterfaces,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("jumbo","default")]
                [string]$MTU="jumbo",
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
                [string]$FexDescription="",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
                [string]$PortChannelDescription="",
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
                [string]$Enabled="true",
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$CliFreeform="",
         
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {}

Process {
$uri      = "$Global:DCNMHost/rest/globalInterface"

if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}
$nvPairs = New-Object -TypeName psobject
$int     = New-Object -TypeName psobject
$body    = New-Object -TypeName psobject

if ($Switch2) {
    $templateName = 'int_port_channel_aa_fex_11_1'
    $FexType      = 'AA_FEX'
    $Sw1sn = (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $Switch).serialNumber)
    $Sw2sn = (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $Switch2).serialNumber)
    $SwSN  = "$Sw1sn~$Sw2sn"
    } else {
    $templateName = 'int_port_channel_fex_11_1'
    $FexType      = 'STRAIGHT_TROUGH_FEX'
    $SwSN  = (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $Switch).serialNumber)
    }

$nvPairs | Add-Member -Type NoteProperty -Name FEX_ID                 -Value $FexID.ToString()
$nvPairs | Add-Member -Type NoteProperty -Name DESC                   -Value $FexDescription
if (!$Switch2) {$nvPairs | Add-Member -Type NoteProperty -Name MEMBER_INTERFACES        -Value $MemberInterfaces}
if ($Switch2)  {$nvPairs | Add-Member -Type NoteProperty -Name PEER1_MEMBER_INTERFACES  -Value $MemberInterfaces}
if ($Switch2)  {$nvPairs | Add-Member -Type NoteProperty -Name PEER2_MEMBER_INTERFACES  -Value $MemberInterfaces}
if (!$Switch2) {$nvPairs | Add-Member -Type NoteProperty -Name PO_ID                    -Value "Port-channel$PortChannelID"}
if ($Switch2)  {$nvPairs | Add-Member -Type NoteProperty -Name PEER1_PCID               -Value $PortChannelID.ToString()}
if ($Switch2)  {$nvPairs | Add-Member -Type NoteProperty -Name PEER2_PCID               -Value $PortChannelID.ToString()}
$nvPairs | Add-Member -Type NoteProperty -Name MTU                    -Value $MTU
if (!$Switch2) {$nvPairs | Add-Member -Type NoteProperty -Name PO_DESC                  -Value $PortChannelDescription}
if ($Switch2)  {$nvPairs | Add-Member -Type NoteProperty -Name PEER1_PO_DESC            -Value $PortChannelDescription}
if ($Switch2)  {$nvPairs | Add-Member -Type NoteProperty -Name PEER2_PO_DESC            -Value $PortChannelDescription}
if (!$Switch2) {$nvPairs | Add-Member -Type NoteProperty -Name CONF                     -Value $CliFreeform}
if ($Switch2)  {$nvPairs | Add-Member -Type NoteProperty -Name PEER1_PO_CONF            -Value $CliFreeform}
if ($Switch2)  {$nvPairs | Add-Member -Type NoteProperty -Name PEER2_PO_CONF            -Value $CliFreeform}

[bool]$Enabled = [System.Convert]::ToBoolean($Enabled)
$nvPairs | Add-Member -Type NoteProperty -Name ADMIN_STATE            -Value $Enabled
if ($Switch2)  {$nvPairs | Add-Member -Type NoteProperty -Name INTF_NAME                -Value "vPC$PortChannelID"}

$int  | Add-Member -Type NoteProperty -Name serialNumber     -Value $SwSN
$int  | Add-Member -Type NoteProperty -Name interfaceType    -Value $FexType
if (!$Switch2) {
    $int  | Add-Member -Type NoteProperty -Name ifName       -Value "Port-channel$PortChannelID"
} else {
    $int  | Add-Member -Type NoteProperty -Name ifName       -Value "vPC$PortChannelID"
}
$int  | Add-Member -Type NoteProperty -Name fabricName       -Value $Fabric
$int  | Add-Member -Type NoteProperty -Name nvPairs          -Value $nvPairs

$ints  = @()
$ints += $int

$body | Add-Member -Type NoteProperty -name policy                  -Value $templateName
$body | Add-Member -Type NoteProperty -name interfaceType           -Value $FexType
$body | Add-Member -Type NoteProperty -name interfaces              -Value $ints
$body | Add-Member -Type NoteProperty -name skipResourceCheck       -Value $false

    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
    
}    

End     {}
 
}