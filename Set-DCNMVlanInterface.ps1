function Set-DCNMVlanInterface           {
    <#
 .SYNOPSIS
Modify existing SVIs
 .DESCRIPTION
This cmdlet will invoke a REST PUT against the DCNM API Global Interface
 .EXAMPLE
Set-DCNMVlanInterface -Fabric site3 -SwitchName SPINE-4 -Vlan 2021 -Description SomeNetwork2021 -MTU 1500 -Prefix 30.30.30.30/24 -Tag 76894 -VRF myvrf

# Configure interface vlan 2021, with a description of "SomeNetwork2021", set the MTU to 1500, configure 30.30.30.30/24 as the IP Address
# Set a tag of 76894, and place in the VRF "myvrf"
 .EXAMPLE
Set-DCNMVlanInterface -Fabric site3 -SwitchName LEAF-6 -Vlan 2222 -Prefix 22.22.22.1/24 -CliFreeform @"
>>  bandwidth 101010
>>  delay 40000
>> "@ -Enabled false

# Use the freeform template to create an SVI for VLAN 2222, with an IP address 22.22.22.1 255.255.255.0, and CLI Freeform containing custom b/w & delay values, and create in the SHUTDOWN state
 .EXAMPLE
(Import-Csv .\Book2.csv)[2..4] | Set-DCNMVlanInterface

# Use a CSV file with headers corresponding to parameters to bulk-import interface configurations
 .EXAMPLE
Set-DCNMVlanInterface -Fabric site3 -SwitchName LEAF-6 -Vlan 2222-2322,3333 -Enabled false

# Disable a range of SVIs
 .PARAMETER Fabric
Name of the fabric
 .PARAMETER SwitchName
Name of the switch
 .PARAMETER Vlan
VLAN for the SVI(s) being modified
 .PARAMETER Description
Interface description
 .PARAMETER Enabled
Enables or disables the interfaces; true or false
 .PARAMETER MTU
MTU for SVI
 .PARAMETER VRF
Sets the VRF of a layer3
 .PARAMETER Prefix
Sets the IP and netmask
 .PARAMETER Tag
Configrues a numeric route tag value (0-4294967295) for a layer3 port.
 .PARAMETER HsrpVersion
Set the HSRP version to either 1 or 2.
 .PARAMETER HsrpGroup
Configure the HSRP group number (0-255 if version is set to 1).
 .PARAMETER HsrpVIP
Set the virtual IP for the HSRP group. This may be a prefix if the primary IP differs from the VIP.
 .PARAMETER HsrpPreempt
Configure HSRP preempt feature.
 .PARAMETER HsrpMAC
Set a custom virtual MAC address for the VIP.
 .PARAMETER HsrpPriority
Configure HSPR priority value.
.PARAMETER CliFreeform
Freeform interfaces configuration 
 /#>
param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("fabricName")]
            [string]$Fabric,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("sysName","logicalName")]
            [string]$SwitchName,

        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("ifName")]
            [string]$Vlan,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description="",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [bool]$DisableIPRedirects=$true,
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [bool]$Enabled=$true,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(576,9216)]
            [int]$MTU="9216",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$VRF="",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [AllowNull()] 
        [AllowEmptyCollection()]
        [ValidatePattern('(\d+\.){3}\d+\/\d+')]
            [string]$Prefix,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,2)]
            [string]$HsrpVersion="2",
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(0,4095)]
            [string]$HsrpGroup="",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(0,255)]
            [string]$HsrpPriority="",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidatePattern('([0-9a-fA-F]{4}\.){2}([0-9a-fA-F]{4})')]
            [string]$HsrpMAC="",
    
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [AllowNull()] 
        [AllowEmptyCollection()]
        [ValidatePattern('(\d+\.){3}\d+\/\d+|(\d+\.){3}\d+')]
            [string]$HsrpVIP,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [bool]$HsrpPreempt=$true,
            
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(0,4294967295)]
            [string]$Tag="",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$CliFreeform="",
         
        [Parameter(Mandatory=$false, DontShow)]
            [switch]$JSON
    )
Begin   {
}
Process {
  
$uri      = "$Global:DCNMHost/rest/globalInterface"
if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}


[array]$vlan  = $vlan.Split(',')
[array]$vlans = @()
foreach ($v in $Vlan) {
    if ($v -match '^\d+$') {$vlans += $v} elseif ($v -match '^\d+\-\d+$') {
        $v.Split('-')[0]..$v.Split('-')[1] | ForEach-Object {$vlans += $_}
    }
}

foreach ($i in $vlans) {
    $ifName = New-Object -TypeName psobject
    $ifName | Add-Member -Type NoteProperty -Name serialNumber  -Value $serial
    $ifName | Add-Member -Type NoteProperty -Name ifName        -Value $i
    if ($Enabled -eq 'true')  {$ifNoSh += $ifName}
    if ($Enabled -eq 'false') {$ifShut += $ifName}

}

$nvPairs = New-Object -TypeName psobject
$nvPairs | Add-Member -Type NoteProperty -Name INTF_VRF                 -Value $VRF
$nvPairs | Add-Member -Type NoteProperty -Name IP                       -Value ($Prefix.Split('/')[0])
$nvPairs | Add-Member -Type NoteProperty -Name PREFIX                   -Value ($Prefix.Split('/')[1])
$nvPairs | Add-Member -Type NoteProperty -Name MTU                      -Value $MTU.ToString()
$nvPairs | Add-Member -Type NoteProperty -Name ROUTING_TAG              -Value $Tag.ToString()
$nvPairs | Add-Member -Type NoteProperty -Name DISABLE_IP_REDIRECTS     -Value $DisableIPRedirects
$nvPairs | Add-Member -Type NoteProperty -Name DESC                     -Value $Description
$nvPairs | Add-Member -Type NoteProperty -Name CONF                     -Value $CliFreeform
$nvPairs | Add-Member -Type NoteProperty -Name ADMIN_STATE              -Value $Enabled

if (!$HsrpGroup) {$nvPairs | Add-Member -Type NoteProperty -Name ENABLE_HSRP                    -Value $false}
if ($HsrpGroup)  {
    $nvPairs | Add-Member -Type NoteProperty -Name ENABLE_HSRP                    -Value $true
    $nvPairs | Add-Member -Type NoteProperty -Name PREEMPT                        -Value $HsrpPreempt
    $nvPairs | Add-Member -Type NoteProperty -Name HSRP_VIP                       -Value $HsrpVIP
    $nvPairs | Add-Member -Type NoteProperty -Name HSRP_GROUP                     -Value $HsrpGroup
    $nvPairs | Add-Member -Type NoteProperty -Name HSRP_VERSION                   -Value $HsrpVersion
    $nvPairs | Add-Member -Type NoteProperty -Name HSRP_PRIORITY                  -Value $HsrpPriority
    $nvPairs | Add-Member -Type NoteProperty -Name MAC                            -Value $HsrpMAC
    }

$nvPairs | Add-Member -Type NoteProperty -Name INTF_NAME                -Value ("vlan"+$vlan)

$int = New-Object -TypeName psobject
$int | Add-Member -Type NoteProperty -Name serialNumber        -Value (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $SwitchName).serialNumber)
$int | Add-Member -Type NoteProperty -name interfaceType       -Value 'INTERFACE_VLAN'
$int | Add-Member -Type NoteProperty -name ifName              -Value ("vlan"+$vlan)
$int | Add-Member -Type NoteProperty -name fabricName          -Value $Fabric
$nvp = $nvPairs.psobject.copy()
$int | Add-Member -Type NoteProperty -name nvPairs             -Value $nvp
$ints=@()
$ints += $int

$body    = New-Object -TypeName psobject
$body    | Add-Member -Type NoteProperty -Name policy                   -Value 'int_vlan'
$body    | Add-Member -Type NoteProperty -Name interfaceType            -Value 'INTERFACE_VLAN'
$body    | Add-Member -Type NoteProperty -Name interfaces               -Value $ints





    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = set-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}

Remove-Variable -Name nvPairs,body -ErrorAction SilentlyContinue
$calls++
while ($calls -ge 80) {
    Start-Sleep -Seconds 10 
    [int]$calls = 0
    }
}    

End     {}
 
}