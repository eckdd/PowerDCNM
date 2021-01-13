function Set-DCNMInterface           {
    <#
 .SYNOPSIS
Configures Ethernet interfaces
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM API Global Interface
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName SPINE-4 -Interface eth1/19 -Description test -Speed 100Gb -Mode Routed -Prefix 30.30.30.30/24 -Tag 76894 -VRF myvrf

# Configure eth1/19 as a routed port, add description of "test", set the speed to 100Gb, configure 30.30.30.30/24 as the IP Address
# Set a tag of 76894, and place in the VRF "myvrf"
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName LEAF-6 -Interface 'eth1/40-45,eth1/50-55,eth1/100' -Mode Access -AccessVLAN 2020

# Configure eth1/40-45,eth1/50-55,eth1/100 as access ports in VLAN 2020
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName LEAF-6 -Interface 'eth1/40-45,eth1/50-55,eth1/100' -Mode Trunk -Enabled true -AllowedVLANs none

# Configure eth1/40-45,eth1/50-55,eth1/100 as trunk ports with no allowed VLANs. 
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName LEAF-6 -Interface 'eth1/101,eth1/105-110' -Mode Freeform -CliFreeform @"
>> description Unnumbered Links
>> no switchport
>> medium p2p
>> ip unnumbered loopback70
>> "@ -Enabled true

# Use the freeform template to create an unnumbered routed interface
 .EXAMPLE
Set-DCNMInterface -Fabric site3 -SwitchName LEAF-6 -Interface eth1/10 -Mode Monitor

# Use the monitor template on eth1/10 to prevent DCNM from enforcing configuration complaince on that interface
 .EXAMPLE
(Import-Csv .\Book2.csv)[2..4] | Set-DCNMInterface

# Use a CSV file with headers corresponding to parameters to bulk-import interface configurations
 .PARAMETER Fabric
Name of the fabric
 .PARAMETER SwitchName
Name of the switch
 .PARAMETER Interface
List of ethernet interfaces. Must begin with eth{slot}/{port} or eth{fex}/{slot}/{port}
 .PARAMETER Description
Interface description
 .PARAMETER Enabled
Enables or disables the interfaces; true or false
 .PARAMETER Freeform
Specifies the freeform template to be used
 .PARAMETER Speed
Interface speed
 .PARAMETER Enabled
Enable or disable interface after creation
 .PARAMETER BPDUGuard
Enables or disables BPDUGuard
 .PARAMETER MTU_L2
MTU for Access or Trunk ports; can be Jumbo (9216) or default (1500)
 .PARAMETER PortFast
Enable/disable spanning-tree port-fast
 .PARAMETER Mode
Specifies whether to use the access, trunk, routed, or monitor template
 .PARAMETER AccessVLAN
Access port VLAN 
 .PARAMETER AllowedVLANs
Configures allowed VLAN list for trunk port-channels.
Options include "all", "none", ranges, or comma-separated values
 .PARAMETER MTU_L3
MTU size for layer-3 ports
 .PARAMETER VRF
Sets the VRF of a layer3
 .PARAMETER Prefix
Sets the IP and netmask
 .PARAMETER Tag
Configrues a numeric route tag value (0-4294967295) for a layer3 port 
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
            [string]$Interface,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$Description="",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
            [string]$Enabled="true",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Auto","100Mb","1Gb","10Gb","25Gb","40Gb","100Gb")]
            [string]$Speed="Auto",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false","no")]
           [string]$BPDUGuard="true",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("jumbo","default")]
            [string]$MTU_L2="jumbo",
   
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("true","false")]
            [string]$PortFast="true",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Access","Trunk","Routed","Freeform","Monitor")]
            [string]$Mode,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,4094)]
            [int]$AccessVLAN,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$AllowedVLANs,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(576,9216)]
            [int]$MTU_L3="9216",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$VRF="",

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [AllowNull()] 
        [AllowEmptyCollection()]
        [ValidatePattern('(\d+\.){3}\d+\/\d+')]
            [string]$Prefix,

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
[string]$Interface = $Interface.ToLower().Replace('ethernet','eth')

    $ifNames = @()
    foreach ($EthMod in $Interface.split('eth', [System.StringSplitOptions]::RemoveEmptyEntries)) {
        if ($EthMod.Split('/')[2]) {
            $fexN = $EthMod.split('/')[0]
            $slot = $EthMod.split('/')[1]
            $port = $EthMod.split('/')[2]
            } else {
            $slot = $EthMod.split('/')[0]
            $port = $EthMod.split('/')[1]
            }
        $port = $port.split(',', [System.StringSplitOptions]::RemoveEmptyEntries)
         foreach ($p in $port) {
            if ($p -match '^\d+$') {
                if ($fexN) {
                    $ifNames += 'Ethernet'+$fexN+'/'+$slot+'/'+$p
                } else {
                $ifNames += 'Ethernet'+$slot+'/'+$p
                }
            } elseif ($p -match '\d+\-\d+') {
                $p = $p.split('-')[0]..$p.split('-')[1]
                $p | ForEach-Object {
                    if ($fexN) {
                        $ifNames += 'Ethernet'+$fexN+'/'+$slot+'/'+$_
                    } else {
                    $ifNames += 'Ethernet'+$slot+'/'+$_
                    }
                }
               } 
        Remove-Variable p,slot,port,fexN -ErrorAction Ignore
            }
    }

if ($ifNames.Length -eq 1) {$MultiEdit = 'false'} else {$MultiEdit = 'true'}
$uri      = "$Global:DCNMHost/rest/globalInterface/pti?isMultiEdit=$MultiEdit"
if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}
$body    = New-Object -TypeName psobject
$nvPairs = New-Object -TypeName psobject
$nvPairs | Add-Member -Type NoteProperty -Name CONF                       -Value $CliFreeform
$nvPairs | Add-Member -Type NoteProperty -Name ADMIN_STATE                -Value $Enabled.ToLower()


if ($Mode -eq 'Access')  {
    $body    | Add-Member -Type NoteProperty -Name policy                   -Value 'int_access_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name SPEED                    -Value $Speed
    $nvPairs | Add-Member -Type NoteProperty -Name DESC                     -Value $Description
    $nvPairs | Add-Member -Type NoteProperty -Name BPDUGUARD_ENABLED        -Value $BPDUGuard
    $nvPairs | Add-Member -Type NoteProperty -Name PORTTYPE_FAST_ENABLED    -Value $PortFast
    $nvPairs | Add-Member -Type NoteProperty -Name MTU                      -Value $MTU_L2
    $nvPairs | Add-Member -Type NoteProperty -Name ACCESS_VLAN              -Value $AccessVLAN
    }

if ($Mode -eq 'Trunk')   {
    $body    | Add-Member -Type NoteProperty -Name policy                   -Value 'int_trunk_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name SPEED                    -Value $Speed
    $nvPairs | Add-Member -Type NoteProperty -Name DESC                     -Value $Description
    $nvPairs | Add-Member -Type NoteProperty -Name BPDUGUARD_ENABLED        -Value $BPDUGuard
    $nvPairs | Add-Member -Type NoteProperty -Name PORTTYPE_FAST_ENABLED    -Value $PortFast
    $nvPairs | Add-Member -Type NoteProperty -Name MTU                      -Value $MTU_L2
    $nvPairs | Add-Member -Type NoteProperty -Name ALLOWED_VLANS            -Value $AllowedVLANs.Replace(' ','')
    }

if ($Mode -eq 'Routed')  {
    $body    | Add-Member -Type NoteProperty -Name policy                   -Value 'int_routed_host_11_1'
    $nvPairs | Add-Member -Type NoteProperty -Name SPEED                    -Value $Speed
    $nvPairs | Add-Member -Type NoteProperty -Name DESC                     -Value $Description
    $nvPairs | Add-Member -Type NoteProperty -Name INTF_VRF                 -Value $VRF
    $nvPairs | Add-Member -Type NoteProperty -Name IP                       -Value ($Prefix.Split('/')[0])
    $nvPairs | Add-Member -Type NoteProperty -Name PREFIX                   -Value ($Prefix.Split('/')[1])
    $nvPairs | Add-Member -Type NoteProperty -Name ROUTING_TAG              -Value $Tag
    $nvPairs | Add-Member -Type NoteProperty -Name MTU                      -Value $MTU_L3
    }

if ($Mode -eq 'Freeform') {
    $body    | Add-Member -Type NoteProperty -Name policy                   -Value 'int_freeform'
}

if ($Mode -eq 'Monitor') {
    $body    | Add-Member -Type NoteProperty -Name policy                   -Value 'int_monitor_ethernet_11_1'
}

$ints=@()
ForEach ($ifName in $ifNames) {
$int = New-Object -TypeName psobject
$nvp = $nvPairs.psobject.copy()
$int | Add-Member -Type NoteProperty -Name serialNumber        -Value (((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $SwitchName).serialNumber)
$int | Add-Member -Type NoteProperty -name interfaceType       -Value 'INTERFACE_ETHERNET'
$int | Add-Member -Type NoteProperty -name ifName              -Value $ifName
$int | Add-Member -Type NoteProperty -name fabricName          -Value $Fabric
$nvp | Add-Member -Type NoteProperty -name INTF_NAME           -Value $ifName 
$int | Add-Member -Type NoteProperty -name nvPairs             -Value $nvp
$ints += $int
}

$body | Add-Member -Type NoteProperty -Name interfaces -Value $ints

    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}

Remove-Variable -Name nvPairs,body -ErrorAction SilentlyContinue
#Remove-Variable -Name BPDUGuard,Speed,Fabric,Description,MTU_L3,MTU_L2,Enabled     -ErrorAction SilentlyContinue
#Remove-Variable -Name VRF,Prefix,Tag,AllowedVLANs,AccessVLAN,PortFast              -ErrorAction SilentlyContinue
#Remove-Variable -Name interface,interfaces,nvPairs,body,Mode                       -ErrorAction SilentlyContinue
$calls++
while ($calls -ge 80) {
    Start-Sleep -Seconds 10 
    [int]$calls = 0
    }
}    

End     {}
 
}