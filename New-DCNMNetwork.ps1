function New-DCNMNetwork             {
    <#
 .SYNOPSIS
Creates a network in a fabric
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM Top Down LAN Network Operations API
 .EXAMPLE
New-DCNMNetwork -Fabric site1 -vrf myVRF1 -Name myNetwork1 -VNI 30001 -VlanID 100 -VlanName test -GatewayIPv4 '10.10.10.1' 
 .EXAMPLE
(Import-Csv .\Book2.csv) | New-DCNMNetwork
 .PARAMETER Fabric
Fabric name
 .PARAMETER Name
Network name
 .PARAMETER VNI
VNI number
 .PARAMETER GatewayIPv4
IPv4 gateway address
 .PARAMETER GatewayIPv6
IPv6 gateway address
 .PARAMETER VlanName
VLAN name 
 .PARAMETER Description
Interface description for gateway SVI
 .PARAMETER MTU
MTU size for gateway SVI (68-9216)
 .PARAMETER SecondaryGW1
Primary IP for gateway SVI
 .PARAMETER SecondaryGW2
Secondary IP for gateway SVI
 .PARAMETER SuppressARP
Enable ARP suppression; true or false
 .PARAMETER RTBothAuto
Use route-target both in configuration profile
 .PARAMETER EnableL3onBorder
Create gateway SVI on border leaf switches; true or false
 .PARAMETER DhcpServer1
First DHCP server
 .PARAMETER DhcpServer2
Second DHCP server
 .PARAMETER DhcpVRF
VRF of DHCP relay source
 .PARAMETER DhcpLoopbackID
Loopback ID for DHCP relay source (0-1023)
 .PARAMETER Tag
Route tag for the gateway subnet
 .PARAMETER IsLayer2Only
Specify network is L2; will not create a gateway
 .PARAMETER IR
Enable Ingress Replication; true or false
 .PARAMETER TRM
Enable Tenent Routed Multicast; true or false
 .PARAMETER VlanID
VLAN ID to be associated with VNI or L3 SVI
 .PARAMETER MulticastGroup
Multicast group address for BUM traffic
 /#>
param
    (
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string]$Fabric,
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias("networkName")]
    [string]$Name,            
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [int]$VNI,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$GatewayIPv4,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$GatewayIPv6,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$VlanName,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$Description,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(68,9216)]
        [int]$MTU=9216,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$SecondaryGW1,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$SecondaryGW2,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$SuppressARP="false",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$RTBothAuto="false",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$EnableL3onBorder="false",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$DhcpServer1,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$DhcpServer2,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$DhcpVRF,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$DhcpLoopbackID,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(0,4294967295)]
        [int]$Tag=12345,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [Alias("vrfName")]
        [string]$VRF,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$MulticastGroup,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$IsLayer2Only="false",  
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$IR="false",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$TRM="false",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(2,3967)]
        [int]$VlanID,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$networkTemplate="Default_Network_Universal",
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$networkExtensionTemplate="Default_Network_Extension_Universal",
    [Parameter(Mandatory=$false, DontShow)]
        [switch]$JSON
    )
Begin   {
$response=@()
$uri    = "$Global:DCNMHost/rest/top-down/bulk-create/networks"
$body   =@()
}
Process {
    if ($IsLayer2Only -eq 'true') {$VRF = 'NA'}
    if (!$Global:DCNMFabrics) {Get-DCNMFabric}
    if (($Global:DCNMFabrics | Where-Object {$_.fabricName -eq $Fabric}).fabricType -eq 'MFD') {[boolean]$msd = $true}
    $netconfig  = @()
    $netconfig += "`"gatewayIpAddress`":`"$GatewayIPv4`","
    $netconfig += "`"gatewayIpV6Address`":`"$GatewayIPv6`","
    $netconfig += "`"vlanName`":`"$VlanName`","
    $netconfig += "`"intfDescription`":`"$Description`","
    $netconfig += "`"mtu`":`"$MTU`","
    $netconfig += "`"secondaryGW1`":`"$SecondaryGW1`","
    $netconfig += "`"secondaryGW2`":`"$SecondaryGW2`","
    $netconfig += "`"suppressArp`":$SuppressARP,"
    if (!$msd) {$netconfig += "`"enableIR`":$IR,"}
    $netconfig += "`"trmEnabled`":$TRM,"
    $netconfig += "`"rtBothAuto`":$RTBothAuto,"
    $netconfig += "`"enableL3OnBorder`":$EnableL3onBorder,"
    $netconfig += "`"mcastGroup`":`"$MulticastGroup`","
    $netconfig += "`"dhcpServerAddr1`":`"$DhcpServer1`","
    $netconfig += "`"dhcpServerAddr2`":`"$DhcpServer2`","
    $netconfig += "`"vrfDhcp`":`"$DhcpVRF`","
    $netconfig += "`"loopbackId`":`"$DhcpLoopbackID`","
    $netconfig += "`"tag`":`"$tag`","
    $netconfig += "`"vrfName`":`"$VRF`","
    $netconfig += "`"isLayer2Only`":$IsLayer2Only,"
    $netconfig += "`"nveId`":1,"
    $netconfig += "`"vlanId`":`"$VlanID`","
    $netconfig += "`"segmentId`":`"$VNI`","
    $netconfig += "`"networkName`":`"$name`""
    $netconfig  = $netconfig -join ''

    $LanNet = New-Object -TypeName psobject
    $LanNet | Add-Member -Type NoteProperty -Name 'fabric'                      -Value $Fabric
    $LanNet | Add-Member -Type NoteProperty -Name 'vrf'                         -Value $VRF
    $LanNet | Add-Member -Type NoteProperty -Name 'networkName'                 -Value $Name
    $LanNet | Add-Member -Type NoteProperty -Name 'displayName'                 -Value $Name
    $LanNet | Add-Member -Type NoteProperty -Name 'networkId'                   -Value "$VNI"
    $LanNet | Add-Member -Type NoteProperty -Name 'networkTemplateConfig'       -Value "`{$netconfig`}"
    $LanNet | Add-Member -Type NoteProperty -Name 'networkTemplate'             -Value $networkTemplate
    $LanNet | Add-Member -Type NoteProperty -Name 'networkExtensionTemplate'    -Value $networkExtensionTemplate
    $LanNet | Add-Member -Type NoteProperty -Name 'source'                      -Value $null
    $LanNet | Add-Member -Type NoteProperty -Name 'serviceNetworkTemplate'      -Value $null

    $body += $LanNet
    Remove-Variable -Name msd -ErrorAction SilentlyContinue | Out-Null
        }
End     {
    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
        }
}