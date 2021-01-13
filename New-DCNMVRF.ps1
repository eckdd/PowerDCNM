function New-DCNMVRF                 {
    <#
 .SYNOPSIS
Creates a VRF in a fabric
 .DESCRIPTION
This cmdlet will invoke a REST POST against the DCNM Top Down LAN VRF Operations API
 .EXAMPLE
New-DCNMVRF -Fabric site1 -vrf myVRF1 -Name Enterprise -VNI 50001 -VlanID 10 -VlanName ENT 
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
    [Alias("vrfName")]
    [string]$Name,            
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(1,16777214)]
        [int]$VNI,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(2,3967)]
        [int]$VlanID,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$VlanName,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$VrfDescription,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$Description,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(68,9216)]
        [int]$MTU=9216,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(0,4294967295)]
        [int]$Tag=12345,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$RedistRouteMap="FABRIC-RMAP-REDIST-SUBNET",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(0,64)]
        [int]$MaxPathsBGP=1,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(0,64)]
        [int]$MaxPathsiBGP=2,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$TRM="false",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$ExternalRP="false",  
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$RPAddress,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(0,1023)]
        [int]$RPLoopbackId,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$UnderlayMCastAddress,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$OverlayMCastGroups,            
    [ValidateSet("true","false")]
        [string]$MultisiteTRM="false",            
    [ValidateSet("true","false")]
        [string]$AdvertiseHostRoutes="false",            
    [ValidateSet("true","false")]
        [string]$EnableIPv6LinkLocal="true",            
    [ValidateSet("true","false")]
        [string]$AdvertiseDefaultRoute="true",            
    [ValidateSet("true","false")]
        [string]$ConfigStaticDefaultRoute="true",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$BGPNeighborPassword,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("3","7")]
        [string]$BGPKeyType="3",            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$VRFTemplate="Default_VRF_Universal",
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$VRFExtensionTemplate="Default_VRF_Extension_Universal",
    [Parameter(Mandatory=$false, DontShow)]
        [switch]$JSON
    )
Begin   {
$response=@()
$uri    = "$Global:DCNMHost/rest/top-down/fabrics/$Fabric/vrfs"
$body   =@()
if (!(Get-Variable DCNMFabrics -ErrorAction SilentlyContinue)) {Get-DCNMFabric | Out-Null}
}
Process {
    $RPLoopbackId = $RPLoopbackId.ToString()
    $asn = ($Global:DCNMFabrics | Where-Object {$_.fabricName -eq $Fabric}).asn
    $vrfconfig  = @()
    $vrfconfig += "`"vrfVlanName`":`"$VlanName`","
    $vrfconfig += "`"vrfIntfDescription`":`"$Description`","
    $vrfconfig += "`"vrfDescription`":`"$vrfDescription`","
    $vrfconfig += "`"trmEnabled`":$TRM,"
    $vrfconfig += "`"isRPExternal`":$ExternalRP,"
    $vrfconfig += "`"ipv6LinkLocalFlag`":$EnableIPv6LinkLocal,"
    $vrfconfig += "`"trmBGWMSiteEnabled`":$MultisiteTRM,"
    $vrfconfig += "`"advertiseHostRouteFlag`":$AdvertiseHostRoutes,"
    $vrfconfig += "`"advertiseDefaultRouteFlag`":$AdvertiseDefaultRoute,"
    $vrfconfig += "`"configureStaticDefaultRouteFlag`":$ConfigStaticDefaultRoute,"
    $vrfconfig += "`"mtu`":`"$MTU`","
    $vrfconfig += "`"tag`":`"$Tag`","
    $vrfconfig += "`"vrfRouteMap`":`"$RedistRouteMap`","
    $vrfconfig += "`"maxBgpPaths`":`"$MaxPathsBGP`","
    $vrfconfig += "`"maxIbgpPaths`":`"$MaxPathsiBGP`","
    $vrfconfig += "`"rpAddress`":`"$RPAddress`","
    $vrfconfig += "`"loopbackNumber`":`"$RPLoopbackId`","
    $vrfconfig += "`"L3VniMcastGroup`":`"$OverlayMCastGroups`","
    $vrfconfig += "`"multicastGroup`":`"$OverlayMCastGroups`","
    $vrfconfig += "`"bgpPassword`":`"$BGPNeighborPassword`","
    $vrfconfig += "`"bgpPasswordKeyType`":`"$BGPKeyType`","
    $vrfconfig += "`"vrfSegmentId`":`"$VNI`","
    $vrfconfig += "`"vrfName`":`"$Name`","
    $vrfconfig += "`"vrfVlanId`":`"$VlanID`","
    $vrfconfig += "`"nveId`":1,"
    $vrfconfig += "`"asn`":`"$asn`""
    $vrfconfig  = $vrfconfig -join ''

    $body = New-Object -TypeName psobject
    $body | Add-Member -Type NoteProperty -Name 'fabric'                    -Value $Fabric
    $body | Add-Member -Type NoteProperty -Name 'vrfName'                   -Value $Name
    $body | Add-Member -Type NoteProperty -Name 'vrfId'                     -Value $VNI.ToString()
    $body | Add-Member -Type NoteProperty -Name 'vrfTemplate'               -Value $VRFTemplate
    $body | Add-Member -Type NoteProperty -Name 'vrfTemplateConfig'         -Value "`{$vrfconfig`}"
    $body | Add-Member -Type NoteProperty -Name 'VRFExtensionTemplate'      -Value $networkExtensionTemplate
    $body | Add-Member -Type NoteProperty -Name 'source'                    -Value $null
    $body | Add-Member -Type NoteProperty -Name 'serviceVrfTemplate'        -Value $null

    if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}

}
End     {
        }
}