function Set-DCNMNetwork             {
    <#
  .SYNOPSIS
  Update properties of existing DCNM networks
  .DESCRIPTION
  This cmdlet will invoke a REST POST against the DCNM Top Down LAN Network Operations API
  .EXAMPLE
  Get-DCNMNetwork -Fabric site1 -Name myNetwork1 | Set-DCNMNetwork  -GatewayIPv4 '10.10.10.1/24' 
  .EXAMPLE
  Get-DCNMNetwork -Fabric site1 -Name myNetwork1 | Set-DCNMNetwork  -VlanName NewName -VlanID 123
  .EXAMPLE
  Get-DCNMNetwork -Fabric site1 -Name myNetwork1 | Set-DCNMNetwork  -MTU 9000
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
        [int]$MTU,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$SecondaryGW1,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$SecondaryGW2,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$SuppressARP,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$RTBothAuto,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$EnableL3onBorder,            
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
        [int]$Tag,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$VRF,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$MulticastGroup,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$IsLayer2Only,  
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$IR,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("true","false")]
        [string]$TRM,            
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
    [ValidateRange(2,3967)]
        [int]$VlanID,            
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            $InputObject,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$networkTemplate,
    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$networkExtensionTemplate,
    [Parameter(Mandatory=$false, DontShow)]
        [switch]$JSON
    )
  Begin   {
    $response =@()
    $body     =@()
  }
  Process {
  
    $fabric = $InputObject.fabric
    $name   = $InputObject.networkName
    $uri    = "$Global:DCNMHost/rest/top-down/fabrics/$fabric/networks/$name"
    
    $OutputObject = $InputObject | Select-Object -ExcludeProperty networkStatus
    $netonfig = $InputObject.networkTemplateConfig | ConvertFrom-Json
  
    if ($IsLayer2Only -eq 'true') {$VRF = 'NA'}
    if ($SuppressARP)       {$netonfig.suppressArp         = $SuppressARP}
    if ($secondaryGW1)      {$netonfig.secondaryGW1        = $secondaryGW1} 
    if ($secondaryGW2)      {$netonfig.secondaryGW2        = $secondaryGW2} 
    if ($DhcpLoopbackID)    {$netonfig.loopbackId          = $DhcpLoopbackID}
    if ($VlanID)            {$netonfig.vlanId              = [string]$VlanID}
    if ($GatewayIPv4)       {$netonfig.gatewayIpAddress    = $GatewayIPv4}
    if ($GatewayIPv6)       {$netonfig.gatewayIpV6Address  = $GatewayIPv6}
    if ($EnableL3onBorder)  {$netonfig.enableL3OnBorder    = $EnableL3onBorder}
    if ($VlanName)          {$netonfig.vlanName            = $VlanName}
    if ($IR)                {$netonfig.enableIR            = $IR}
    if ($MTU)               {$netonfig.mtu                 = [string]$MTU}
    if ($RTBothAuto)        {$netonfig.rtBothAuto          = $RTBothAuto}
    if ($IsLayer2Only)      {$netonfig.isLayer2Only        = $IsLayer2Only}
    if ($Description)       {$netonfig.intfDescription     = $Description}
    if ($MulticastGroup)    {$netonfig.mcastGroup          = $MulticastGroup}
    if ($DhcpServer1)       {$netonfig.dhcpServerAddr1     = $DhcpServer1}
    if ($DhcpServer2)       {$netonfig.dhcpServerAddr2     = $DhcpServer2}
    if ($Tag)               {$netonfig.tag                 = [string]$Tag}
    if ($TRM)               {$netonfig.trmEnabled          = $TRM}
    if ($DhcpVRF)           {$netonfig.vrfDhcp             = $DhcpVRF}
    if ($VRF)               {$netonfig.vrfName             = $VRF}
    if ($VRF)               {$OutputObject.vrf             = $VRF}
  
  $OutputObject.networkTemplateConfig = $netonfig | ConvertTo-Json -Compress
  $body = $OutputObject

  if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject $body -Depth 10) ; $Global:DCNM_JSON} else {
    $response = Set-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject $body -Depth 10) ; $response}
        }
  End     {}
  }