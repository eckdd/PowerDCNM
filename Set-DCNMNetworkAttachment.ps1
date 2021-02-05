function Set-DCNMNetworkAttachment   {
    <#
     .SYNOPSIS
    Attaches/Removes networks to switches
     .DESCRIPTION
    This cmdlet will invoke a REST POST against the DCNM API Top Down LAN Network Operations
     .EXAMPLE
    Set-DCNMNetworkAttachment -Fabric SITE-3 -Network MyNetwork_30001 -Switch 'Leaf2,Leaf3'
     .EXAMPLE
    Set-DCNMNetworkAttachment -Fabric SITE-3 -Network MyNetwork_30001 -Switch Leaf2 -Interface Ethernet1/10
     .EXAMPLE
    Set-DCNMNetworkAttachment -Fabric SITE-3 -Network MyNetwork_30001 -Switch Leaf2 -DetatchInterface Ethernet1/10
     .EXAMPLE
    Set-DCNMNetworkAttachment -Network SHUTDOWN -Fabric SITE-3 -Switch Leaf2 -RemoveNetwork
     .EXAMPLE
    Get-DCNMSwitch -fabricName dc2 | ? {$_.switchRole -eq 'leaf'} | foreach {
    >> Get-DCNMNetwork -Fabric msd | Set-DCNMNetworkAttachment -Fabric dc2 -Switch $_.logicalName}
     .PARAMETER Network
    Name of the Network
     .PARAMETER Fabric
    Name of the Fabric
     .PARAMETER Switch
    Name of the Leaf switch
     .PARAMETER Interface
    Name of optional interface to attach to network 
     .PARAMETER DetatchInterface
    Name of interface to remove from network
     .PARAMETER Untagged
    Specifiy tagged or untagged
     .PARAMETER AccessVLAN
    Set different VLAN id
     .PARAMETER TrunkVLAN
    802.1q VLAN
     .PARAMETER RemoveNetwork
    Removes network from switch
     .PARAMETER DoNotDeploy
    Leaves changes pending deployment
    /#>
    param
        (
            [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [Alias("networkName")]
            [Alias("Name")]
                [string]$Network,
            [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [Alias("fabricName")]
                [string]$Fabric,
            [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [Alias("logicalName","switchName")]
                [string]$Switch,
            [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [Alias("portNames")]
                [string]$Interface,
            [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
                [string]$DetatchInterface,
            [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
                [bool]$Untagged=$false,
            [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [ValidateRange(1,4094)]
            [Alias("vlanId")]
                [int]$AccessVLAN=0,
            [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [ValidateRange(1,4094)]
                [int]$TrunkVLAN,
            [Parameter(Mandatory=$false)]
                [switch]$RemoveNetwork,
            [Parameter(Mandatory=$false)]
                [switch]$DoNotDeploy,
            [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
                [string]$CliFreeform,
    
            [Parameter(Mandatory=$false, DontShow)]
                [switch]$JSON
        )
    Begin   {
    $lanAttachList = @()
    }
    Process {
    if (!(Get-Variable DCNMSwitch_$Fabric -ErrorAction SilentlyContinue)) {Get-DCNMSwitch -fabricName $Fabric | Out-Null}
    
    if ($Interface) {
        [string]$Interface  = $Interface.ToLower().Replace('ethernet','eth')
        [string]$Interface  = $Interface.ToLower().Replace('port-channel','po')
         [array]$Interfaces = $Interface.Split(',')

        $ifNamesAtt = @()
        foreach ($pocInt in ($Interfaces | Where-Object {$_ -match '^po.*'})) {
            foreach ($p in $pocInt) {
                $p = $p -replace 'po',''
                if ($p -match '^\d+$') {$ifNamesAtt += ('Port-channel'+$p)} elseif ($p -match '^\d+\-\d+$') {
                    $p.Split('-')[0]..$p.Split('-')[1] | ForEach-Object {$ifNamesAtt += 'Port-channel'+$_}
                }
            }
        }

        foreach ($ethInt in ($Interfaces | Where-Object {$_ -match '^eth.*'})) {
            foreach ($EthMod in $ethInt.split('eth', [System.StringSplitOptions]::RemoveEmptyEntries)) {
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
                            $ifNamesAtt += 'Ethernet'+$fexN+'/'+$slot+'/'+$p
                        } else {
                        $ifNamesAtt += 'Ethernet'+$slot+'/'+$p
                        }
                    } elseif ($p -match '\d+\-\d+') {
                        $p = $p.split('-')[0]..$p.split('-')[1]
                        $p | ForEach-Object {
                            if ($fexN) {
                                $ifNamesAtt += 'Ethernet'+$fexN+'/'+$slot+'/'+$_
                            } else {
                            $ifNamesAtt += 'Ethernet'+$slot+'/'+$_
                            }
                        }
                       } 
                Remove-Variable p,slot,port,fexN -ErrorAction Ignore
                    }
            }
        }
    }
    
    if ($DetatchInterface) {
        [string]$DetatchInterface = $DetatchInterface.ToLower().Replace('ethernet','eth')
        [string]$DetatchInterface = $DetatchInterface.ToLower().Replace('port-channel','po')
         [array]$DetatcInterfaces = $DetatchInterface.Split(',')
        
            $ifNamesDet = @()
            foreach ($pocInt in ($DetatcInterfaces | Where-Object {$_ -match '^po.*'})) {
                foreach ($p in $pocInt) {
                    $p = $p -replace 'po',''
                    if ($p -match '^\d+$') {$ifNamesDet += ('Port-channel'+$p)} elseif ($p -match '^\d+\-\d+$') {
                        $p.Split('-')[0]..$p.Split('-')[1] | ForEach-Object {$ifNamesDet += 'Port-channel'+$_}
                    }
                }
            }
   
            foreach ($EthMod in $DetatchInterface.split('eth', [System.StringSplitOptions]::RemoveEmptyEntries)) {
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
                            $ifNamesDet += 'Ethernet'+$fexN+'/'+$slot+'/'+$p
                        } else {
                        $ifNamesDet += 'Ethernet'+$slot+'/'+$p
                        }
                    } elseif ($p -match '\d+\-\d+') {
                        $p = $p.split('-')[0]..$p.split('-')[1]
                        $p | ForEach-Object {
                            if ($fexN) {
                                $ifNamesDet += 'Ethernet'+$fexN+'/'+$slot+'/'+$_
                            } else {
                            $ifNamesDet += 'Ethernet'+$slot+'/'+$_
                            }
                        }
                       } 
                Remove-Variable p,slot,port,fexN -ErrorAction Ignore
                    }
            }
        }
    $Switches  = $Switch.Split(',')
    foreach ($sw in $Switches) {
    $lanAttach = New-Object -TypeName psobject
    $lanAttach | Add-Member -Type NoteProperty -Name fabric       -Value $Fabric
    $lanAttach | Add-Member -Type NoteProperty -Name networkName  -Value $Network
    $lanAttach | Add-Member -Type NoteProperty -Name serialNumber -Value ((Get-Variable DCNMSwitch_$Fabric -ValueOnly) | Where-Object -Property logicalName -EQ $sw).serialNumber
    $lanAttach | Add-Member -Type NoteProperty -Name switchPorts        -Value ($ifNamesAtt -join ',')
    $lanAttach | Add-Member -Type NoteProperty -Name detachSwitchPorts  -Value ($ifNamesDet -join ',')
    $lanAttach | Add-Member -Type NoteProperty -Name vlan               -Value $AccessVLAN
    $lanAttach | Add-Member -Type NoteProperty -Name dot1QVlan          -Value $TrunkVLAN
    $lanAttach | Add-Member -Type NoteProperty -Name untagged           -Value $Untagged
    $lanAttach | Add-Member -Type NoteProperty -Name deployment         -Value (!$RemoveNetwork)
    $lanAttach | Add-Member -Type NoteProperty -Name freeformConfig     -Value $CliFreeform
    
    $lanAttachList += $lanAttach
        }
    }
    
    End     {
    $Fabrics  = $lanAttachList.fabric      | Get-Unique
    foreach ($fab in $Fabrics) {
      $body     = @()  
      $Networks = @()
      $fabItems = @()
      $uri      = "$Global:DCNMHost/rest/top-down/fabrics/$fab/networks/attachments"
      $fabItems = $lanAttachList | Where-Object {$_.fabric -EQ $fab}
      $Networks = $fabItems.networkName | Get-Unique
      foreach ($net in $Networks) {
       $item = New-Object -TypeName psobject
       $item | Add-Member -MemberType NoteProperty -Name networkName   -Value $net
    
       $netItems = @()
       foreach ($fabItem in ($fabItems | Where-Object {$_.networkName -EQ $net})) {
        $netItems += $fabItem
       }
       $item | Add-Member -MemberType NoteProperty -Name lanAttachList   -Value $netItems
       $body += $item
      }
       if ($JSON) {$uri ; $Global:DCNM_JSON = (ConvertTo-Json -InputObject @($body) -Depth 10) ; $Global:DCNM_JSON} else {
        $response = New-DCNMObject -uri $uri -object (ConvertTo-Json -InputObject @($body) -Depth 10) ; $response 
       } 
      }
     }
}