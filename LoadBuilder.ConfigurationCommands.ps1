function New-LoadBuilderConfiguration {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [ValidateNotNullOrEmpty()]
    [string]
    $Name,

    [ValidateNotNullOrEmpty()]
    [string]
    $Base,

    [Alias("Switches")]
    [PSTypeName("LoadBuilderSwitch")]
    [AllowEmptyCollection()]
    [Object[]]
    $VirtualSwitchDefinitions,

    [PSTypeName("LoadBuilderCredential")]
    [AllowEmptyCollection()]
    [Object[]]
    $Credentials,

    [PSTypeName("LoadBuilderAction")]
    [AllowEmptyCollection()]
    [Object[]]
    $Actions,

    [ValidateNotNullOrEmpty()]
    [string]
    $AlternateName,

    [PSTypeName("LoadBuilderAlternate")]
    [AllowEmptyCollection()]
    [Object[]]
    $Alternates,

    [switch]
    $AllowDifferencedImportFromFastLoadExport
  )

  $xml = [System.Xml.XmlDocument]::new()

  $xml.AppendChild(
    $xml.CreateElement("Configuration")
  ) | Out-Null

  $cfg = $xml.SelectSingleNode("Configuration")

  $cfg.SetAttribute("xmlns:xsi","http://www.w3.org/2001/XMLSchema-instance")

  "Name",
  "Base",
  "VirtualSwitchDefinitions",
  "LoadMembers",
  "Credentials",
  "Actions",
  "Settings",
  "AlternateName",
  "Alternates" |
    ForEach-Object {
      $cfg.AppendChild(
        $xml.CreateElement($_)
      ) | Out-Null
    }

  $settings = $cfg.SelectSingleNode("Settings")

  $settings.AppendChild(
    $xml.
    CreateElement("AllowDifferencedImportFromFastLoadExport")
  ) | Out-Null

  $setParams = [hashtable]$PSBoundParameters

  if (-not $PSBoundParameters.ContainsKey("Base")) {
    $setParams.Base = "none"
  }
  if (-not $PSBoundParameters.ContainsKey("AllowDifferencedImportFromFastLoadExport")) {
    $setParams.AllowDifferencedImportFromFastLoadExport = $false
  }

  $cfg |
    Set-LoadBuilderConfiguration @setParams

  $cfg
}
function Set-LoadBuilderConfiguration {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )

  DynamicParam {
    $params = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()

    $commonParamNames = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject(
      [System.Management.Automation.Internal.CommonParameters]
    ) |
      ForEach-Object psobject |
      ForEach-Object Properties |
      ForEach-Object Name

    $sourceParams = Get-Command New-LoadBuilderConfiguration |
                      ForEach-Object Parameters |
                      ForEach-Object GetEnumerator |
                      ForEach-Object Value |
                      Where-Object Name -cnotin $commonParamNames

    foreach ($sourceParam in $sourceParams) {
      $param = [System.Management.Automation.RuntimeDefinedParameter]::new(
        $sourceParam.Name,
        $sourceParam.ParameterType,
        $sourceParam.Attributes
      )

      $params.Add(
        $sourceParam.Name,
        $param
      )
    }

    return $params
  }

  process {
    if ($PSBoundParameters.ContainsKey("Name")) {
      $InputObject.Name = $PSBoundParameters.Name
    }

    if ($PSBoundParameters.ContainsKey("Base")) {
      $InputObject.Base = $PSBoundParameters.Base
    }

    if ($PSBoundParameters.ContainsKey("VirtualSwitchDefinitions")) {
      $InputObject |
        Get-LoadBuilderSwitch |
        Remove-LoadBuilderSwitch

      $InputObject |
        Add-LoadBuilderSwitch $PSBoundParameters.VirtualSwitchDefinitions
    }

    if ($PSBoundParameters.ContainsKey("Credentials")) {
      $InputObject |
        Get-LoadBuilderCredential |
        Remove-LoadBuilderCredential

      $InputObject |
        Add-LoadBuilderCredential $PSBoundParameters.Credentials
    }

    if ($PSBoundParameters.ContainsKey("Actions")) {
      $InputObject |
        Get-LoadBuilderAction |
        Remove-LoadBuilderAction

      $InputObject |
        Add-LoadBuilderAction $PSBoundParameters.Actions
    }

    if ($PSBoundParameters.ContainsKey("AlternateName")) {
      $InputObject.AlternateName = $PSBoundParameters.AlternateName
    }

    if ($PSBoundParameters.ContainsKey("Alternates")) {
      $InputObject |
        Get-LoadBuilderAlternate |
        Remove-LoadBuilderAlternate

      $InputObject |
        Add-LoadBuilderAlternate $PSBoundParameters.Alternates
    }

    if ($PSBoundParameters.ContainsKey("AllowDifferencedImportFromFastLoadExport")) {
      $InputObject.Settings.AllowDifferencedImportFromFastLoadExport = ([bool]$PSBoundParameters.AllowDifferencedImportFromFastLoadExport).ToString().ToLower()
    }
  }
}

function Get-LoadBuilderSwitch {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      SelectNodes("VirtualSwitchDefinitions/VirtualSwitchDefinition")
  }
}
function New-LoadBuilderSwitch {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [ValidateNotNullOrEmpty()]
    [string]
    $Name,

    [Parameter(
      Mandatory = $true
    )]
    [ValidateSet("Private","Internal","External")]
    [string]
    $Type
  )

  $outHash = [hashtable]$PSBoundParameters
  $outHash.PSTypeName = "LoadBuilderSwitch"

  [PSCustomObject]$outHash
}
function Add-LoadBuilderSwitch {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject,

    [Parameter(
      Mandatory = $true,
      Position = 0
    )]
    [PSTypeName("LoadBuilderSwitch")]
    [AllowEmptyCollection()]
    [Object[]]
    $Switch
  )

  $switchesNode = $InputObject.SelectSingleNode("VirtualSwitchDefinitions")

  foreach ($SwitchItem in $Switch) {
    $switchNode = $switchesNode.AppendChild(
      $InputObject.
        OwnerDocument.
        CreateElement("VirtualSwitchDefinition")
    )

    $switchNode.SetAttribute("Name", $SwitchItem.Name)
    $switchNode.SetAttribute("Type", $SwitchItem.Type)
  }
}
function Remove-LoadBuilderSwitch {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      ParentNode.
      RemoveChild($InputObject) |
      Out-Null
  }
}

function Get-LoadBuilderMember {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      SelectNodes("LoadMembers/LoadMember")
  }
}
function Add-LoadBuilderMember {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject,

    [ValidateNotNullOrEmpty()]
    [string]
    $Name,

    [ValidateNotNullOrEmpty()]
    [string]
    $OS,

    [ValidateNotNullOrEmpty()]
    [string]
    $OSEdition,

    [bool]
    $OSUpdated,

    [long]
    $VHDSizeBytes,

    [ValidateSet("Dynamic","Differencing")]
    [string]
    $VHDType,

    [ValidateSet("vhd","vhdx")]
    [string]
    $VHDFormat,

    [ValidateNotNullOrEmpty()]
    [hashtable]
    $ScriptParameters,

    [ValidateNotNullOrEmpty()]
    [string]
    $UsrClass,

    [ValidateNotNullOrEmpty()]
    [string]
    $OfflineScript,

    [ValidateNotNullOrEmpty()]
    [string]
    $Unattend,

    [ValidateNotNullOrEmpty()]
    [string]
    $Script,

    # Drivers, OfflinePackages, Modules, and Packages cannot be further
    # validated here because a string-to-LoadBuilderPackage conversion
    # is handled by the Add-LoadBuilderPackage function.
    [AllowEmptyCollection()]
    [Object[]]
    $Drivers,

    [AllowEmptyCollection()]
    [Object[]]
    $OfflinePackages,

    [AllowEmptyCollection()]
    [Object[]]
    $Modules,

    [AllowEmptyCollection()]
    [Object[]]
    $Packages,

    [ValidateNotNullOrEmpty()]
    [string]
    $VMName,

    [ValidateSet(1, 2)]
    [byte]
    $VMGeneration,

    [ValidateNotNullOrEmpty()]
    [string]
    $VMVersion,

    [byte]
    $VMProcessorCount,

    [long]
    $VMMemoryMinimumBytes,

    [long]
    $VMMemoryStartupBytes,

    [long]
    $VMMemoryMaximumBytes,

    [AllowEmptyCollection()]
    [string[]]
    $VMNetworkAdapters,

    [PSTypeName("LoadBuilderVhd")]
    [AllowEmptyCollection()]
    [Object[]]
    $VMVHDs,

    [ValidateNotNullOrEmpty()]
    [string]
    $ComputerName,

    [switch]
    $UseMemberNameAsComputerName,

    [switch]
    $PassThru
  )

  $members = $InputObject.SelectSingleNode("LoadMembers")

  $member = $members.AppendChild(
    $InputObject.
      OwnerDocument.
      CreateElement("LoadMember")
  )

  "Name",
  "OS",
  "VM",
  "OSEdition",
  "OSUpdated",
  "VHDSizeBytes",
  "VHDType",
  "VHDFormat",
  "ScriptParameters",
  "UsrClass",
  "OfflineScript",
  "Unattend",
  "UnattendTransforms",
  "Script",
  "Drivers",
  "OfflinePackages",
  "Modules",
  "Packages" |
    ForEach-Object {
      $member.AppendChild(
        $InputObject.
          OwnerDocument.
          CreateElement($_)
      ) | Out-Null
    }

  $vm = $member.SelectSingleNode("VM")

  "Name",
  "Generation",
  "Version",
  "ProcessorCount",
  "Memory",
  "NetworkAdapters",
  "VHDs" |
    ForEach-Object {
      $vm.AppendChild(
        $InputObject.
          OwnerDocument.
          CreateElement($_)
      ) | Out-Null
    }

  $memory = $vm.SelectSingleNode("Memory")

  "MinimumBytes",
  "StartupBytes",
  "MaximumBytes" |
    ForEach-Object {
      $memory.AppendChild(
        $InputObject.
          OwnerDocument.
          CreateElement($_)
      ) | Out-Null
    }

  $transforms = $member.SelectSingleNode("UnattendTransforms")

  "UseMemberNameAsComputerName",
  "ComputerName" |
    ForEach-Object {
      $transforms.AppendChild(
        $InputObject.
          OwnerDocument.
          CreateElement($_)
      ) | Out-Null
    }

  $setParams = [hashtable]$PSBoundParameters

  $setParams.Remove("InputObject")
  $setParams.Remove("PassThru")

  $member |
    Set-LoadBuilderMember @setParams

  if ($PassThru) {
    $member
  }
}
function Set-LoadBuilderMember {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param()

  DynamicParam {
    $params = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()

    $commonParamNames = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject(
      [System.Management.Automation.Internal.CommonParameters]
    ) |
      ForEach-Object psobject |
      ForEach-Object Properties |
      ForEach-Object Name

    $excludedParamNames = @(
      "PassThru"
    )

    $sourceParams = Get-Command Add-LoadBuilderMember |
                      ForEach-Object Parameters |
                      ForEach-Object GetEnumerator |
                      ForEach-Object Value |
                      Where-Object Name -cnotin $commonParamNames |
                      Where-Object Name -cnotin $excludedParamNames


    foreach ($sourceParam in $sourceParams) {
      $param = [System.Management.Automation.RuntimeDefinedParameter]::new(
        $sourceParam.Name,
        $sourceParam.ParameterType,
        $sourceParam.Attributes
      )

      $params.Add(
        $sourceParam.Name,
        $param
      )
    }

    return $params
  }

  process {

    if ($PSBoundParameters.ContainsKey("Name")) {
      $PSBoundParameters.InputObject.Name = $PSBoundParameters.Name
    }

    if ($PSBoundParameters.ContainsKey("OS")) {
      $PSBoundParameters.InputObject.OS = $PSBoundParameters.OS
    }

    if ($PSBoundParameters.ContainsKey("OSEdition")) {
      $PSBoundParameters.InputObject.OSEdition = $PSBoundParameters.OSEdition
    }

    if ($PSBoundParameters.ContainsKey("OSUpdated")) {
      $PSBoundParameters.InputObject.OSUpdated = $PSBoundParameters.OSUpdated.ToString().ToLower()
    }

    if ($PSBoundParameters.ContainsKey("VHDSizeBytes")) {
      $PSBoundParameters.InputObject.VHDSizeBytes = $PSBoundParameters.VHDSizeBytes.ToString()
    }

    if ($PSBoundParameters.ContainsKey("VHDType")) {
      $PSBoundParameters.InputObject.VHDType = $PSBoundParameters.VHDType
    }

    if ($PSBoundParameters.ContainsKey("VHDFormat")) {
      $PSBoundParameters.InputObject.VHDFormat = $PSBoundParameters.VHDFormat
    }

    if ($PSBoundParameters.ContainsKey("ScriptParameters")) {
      $paramsNode = $PSBoundParameters.InputObject.SelectSingleNode("ScriptParameters")

      $paramsNode.RemoveAll()

      foreach ($item in $PSBoundParameters.ScriptParameters.GetEnumerator()) {
        $paramNode = $paramsNode.AppendChild(
          $PSBoundParameters.
          InputObject.
          OwnerDocument.
          CreateElement("ScriptParameter")
        )

        $val = $item.Value

        if ($val -is [System.Boolean]) {
          $val = $val.ToString().ToLower()
        }

        $paramNode.SetAttribute("Name", $item.Key)
        $paramNode.SetAttribute("Value", $val)
      }
    }

    if ($PSBoundParameters.ContainsKey("UsrClass")) {
      $PSBoundParameters.InputObject.UsrClass = $PSBoundParameters.UsrClass
    }

    if ($PSBoundParameters.ContainsKey("OfflineScript")) {
      $PSBoundParameters.InputObject.OfflineScript = $PSBoundParameters.OfflineScript
    }

    if ($PSBoundParameters.ContainsKey("Unattend")) {
      $PSBoundParameters.InputObject.Unattend = $PSBoundParameters.Unattend
    }

    if ($PSBoundParameters.ContainsKey("Script")) {
      $PSBoundParameters.InputObject.Script = $PSBoundParameters.Script
    }

    if ($PSBoundParameters.ContainsKey("Drivers")) {
      $PSBoundParameters.InputObject |
        Get-LoadBuilderPackage -PackageType Drivers |
        Remove-LoadBuilderPackage

      $PSBoundParameters.InputObject |
        Add-LoadBuilderPackage -PackageType Drivers $PSBoundParameters.Drivers
    }

    if ($PSBoundParameters.ContainsKey("OfflinePackages")) {
      $PSBoundParameters.InputObject |
        Get-LoadBuilderPackage -PackageType OfflinePackages |
        Remove-LoadBuilderPackage

      $PSBoundParameters.InputObject |
        Add-LoadBuilderPackage -PackageType OfflinePackages $PSBoundParameters.OfflinePackages
    }

    if ($PSBoundParameters.ContainsKey("Modules")) {
      $PSBoundParameters.InputObject |
        Get-LoadBuilderPackage -PackageType Modules |
        Remove-LoadBuilderPackage

      $PSBoundParameters.InputObject |
        Add-LoadBuilderPackage -PackageType Modules $PSBoundParameters.Modules
    }

    if ($PSBoundParameters.ContainsKey("Packages")) {
      $PSBoundParameters.InputObject |
        Get-LoadBuilderPackage -PackageType Packages |
        Remove-LoadBuilderPackage

      $PSBoundParameters.InputObject |
        Add-LoadBuilderPackage -PackageType Packages $PSBoundParameters.Packages
    }

    if ($PSBoundParameters.ContainsKey("VMName")) {
      $PSBoundParameters.InputObject.VM.Name = $PSBoundParameters.VMName
    }

    if ($PSBoundParameters.ContainsKey("VMGeneration")) {
      $PSBoundParameters.InputObject.VM.Generation = $PSBoundParameters.VMGeneration.ToString()
    }

    if ($PSBoundParameters.ContainsKey("VMVersion")) {
      $PSBoundParameters.InputObject.VM.Version = $PSBoundParameters.VMVersion
    }

    if ($PSBoundParameters.ContainsKey("VMProcessorCount")) {
      $PSBoundParameters.InputObject.VM.ProcessorCount = $PSBoundParameters.VMProcessorCount.ToString()
    }

    if ($PSBoundParameters.ContainsKey("VMMemoryStartupBytes")) {
      $PSBoundParameters.InputObject.VM.Memory.StartupBytes = $PSBoundParameters.VMMemoryStartupBytes.ToString()
    }

    if ($PSBoundParameters.ContainsKey("VMMemoryMinimumBytes")) {
      $PSBoundParameters.InputObject.VM.Memory.MinimumBytes = $PSBoundParameters.VMMemoryMinimumBytes.ToString()
    }

    if ($PSBoundParameters.ContainsKey("VMMemoryMaximumBytes")) {
      $PSBoundParameters.InputObject.VM.Memory.MaximumBytes = $PSBoundParameters.VMMemoryMaximumBytes.ToString()
    }

    if ($PSBoundParameters.ContainsKey("VMNetworkAdapters")) {
      $PSBoundParameters.InputObject |
        Get-LoadBuilderAdapter |
        Remove-LoadBuilderAdapter

      $PSBoundParameters.InputObject |
        Add-LoadBuilderAdapter $PSBoundParameters.VMNetworkAdapters
    }

    if ($PSBoundParameters.ContainsKey("VMVHDs")) {
      $PSBoundParameters.InputObject |
        Get-LoadBuilderVhd |
        Remove-LoadBuilderVhd

      $PSBoundParameters.InputObject |
        Add-LoadBuilderVhd $PSBoundParameters.VMVHDs
    }

    if ($PSBoundParameters.ContainsKey("UseMemberNameAsComputerName")) {
      $PSBoundParameters.InputObject.UnattendTransforms.UseMemberNameAsComputerName = ([bool]$PSBoundParameters.UseMemberNameAsComputerName).ToString().ToLower()
    }

    if ($PSBoundParameters.ContainsKey("ComputerName")) {
      $PSBoundParameters.InputObject.UnattendTransforms.ComputerName = $PSBoundParameters.ComputerName
    }
  }
}
function Remove-LoadBuilderMember {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      ParentNode.
      RemoveChild($InputObject) |
      Out-Null
  }
}

function Get-LoadBuilderPackage {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject,

    [ValidateNotNullOrEmpty()]
    [string]
    $PackageType = "Packages"
  )
  process {
    $InputObject.
      SelectNodes("$PackageType/Package")
  }
}
function New-LoadBuilderPackage {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [ValidateNotNullOrEmpty()]
    [string]
    $Source,

    [ValidateNotNullOrEmpty()]
    [string]
    $Destination
  )

  $outHash = [hashtable]$PSBoundParameters
  $outHash.PSTypeName = "LoadBuilderPackage"

  [PSCustomObject]$outHash
}
function Add-LoadBuilderPackage {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject,

    [ValidateNotNullOrEmpty()]
    [string]
    $PackageType = "Packages",

    [Parameter(
      Mandatory = $true,
      Position = 0
    )]
    [AllowEmptyCollection()]
    [Object[]]
    $Package
  )

  $packagesNode = $InputObject.SelectSingleNode($PackageType)

  foreach ($PackageItem in $Package) {
    if ($PackageItem -is [string]) {
      $PackageItem = New-LoadBuilderPackage -Source $PackageItem
    }

    if ($PackageItem.psobject.TypeNames[0] -cne "LoadBuilderPackage") {
      throw "Invalid package. Object was not a 'LoadBuilderPackage', or a string source from which a package could be constructed."
    }

    $packageNode = $packagesNode.AppendChild(
      $InputObject.
        OwnerDocument.
        CreateElement("Package")
    )

    $packageNode.SetAttribute("Source", $PackageItem.Source)
    $packageNode.SetAttribute("Destination", $PackageItem.Destination)
  }
}
function Remove-LoadBuilderPackage {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      ParentNode.
      RemoveChild($InputObject) |
      Out-Null
  }
}

function Get-LoadBuilderAdapter {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      SelectNodes("VM/NetworkAdapters/NetworkAdapter")
  }
}
function Add-LoadBuilderAdapter {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject,

    [Parameter(
      Mandatory = $true,
      Position = 0
    )]
    [AllowEmptyCollection()]
    [string[]]
    $SwitchName
  )

  $adaptersNode = $InputObject.SelectSingleNode("VM/NetworkAdapters")

  foreach ($SwitchNameItem in $SwitchName) {
    $adapterNode = $adaptersNode.AppendChild(
      $InputObject.
        OwnerDocument.
        CreateElement("NetworkAdapter")
    )

    $adapterNode.AppendChild(
      $InputObject.
        OwnerDocument.
        CreateTextNode($SwitchNameItem)
    ) | Out-Null
  }
}
function Remove-LoadBuilderAdapter {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      ParentNode.
      RemoveChild($InputObject) |
      Out-Null
  }
}

function Get-LoadBuilderVhd {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      SelectNodes("VM/VHDs/VHD")
  }
}
function New-LoadBuilderVhd {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [ValidateNotNullOrEmpty()]
    [string]
    $Name,

    [long]
    $SizeBytes,

    [Object[]]
    $Packages,

    [switch]
    $Raw,

    [switch]
    $Attach
  )

  $outHash = @{
    PSTypeName = "LoadBuilderVhd"
  }

  "Name",
  "SizeBytes",
  "Packages" |
    ForEach-Object {
      if ($PSBoundParameters.ContainsKey($_)) {
        $outHash.$_ = $PSBoundParameters.$_
      }
    }

  $outHash.AutoPartition = ((-not $PSBoundParameters.ContainsKey("Raw")) -or (-not $Raw)).ToString().ToLower()
  $outHash.AutoAttach = ((-not $PSBoundParameters.ContainsKey("Attach")) -or ($Attach)).ToString().ToLower()

  [PSCustomObject]$outHash
}
function Add-LoadBuilderVhd {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject,

    [Parameter(
      Mandatory = $true,
      Position = 0
    )]
    [PSTypeName("LoadBuilderVhd")]
    [AllowEmptyCollection()]
    [Object[]]
    $VHD
  )

  $vhdsNode = $InputObject.SelectSingleNode("VM/VHDs")

  foreach ($vhdItem in $VHD) {
    $vhdNode = $vhdsNode.AppendChild(
      $InputObject.
        OwnerDocument.
        CreateElement("VHD")
    )

    "Name",
    "SizeBytes",
    "Packages",
    "AutoPartition",
    "AutoAttach" |
      ForEach-Object {
        $vhdNode.AppendChild(
          $InputObject.
            OwnerDocument.
            CreateElement($_)
        ) | Out-Null
      }

    if ($vhdItem.Name) {
      $vhdNode.Name = $vhdItem.Name
    }

    if ($vhdItem.SizeBytes) {
      $vhdNode.SizeBytes = $vhdItem.SizeBytes.ToString()
    }

    if ($vhdItem.Packages) {
      $vhdNode |
        Add-LoadBuilderPackage -PackageType Packages $vhdItem.Packages
    }

    $vhdNode.AutoPartition = $vhdItem.AutoPartition
    $vhdNode.AutoAttach = $vhdItem.AutoAttach      
  }
}
function Remove-LoadBuilderVhd {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      ParentNode.
      RemoveChild($InputObject) |
      Out-Null
  }
}

function Get-LoadBuilderCredential {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      SelectNodes("Credentials/Credential")
  }
}
function New-LoadBuilderCredential {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [ValidateNotNullOrEmpty()]
    [string]
    $Domain,

    [Parameter(
      Mandatory = $true
    )]
    [ValidateNotNullOrEmpty()]
    [string]
    $UserName,

    [Parameter(
      Mandatory = $true
    )]
    [ValidateNotNullOrEmpty()]
    [string]
    $Password
  )

  $outHash = [hashtable]$PSBoundParameters
  $outHash.PSTypeName = "LoadBuilderCredential"

  if (-not $outHash.ContainsKey("Domain")) {
    $outHash.Domain = "."
  }

  [PSCustomObject]$outHash
}
function Add-LoadBuilderCredential {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject,

    [Parameter(
      Mandatory = $true,
      Position = 0
    )]
    [PSTypeName("LoadBuilderCredential")]
    [AllowEmptyCollection()]
    [Object[]]
    $Credential
  )

  $credentialsNode = $InputObject.SelectSingleNode("Credentials")

  foreach ($CredentialItem in $Credential) {
    $credentialNode = $credentialsNode.AppendChild(
      $InputObject.
        OwnerDocument.
        CreateElement("Credential")
    )

    $credentialNode.SetAttribute("Domain", $CredentialItem.Domain)
    $credentialNode.SetAttribute("UserName", $CredentialItem.UserName)
    $credentialNode.SetAttribute("Password", $CredentialItem.Password)
  }
}
function Remove-LoadBuilderCredential {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      ParentNode.
      RemoveChild($InputObject) |
      Out-Null
  }
}

function Get-LoadBuilderAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      SelectNodes("Actions/Action")
  }
}
function New-LoadBuilderStartAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Position = 0
    )]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $Targets,

    [switch]
    $WaitForHeartbeat
  )

  [PSCustomObject]@{
    PSTypeName       = "LoadBuilderAction"
    Type             = "StartAction"
    Targets          = $Targets
    WaitForHeartbeat = (-not $PSBoundParameters.ContainsKey("WaitForHeartbeat")) -or ($WaitForHeartbeat)
  }
}
function New-LoadBuilderStopAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Position = 0
    )]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $Targets
  )

  [PSCustomObject]@{
    PSTypeName       = "LoadBuilderAction"
    Type             = "StopAction"
    Targets          = $Targets
  }
}
function New-LoadBuilderWaitAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Position = 0
    )]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $Targets,

    [switch]
    $UseShim
  )

  [PSCustomObject]@{
    PSTypeName       = "LoadBuilderAction"
    Type             = "WaitAction"
    Targets          = $Targets
    UseShim          = [bool]$UseShim
  }
}
function New-LoadBuilderPokeAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Position = 0
    )]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $Targets,

    [switch]
    $UseShim
  )

  [PSCustomObject]@{
    PSTypeName       = "LoadBuilderAction"
    Type             = "PokeAction"
    Targets          = $Targets
    UseShim          = [bool]$UseShim
  }
}
function New-LoadBuilderInjectAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Position = 0
    )]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $Targets,

    [ValidateNotNullOrEmpty()]
    [hashtable]
    $ScriptParameters,

    [Parameter(
      Mandatory = $true
    )]
    [ValidateNotNullOrEmpty()]
    [string]
    $Script
  )

  [PSCustomObject]@{
    PSTypeName       = "LoadBuilderAction"
    Type             = "InjectAction"
    Targets          = $Targets
    ScriptParameters = $ScriptParameters
    Script           = $Script
  }
}
function New-LoadBuilderCustomAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Position = 0
    )]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $Targets,

    [ValidateNotNullOrEmpty()]
    [hashtable]
    $ScriptParameters,

    [Parameter(
      Mandatory = $true
    )]
    [ValidateNotNullOrEmpty()]
    [string]
    $Script,

    [byte]
    $MountVhd,

    [switch]
    $ExpectOutput
  )

  $outObj = [PSCustomObject]@{
    PSTypeName       = "LoadBuilderAction"
    Type             = "CustomAction"
    Targets          = $Targets
    ScriptParameters = $ScriptParameters
    Script           = $Script
    MountVhd         = [string]::Empty
    ExpectOutput     = [bool]$ExpectOutput
  }

  if ($PSBoundParameters.ContainsKey("MountVhd")) {
    $outObj.MountVhd = $MountVhd
  }

  $outObj
}
function New-LoadBuilderAttendedAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Position = 0
    )]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $Targets,

    [Parameter(
      Mandatory = $true
    )]
    [ValidateNotNullOrEmpty()]
    [string]
    $Description
  )

  [PSCustomObject]@{
    PSTypeName       = "LoadBuilderAction"
    Type             = "AttendedAction"
    Targets          = $Targets
    Description      = $Description
  }
}
function New-LoadBuilderCheckpointAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Position = 0
    )]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $Targets,

    [ValidateNotNullOrEmpty()]
    [string]
    $CheckpointName = "Known Good Configuration",

    [switch]
    $OptimizeVhds
  )

  [PSCustomObject]@{
    PSTypeName       = "LoadBuilderAction"
    Type             = "CheckpointAction"
    Targets          = $Targets
    CheckpointName   = $CheckpointName
    OptimizeVhds     = (-not $PSBoundParameters.ContainsKey("OptimizeVhds")) -or ($OptimizeVhds)
  }
}
function New-LoadBuilderExportVMAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Position = 0
    )]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $Targets,

    [ValidateNotNullOrEmpty()]
    [string]
    $Destination,

    [switch]
    $OptimizeVhds,

    [switch]
    $RemoveRealizedLoad,

    [ValidateSet("None", "Import", "ImportAndInit")]
    [string]
    $SpecialHandling = "Import"
  )

  $outObj = [PSCustomObject]@{
    PSTypeName         = "LoadBuilderAction"
    Type               = "ExportVMAction"
    Targets            = $Targets
    Destination        = $Destination
    OptimizeVhds       = (-not $PSBoundParameters.ContainsKey("OptimizeVhds")) -or ($OptimizeVhds)
    RemoveRealizedLoad = [bool]$RemoveRealizedLoad
    SpecialHandling    = $SpecialHandling
  }

  $outObj
}
function New-LoadBuilderExportLoadAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Position = 0
    )]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $Targets,

    [ValidateNotNullOrEmpty()]
    [string]
    $Destination,

    [switch]
    $OptimizeVhds,

    [switch]
    $RemoveRealizedLoad
  )

  [PSCustomObject]@{
    PSTypeName         = "LoadBuilderAction"
    Type               = "ExportLoadAction"
    Targets            = $Targets
    Destination        = $Destination
    OptimizeVhds       = (-not $PSBoundParameters.ContainsKey("OptimizeVhds")) -or ($OptimizeVhds)
    RemoveRealizedLoad = [bool]$RemoveRealizedLoad
  }
}
function Add-LoadBuilderAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject,

    [Parameter(
      Mandatory = $true,
      Position = 0
    )]
    [AllowEmptyCollection()]
    [PSTypeName("LoadBuilderAction")]
    [Object[]]
    $Action
  )

  $actionsNode = $InputObject.SelectSingleNode("Actions")

  foreach ($ActionItem in $Action) {
    $actionNode = $actionsNode.AppendChild(
      $InputObject.
        OwnerDocument.
        CreateElement("Action")
    )

    $targetsNode = $actionNode.AppendChild(
      $InputObject.
        OwnerDocument.
        CreateElement("Targets")
    )

    foreach ($target in $ActionItem.Targets) {
      $targetNode = $targetsNode.AppendChild(
        $InputObject.
         OwnerDocument.
         CreateElement("Target")
      )

      $targetNode.AppendChild(
        $InputObject.
          OwnerDocument.
          CreateTextNode($target)
      ) | Out-Null
    }

    $typeAttr = $InputObject.
                  OwnerDocument.
                  CreateAttribute("xsi:type", $InputObject.xsi)

    $typeAttr.Value = $ActionItem.Type

    $actionNode.SetAttributeNode($typeAttr) | Out-Null

    $properties = @(
      $ActionItem |
        ForEach-Object psobject |
        ForEach-Object Properties |
        Where-Object Name -notin Targets,Type
    )

    foreach ($property in $properties) {
      $value = $property.Value

      if ($property.TypeNameOfValue -eq "System.Boolean") {
        $value = $value.ToString().ToLower()
      }
      elseif ($property.TypeNameOfValue -eq "System.Byte") {
        $value = $value.ToString()
      }

      $valueNode = $actionNode.AppendChild(
        $InputObject.
         OwnerDocument.
         CreateElement($property.Name)
      )

      if ($property.Name -eq "ScriptParameters" -and $value -is [hashtable]) {
        foreach ($item in $value.GetEnumerator()) {
          $paramNode = $valueNode.AppendChild(
            $InputObject.
            OwnerDocument.
            CreateElement("ScriptParameter")
          )

          $val = $item.Value

          if ($val -is [System.Boolean]) {
            $val = $val.ToString().ToLower()
          }

          $paramNode.SetAttribute("Name", $item.Key)
          $paramNode.SetAttribute("Value", $val)
        }
      }
      elseif ($value -is [string] -and $value.Length -gt 0) {
        $valueNode.InnerText = $value
      }
    }
  }
}
function Remove-LoadBuilderAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      ParentNode.
      RemoveChild($InputObject) |
      Out-Null
  }
}

function Get-LoadBuilderAlternate {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      SelectNodes("Alternates/Alternate")
  }
}
function New-LoadBuilderAlternate {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Name,

    [string[]]
    $Targets,

    [Parameter(
      Mandatory = $true
    )]
    [scriptblock]
    $Script,

    [switch]
    $AppendName
  )

  $outHash = @{
    PSTypeName = "LoadBuilderAlternate"
    Name       = $Name
    Targets    = $Targets
    Script     = $Script
    AppendName = [bool]$AppendName
  }

  [PSCustomObject]$outHash
}
function Add-LoadBuilderAlternate {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject,

    [Parameter(
      Mandatory = $true,
      Position = 0
    )]
    [PSTypeName("LoadBuilderAlternate")]
    [AllowEmptyCollection()]
    [Object[]]
    $Alternate
  )

  $alternatesNode = $InputObject.SelectSingleNode("Alternates")

  foreach ($AlternateItem in $Alternate) {
    $alternateNode = $alternatesNode.AppendChild(
      $InputObject.
        OwnerDocument.
        CreateElement("Alternate")
    )

    $alternateNode.AppendChild(
      $InputObject.
        OwnerDocument.
        CreateElement("Name")
    ) | Out-Null

    $alternateNode.Name = $AlternateItem.Name

    $targetsNode = $alternateNode.AppendChild(
      $InputObject.
        OwnerDocument.
        CreateElement("Targets")
    )

    foreach ($target in $AlternateItem.Targets) {
      $targetNode = $targetsNode.AppendChild(
        $InputObject.
         OwnerDocument.
         CreateElement("Target")
      )

      $targetNode.AppendChild(
        $InputObject.
          OwnerDocument.
          CreateTextNode($target)
      ) | Out-Null
    }

    "Script",
    "AppendName" |
      ForEach-Object {
        $alternateNode.AppendChild(
          $InputObject.
            OwnerDocument.
            CreateElement($_)
        ) | Out-Null
      }

    $alternateNode.Script = $AlternateItem.Script.ToString()
    $alternateNode.AppendName = $AlternateItem.AppendName.ToString().ToLower()
  }
}
function Remove-LoadBuilderAlternate {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $InputObject
  )
  process {
    $InputObject.
      ParentNode.
      RemoveChild($InputObject) |
      Out-Null
  }
}