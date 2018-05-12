$OSData = & (Get-Path OSData) -Workflow VHD

function New-PackageType {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $TypeName,
    
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $DefaultSource,

    [string]
    $DefaultDestination,

    [switch]
    $AllowCustomSource,

    [switch]
    $AllowCustomDestination
  )

  $outObj = [PSCustomObject]@{
    TypeName               = $TypeName
    DefaultSource          = $DefaultSource
    DefaultDestination     = $null
    AllowCustomSource      = [bool]$AllowCustomSource
    AllowCustomDestination = [bool]$AllowCustomDestination
  }

  if ($PSBoundParameters.ContainsKey("DefaultDestination")) {
    $outObj.DefaultDestination = $DefaultDestination
  }

  $outObj
}

$packageTypes = @(
  New-PackageType -TypeName Drivers `
                  -DefaultSource (Get-Path Packages) `
                  -AllowCustomSource

  New-PackageType -TypeName OfflinePackages `
                  -DefaultSource (Get-Path Packages) `
                  -AllowCustomSource

  New-PackageType -TypeName Modules `
                  -DefaultSource (Get-Path Modules) `
                  -DefaultDestination CT\Modules `
                  -AllowCustomSource

  New-PackageType -TypeName Packages `
                  -DefaultSource (Get-Path Packages) `
                  -DefaultDestination "CT\Packages" `
                  -AllowCustomSource `
                  -AllowCustomDestination

  New-PackageType -TypeName VHDPackages `
                  -DefaultSource (Get-Path Packages) `
                  -DefaultDestination "\" `
                  -AllowCustomSource `
                  -AllowCustomDestination
)

function Get-VhdPath {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [System.Xml.XmlElement]
    $Member,

    [switch]
    $Updated
  )

  $filePrefix = $OSData.OperatingSystems |
                  Where-Object Name -eq $Member.OS |
                  ForEach-Object FilePrefix

  $updatedMap = @{
    $true  = "Updated"
    $false = "Not Updated"
  }

  $vhdBaseName = @(
    $filePrefix
    $Member.OSEdition
    $Member.VHDPartitionStyle
    $updatedMap.[bool]$Updated
  ) -join ' - '

  $vhdName = $vhdBaseName + ".$($Member.VHDFormat)"

  Join-Path -Path (Get-Path VHDs) -ChildPath $vhdName
}

function Test-IsValidComputerName {
  param(
    [string]
    $Name
  )
  try {
    if ($Name.Length -ne $Name.Trim().Length) {
      return $false
    }

    if ($Name.Length -lt 1 -or $Name.Length -gt 15) {
      return $false
    }

    if ($Name -notmatch "^[A-Z0-9\-]+$") {
      return $false
    }

    if ($Name[0] -eq "-" -or $Name[-1] -eq "-") {
      return $false
    }

    return $true
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Test-IsValidRootedPath {
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Path,

    [boolean]
    $ShouldExist,

    [System.Type]
    $ItemType
  )
  try {
    if ($Path -notmatch "^[A-Z]:\\" -and $Path -notmatch "^\\\\") {
      return $false
    }

    if (-not (Test-Path -LiteralPath $Path -IsValid -ErrorAction Stop)) {
      return $false
    }

    if (-not ($PSBoundParameters.ContainsKey("Should Exist"))) {
      return $true
    }

    $pathExists = Test-Path -LiteralPath $Path -ErrorAction Stop

    if ($pathExists -ne $ShouldExist) {
      return $false
    }

    if (-not $ShouldExist) {
      return $true
    }

    $item = Get-Item -LiteralPath $Path

    if ($Path -ne $item.FullName) {
      return $false
    }

    if ($ItemType -and $item -isnot $ItemType) {
      return $false
    }

    return $true
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

$constrainedString = {
  if ($nodeValue.Length -ne $nodeValue.Trim().Length) {
    throw "Value had leading or trailing whitespace."
  }

  if ($nodeValue.Length -lt $params.MinLength -or $nodeValue.Length -gt $params.MaxLength) {
    throw "Value did not meet length constraint of $($params.MinLength) min or $($params.MaxLength) max."
  }

  if ($nodeValue.Contains("\")) {
    throw "Value contained ('\') path separator character."
  }

  if ($nodeValue -notmatch $params.Pattern) {
    throw "Value did not match expected pattern '$($params.Pattern)'."
  }

  if ($params.SkipValidityTest) {
    return
  }

  $testPath = Join-Path -Path C:\ -ChildPath $nodeValue -ErrorAction Stop

  if (-not (Test-Path -LiteralPath $testPath -IsValid -ErrorAction Stop)) {
    throw "Value failed 'Test-Path -IsValid' validity failsafe."
  }
}
$vhdDefaultSize = {
  $node.$valProp = 40gb
}
$vhdSize = {
  if ([int64]$nodeValue -ne 40gb -and [int64]$nodeValue -lt 60gb) {
    throw "Value must be exactly 40gb or no less than 60gb to avoid edge cases in size comparison."
  }

  if (([int64]$nodeValue % 1gb) -ne 0) {
    throw "Value must be evenly divisible by 1gb."
  }
}
$packageSource = {
  $typeObj = $packageTypes |
               Where-Object TypeName -eq $params.PackageType

  $packageInDefaultSource = Get-ChildItem -LiteralPath $typeObj.DefaultSource |
                              Where-Object Name -eq $nodeValue |
                              ForEach-Object FullName

  if ($packageInDefaultSource -is [string]) {
    # Other means of setting this value (e.g $node.$valProp) were ineffective.
    $node.OwnerElement.SetAttribute("Source", $packageInDefaultSource)
    return
  }

  if (-not ($typeObj.AllowCustomSource)) {
    throw "No item with this name was found in the default source location for this package type, and the type is not configured to allow custom source locations."
  }

  if (-not (Test-IsValidRootedPath -Path $nodeValue)) {
    throw "No item with this name was found in the default source location for this package type, and the value did not match the format expected of a rooted path to content in a custom source location on a local volume or network share."
  }

  if (-not (Test-IsValidRootedPath -Path $nodeValue -ShouldExist $true -ErrorAction Stop)) {
    throw "A package from a custom source location must be a rooted, direct path to an existing file or folder on a local volume or network share."
  }
}
$packageDest = {
  $typeObj = $packageTypes |
               Where-Object TypeName -eq $params.PackageType

  if ($nodeValue.Length -eq 0 -and $typeObj.DefaultDestination -isnot [string]) {
    $node.OwnerElement.SetAttribute("Destination", "n/a")
    return
  }
  elseif ($nodeValue.Length -gt 0 -and ($typeObj.DefaultDestination -isnot [string] -or (-not $typeObj.AllowCustomDestination))) {
    throw "Packages defined in '$($params.PackageType)' context may not set a custom destination."
  }

  if ($nodeValue.Length -eq 0) {
    $node.OwnerElement.SetAttribute("Destination", $typeObj.DefaultDestination.Trim("\"))
    return
  }

  if ($nodeValue -match "^[A-Z]:\\" -or $nodeValue -match "^\\\\") {
    throw "Custom Destination must be a relative path, considered by reference to the root of the destination volume."
  }

  try {
    $testPath = Join-Path -Path $env:SystemDrive -ChildPath $nodeValue -ErrorAction Stop

    if (-not (Test-Path -LiteralPath $testPath -IsValid -ErrorAction Stop)) {
      throw
    }
  } catch {
    throw "Custom destination failed path validity test."
  }

  $node.OwnerElement.SetAttribute("Destination", $nodeValue.Trim("\"))
}
$notApplicable = {
  foreach ($naNodeName in $params.NANodeNames) {
    $naNode = $node.SelectSingleNode($naNodeName)

    if ($naNode.InnerXml.Length -eq 0) {
      $naNode.InnerXml = "n/a"
    }
    else {
      throw "The value at '$naNodeName' is incompatible with value '$nodeValue' at this node."
    }
  }
}

$uniqueness = {
  $uniqueValues = @(
    $nodeListValues |
      Sort-Object -Unique
  )

  if ($nodeListValues.Count -ne $uniqueValues.Count) {
    throw "List contained duplicate values."
  }
}
$uniqueness_nonEmpty = {
  $nonEmpty = @(
    $nodeListValues |
      Where-Object Length -gt 0
  )

  $uniqueValues = @(
    $nonEmpty |
      Sort-Object -Unique
  )

  if ($nonEmpty.Count -ne $uniqueValues.Count) {
    throw "Non-empty items from list contained duplicate values."
  }
}
$atLeastOne = {
  if ($nodeList.Count -eq 0) {
    throw "List contained no members."
  }
}

$Xml.
  SelectSingleNode("/Configuration").
  AppendChild(
    $Xml.CreateElement("BaseMembers")
  ) | Out-Null

$Xml.
  SelectSingleNode("/Configuration").
  AppendChild(
    $Xml.CreateElement("CompiledMembers")
  ) | Out-Null

rule -Individual /Configuration/Name $constrainedString @{
  MinLength = 1
  MaxLength = 36
  Pattern   = "^[A-Za-z0-9 \-+()]+$"
}

# Uniqueness of base load data is confirmed in concert with load member data
# via compiled members.
rule -Individual /Configuration/Base `
     -PrereqScript {
  $nodeValue -ne "none"
} `
     -Script $constrainedString `
     -Params @{
  MinLength = 1
  MaxLength = 20
  Pattern   = "^[A-Za-z0-9 \-+()]+$"
}
rule -Individual /Configuration/Base `
     -PrereqScript {
  $nodeValue -ne "none"
} `
     -Script {
  $paths = @{
    Fast = Get-Path LoadExport_Fast | Join-Path -ChildPath $nodeValue
    Slow = Get-Path LoadExport | Join-Path -ChildPath $nodeValue
  }

  if (Test-Path -LiteralPath $paths.Fast) {
    $basePath = $paths.Fast
    $pathType = "Fast"
  }
  elseif (Test-Path -LiteralPath $paths.Slow) {
    $basePath = $paths.Slow
    $pathType = "Slow"
  }
  else {
    throw "Base load '$nodeValue' not found in any export folder."
  }

  $jsonPath = $basePath | Join-Path -ChildPath export.data.json

  if (-not (Test-Path -LiteralPath $jsonPath)) {
    throw "Base load '$nodeValue' in '$pathType' path had no export data."
  }

  $exportData = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json

  $baseMembers     = $node.SelectSingleNode("/Configuration/BaseMembers")
  $compiledMembers = $node.SelectSingleNode("/Configuration/CompiledMembers")

  $exportData |
    ForEach-Object {
      $baseMember = $baseMembers.AppendChild(
        $node.
        OwnerDocument.
        CreateElement("BaseMember")
      )

      $compiledMember = $compiledMembers.AppendChild(
        $node.
        OwnerDocument.
        CreateElement("CompiledMember")
      )

      $paths_source_vm = Join-Path -Path $basePath -ChildPath $_.VMName
      $paths_relative_vm_config = Join-Path -Path "Virtual Machines" -ChildPath "$($_.VMId).vmcx"

      $vmConfigPath = Join-Path -Path $paths_source_vm -ChildPath $paths_relative_vm_config

      if (-not (Test-Path -LiteralPath $vmConfigPath)) {
        throw "VM resources for base load member '$($_.MemberName)' were missing/incomplete."
      }

      $baseMember.AppendChild(
        $node.
        OwnerDocument.
        CreateElement("Name")
      ).InnerXml = $_.MemberName

      $baseMember.AppendChild(
        $node.
        OwnerDocument.
        CreateElement("VMName")
      ).InnerXml = $_.VMName

      $baseMember.AppendChild(
        $node.
        OwnerDocument.
        CreateElement("VMId")
      ).InnerXml = $_.VMId

      $baseMember.AppendChild(
        $node.
        OwnerDocument.
        CreateElement("PathType")
      ).InnerXml = $pathType

      # The following paths are needed to validate existence of resources at
      # source. It would be wasteful not to store them in the markup, even
      # though resolution of most paths occurs later.
      $baseMember.AppendChild(
        $node.
        OwnerDocument.
        CreateElement("Paths.Source.VM")
      ).InnerXml = $paths_source_vm

      $baseMember.AppendChild(
        $node.
        OwnerDocument.
        CreateElement("Paths.Relative.VM.Config")
      ).InnerXml = $paths_relative_vm_config

      $compiledMember.AppendChild(
        $node.
        OwnerDocument.
        CreateElement("MemberName")
      ).InnerXml = $_.MemberName

      $compiledMember.AppendChild(
        $node.
        OwnerDocument.
        CreateElement("VMName")
      ).InnerXml = $_.VMName

      $compiledMember.AppendChild(
        $node.
        OwnerDocument.
        CreateElement("VMId")
      ).InnerXml = $_.VMId
    }
}

rule -Individual /Configuration/VirtualSwitchDefinitions/VirtualSwitchDefinition/@Name `
     -Script $constrainedString `
     -Params @{
  Pattern   = "^[A-Za-z0-9 ()]+$"
  MinLength = 1
  MaxLength = 20
}
# Writes "Present" attribute to definition.
rule -Individual /Configuration/VirtualSwitchDefinitions/VirtualSwitchDefinition `
     -Script {
  $existing = @(
    Get-VMSwitch |
      Where-Object Name -eq $node.GetAttribute("Name")
  )

  if ($existing.Count -gt 1) {
    throw "Multiple switches with this name aready exist, and the script is not equipped to handle the ambiguity."
  }

  if ($existing.Count -eq 0 -and $node.GetAttribute("Type") -eq "External") {
    throw "No switch with this name exists, and the configuration defines it as an 'External' virtual switch. The script is not equipped to automatically create the resource."
  }
  elseif ($existing.Count -eq 0) {
    $node.SetAttribute("Present", "false")
    return
  }

  $existing = $existing[0]

  if ($node.GetAttribute("Type") -ne $existing.SwitchType) {
    throw "A switch with this name already exists, but the type is inconsistent with its definition. The script is not equipped to handle the ambiguity."
  }

  $node.SetAttribute("Present", "true")
}
rule -Aggregate /Configuration/VirtualSwitchDefinitions/VirtualSwitchDefinition/@Name `
     -Script $uniqueness

#region /Configuration/LoadMembers
$loadMemberCount = $Xml.SelectNodes("/Configuration/LoadMembers/LoadMember").Count

rule -Individual /Configuration/LoadMembers/LoadMember/Name `
     -PrereqScript {
  $nodeValue.Length -eq 0
} `
     -Script {
  $memberCount = $node.SelectNodes("/Configuration/LoadMembers/LoadMember").Count

  if ($memberCount -gt 1) {
    throw "Default assignment of a value to this node is only possible when the configuration contains exactly one load member."
  }

  $node.$valProp = $node.SelectSingleNode("/Configuration/Name").InnerXml
}
rule -Individual /Configuration/LoadMembers/LoadMember/Name $constrainedString @{
  Pattern   = "^[A-Za-z0-9 .\-]+$"
  MinLength = 1
  MaxLength = 30
}
rule -Aggregate /Configuration/LoadMembers/LoadMember/Name $uniqueness

rule -Individual /Configuration/LoadMembers/LoadMember/OS `
     -PrereqScript {
  $nodeValue -eq "none"
} `
     -Script $notApplicable `
     -Params @{
  NANodeNames = @(
    "../OSEdition"
    "../OSUpdated"
    "../ScriptParameters"
    "../UsrClass"
    "../OfflineScript"
    "../Unattend"
    "../Script"
    "../Drivers"
    "../OfflinePackages"
    "../Modules"
    "../Packages"
  )
}
rule -Individual /Configuration/LoadMembers/LoadMember/OS `
     -PrereqScript {
  $nodeValue -ne "none"
} `
     -Script {
  $os = @(
    $OSData.OperatingSystems |
      Where-Object {
        $_.Name -eq $nodeValue -or
        $_.Targeting -contains $nodeValue
      } |
      ForEach-Object Name
  )

  if ($os.Count -ne 1) {
    throw "Value could not be used to target a known os. $($os.Count) operating systems matched."
  }

  $node.$valProp = $os[0]
}

rule -Individual /Configuration/LoadMembers/LoadMember/VM/Name `
     -PrereqScript {
  $nodeValue.Length -eq 0
} `
     -Script {
  $node.$valProp = $node.SelectSingleNode("../../Name").InnerXml
}
rule -Individual /Configuration/LoadMembers/LoadMember/VM/Name $constrainedString @{
  Pattern   = "^[A-Za-z0-9 .\-+()]+$"
  MinLength = 1
  MaxLength = 40
}
rule -Aggregate /Configuration/LoadMembers/LoadMember/VM/Name $uniqueness

# Informed by OS, as well as by VHDFormat, if defined. Writes VHDPartitionStyle
# to LoadMember.
rule -Individual /Configuration/LoadMembers/LoadMember/VM/Generation `
     -Script {
  $memberNode = $node.SelectSingleNode("../..")

  if ($memberNode.OS -eq "none") {
    $supportedGenerations = 1,2
  }
  else {
    $supportedGenerations = @(
      $OSData.OperatingSystems |
        Where-Object Name -eq $memberNode.OS |
        ForEach-Object Generations
    )
  }

  if ($memberNode.VHDFormat.Length -gt 0) {
    $vhdFormat_supportedGenerations = @(
      $OSData.Generations |
        Where-Object VHDFormats -contains $memberNode.VHDFormat |
        ForEach-Object Number
    )

    $supportedGenerations = @(
      $supportedGenerations |
        Where-Object {$_ -in $vhdFormat_supportedGenerations}
    )
  }

  if ($node.$valProp.Length -eq 0) {
    $node.$valProp = $supportedGenerations |
                       Sort-Object -Descending |
                       Select-Object -First 1
  }

  # Manual casting of supportedGenerations to string is needed to avoid clumsy
  # automatic casting of the node value during the -in comparison.
  $supportedGenerations = @(
    $supportedGenerations |
      ForEach-Object ToString
  )

  if ($node.$valProp -notin $supportedGenerations) {
    throw "Value is not among the generations supported by the selected operating system and/or vhd format."
  }

  $memberNode.AppendChild(
    $node.
    OwnerDocument.
    CreateElement("VHDPartitionStyle")
  ).InnerXml = $OSData.Generations |
                 Where-Object Number -eq $node.$valProp |
                 ForEach-Object PartitionStyle
}

rule -Individual /Configuration/LoadMembers/LoadMember/VM/Version `
     -PrereqScript {
  $nodeValue.Length -eq 0
} `
     -Script {
  $node.$valProp = $OSData.VMVersionDefault
}
rule -Individual /Configuration/LoadMembers/LoadMember/VM/Version `
     -Script {
  $supportedVersions = @(
    Get-VMHostSupportedVersion |
      Where-Object Version -lt "254.0" | # Exempts pre-release & experimental, if any.
      ForEach-Object Version |
      ForEach-Object ToString
  )

  if ($nodeValue -notin $supportedVersions) {
    throw "Value is not among the vm configuration versions supported by this virtualization host."
  }
}

rule -Individual /Configuration/LoadMembers/LoadMember/VM/ProcessorCount `
     -PrereqScript {
  $nodeValue.Length -eq 0
} `
     -Script {
  $node.$valProp = "1"
}
rule -Individual /Configuration/LoadMembers/LoadMember/VM/ProcessorCount `
     -Script {
  $processorCountMax = (Get-VMHost).LogicalProcessorCount

  if ([int]$nodeValue -lt 1 -or [int]$nodeValue -gt $processorCountMax) {
    throw "Value was not within the range of logical processors supported by this virtualization host: 1 min, $($processorCountMax) max."
  }
}

rule -Individual /Configuration/LoadMembers/LoadMember/VM/Memory `
     -Script {
  $defaultCount = @(
    $node.MinimumBytes,
    $node.StartupBytes,
    $node.MaximumBytes |
      Where-Object {$_.Length -eq 0}
  ).Count

  if ($defaultCount -notin 0,3) {
    throw "Value specification was incomplete. If any memory settings are provided, all must be."
  }

  if ($defaultCount -eq 3) {
    $node.SelectSingleNode("MinimumBytes").InnerXml = 512mb
    $node.SelectSingleNode("StartupBytes").InnerXml = 1gb
    $node.SelectSingleNode("MaximumBytes").InnerXml = 2gb
  }

  $values = @(
    $node.MinimumBytes
    $node.StartupBytes
    $node.MaximumBytes
  )

  foreach ($value in $values) {
    if ([int64]$value -ne 512mb -and ([int64]$value % 1gb) -ne 0) {
      throw "All memory settings must be exactly 512mb or an exact multiple of 1gb."
    }
  }

  if (
    [int64]$node.MinimumBytes -gt [int64]$node.StartupBytes -or
    [int64]$node.StartupBytes -gt [int64]$node.MaximumBytes
  ) {
    throw "Value specification was misordered. MinimumBytes may not be greater than StartupBytes, and StartupBytes may not be greater than MaximumBytes."
  }
}

rule -Individual /Configuration/LoadMembers/LoadMember/VM/NetworkAdapters/NetworkAdapter `
     -Script {
  if ($nodeValue -eq "none") {
    return
  }

  $knownSwitchNames = @(
    $node.SelectNodes("/Configuration/VirtualSwitchDefinitions/VirtualSwitchDefinition/@Name") |
      ForEach-Object "#text"
  )

  if ($nodeValue -eq "default" -and $knownSwitchNames.Count -eq 1) {
    $node.$valProp = $knownSwitchNames[0]
    return
  }

  if ($nodeValue -eq "default") {
    throw "The 'default' value may only be used where one virual switch is defined in the configuration."
  }
  elseif ($nodeValue -notin $knownSwitchNames) {
    throw "Value was not the name of a virtual switch defined in the configuration."
  }

  # Enforce canonical capitalization -- that used in the Switch Definition.
  $node.$valProp = $knownSwitchNames |
                     Where-Object {$_ -eq $nodeValue}
}

rule -Individual /Configuration/LoadMembers/LoadMember/VM/VHDs/VHD/Name `
     -PrereqScript {
  $nodeValue.Length -eq 0
} `
     -Script {
  $nodeListValues = @(
    $node.SelectNodes("../../VHD/Name") |
      ForEach-Object InnerXml
  )

  $inc = 0

  do {
    $inc++

    $nameCandidate = "Disk$($inc)"
  } until ($nameCandidate -notin $nodeListValues)

  $node.$valProp = $nameCandidate
}
rule -Individual /Configuration/LoadMembers/LoadMember/VM/VHDs/VHD/Name `
     -Script $constrainedString `
     -Params @{
  Pattern   = "^[A-Za-z0-9 \-]+$"
  MinLength = 1
  MaxLength = 20
}
1..$loadMemberCount |
  ForEach-Object {
    rule -Aggregate "/Configuration/LoadMembers/LoadMember[$_]/VM/VHDs/VHD/Name" `
         -Script $uniqueness
  }

rule -Individual /Configuration/LoadMembers/LoadMember/VM/VHDs/VHD/SizeBytes `
     -PrereqScript {
  $nodeValue.Length -eq 0
} `
     -Script $vhdDefaultSize
rule -Individual /Configuration/LoadMembers/LoadMember/VM/VHDs/VHD/SizeBytes `
     -Script $vhdSize

rule -Individual /Configuration/LoadMembers/LoadMember/VM/VHDs/VHD/AutoPartition `
     -PrereqScript {
  $nodeValue -eq "false"
} `
     -Script $notApplicable `
     -Params @{
  NANodeNames = @(
    "../Packages"
  )
}

rule -Individual /Configuration/LoadMembers/LoadMember/VM/VHDs/VHD/Packages/Package/@Source `
     -Script $packageSource `
     -Params @{
  PackageType = "VHDPackages"
}
rule -Individual /Configuration/LoadMembers/LoadMember/VM/VHDs/VHD/Packages/Package/@Destination `
     -Script $packageDest `
     -Params @{
  PackageType = "VHDPackages"
}

rule -Individual /Configuration/LoadMembers/LoadMember/OSEdition `
     -PrereqScript {
 $nodeValue -ne "n/a"
} `
     -Script {
  $os = $node.SelectSingleNode("../OS").InnerXml

  $osEditions = @(
    $OSData.OperatingSystems |
      Where-Object Name -eq $os |
      ForEach-Object Editions
  )

  if ($nodeValue.Length -eq 0) {
    $node.$valProp = $osEditions[0]
    return
  }

  if ($nodeValue -notin $osEditions) {
    $targetedEdition = @(
      $OSData.Editions |
        Where-Object Name -in $osEditions |
        Where-Object Targeting -contains $nodeValue |
        ForEach-Object Name
    )

    if ($targetedEdition.Count -eq 1) {
      $nodeValue = $targetedEdition[0]
    }
  }

  if ($nodeValue -notin $osEditions) {
    throw "Unable to target by name or abbreviation an edition of the selected os."
  }

  # Enforce canonical capitalization.
  $node.$valProp = $osEditions | Where-Object {$_ -eq $nodeValue}
}

rule -Individual /Configuration/LoadMembers/LoadMember/VHDSizeBytes `
     -PrereqScript {
  $nodeValue.Length -eq 0
} `
     -Script $vhdDefaultSize
rule -Individual /Configuration/LoadMembers/LoadMember/VHDSizeBytes `
     -Script $vhdSize

rule -Individual /Configuration/LoadMembers/LoadMember/VHDFormat `
     -Script {
  $generation = $node.SelectSingleNode("../VM/Generation").InnerXml

  $supportedFormats = $OSData.Generations |
                        Where-Object Number -eq $generation |
                        ForEach-Object VHDFormats

  if ($nodeValue.Length -eq 0) {
    $node.$valProp = $supportedFormats |
                       Select-Object -First 1
    return
  }

  if ($nodeValue -notin $supportedFormats) {
    throw "VHDFormat '$nodeValue' is not supported by vm generation $generation."
  }
}

# Requires knowing OS, OSEdition, VHDPartitionStyle (which is derived from
# VM/Generation), and VHDFormat. Writes ParentVHD path values to LoadMember
# Node.
rule -Individual /Configuration/LoadMembers/LoadMember/OSUpdated `
     -PrereqScript {
  $nodeValue -ne "n/a"
} `
     -Script {

  $memberNode = $node.SelectSingleNode("..")

  $vhdPaths = @{
    Updated    = Get-VhdPath -Member $memberNode -Updated:$true
    NotUpdated = Get-VhdPath -Member $memberNode -Updated:$false
  }

  $testResults = @{
    Updated    = Test-Path -LiteralPath $vhdPaths.Updated
    NotUpdated = Test-Path -LiteralPath $vhdPaths.NotUpdated
  }

  $updatedMap = @{
    true  = "Updated"
    false = "NotUpdated"
  }

  if ($nodeValue.Length -eq 0) {
    $node.$valProp = $testResults.Updated.ToString().ToLower()
  }

  if (-not $testResults.($updatedMap.($node.$valProp))) {
    throw "No vhd file was found at the path indicated by OS, Edition, VHDPartitionStyle, and VHDFormat settings."
  }

  $memberNode.AppendChild(
    $memberNode.
      OwnerDocument.
      CreateElement("Paths.ParentVHD.Source")
  ).InnerXml = $vhdPaths.($updatedMap.($node.$valProp))

  $memberNode.AppendChild(
    $memberNode.
      OwnerDocument.
      CreateElement("Paths.ParentVHD.InBase")
  ).InnerXml = Join-Path -Path (Get-Path RealizedLoads_Base) `
                         -ChildPath (Split-Path -Path $vhdPaths.($updatedMap.($node.$valProp)) -Leaf)
}

# Improved by knowing VHDFormat
rule -Individual /Configuration/LoadMembers/LoadMember/VHDType `
     -Script {
  $os = $node.SelectSingleNode("../OS").InnerXml
  $vhdFormat = $node.SelectSingleNode("../VHDFormat").InnerXml
  $vhdSize = $node.SelectSingleNode("../VHDSizeBytes").InnerXml

  if ($os -eq 'none') {
    $supportedType = "Dynamic"

    if ($nodeValue.Length -eq 0) {
      $node.$valProp = $supportedType
      return
    }
    elseif ($nodeValue -ne $supportedType) {
      throw "When OS is 'none' VHDType must be 'Dynamic', as there is no OS to difference from."
    }
  }
  elseif ($vhdFormat -eq "vhd" -and $vhdSize -ne 40gb) {
    $supportedType = "Dynamic"

    if ($nodeValue.Length -eq 0) {
      $node.$valProp = $supportedType
      return
    }
    elseif ($nodeValue -ne $supportedType) {
      throw "When VHDFormat is 'vhd' and VHDSizeBytes is not 40gb, VHDType must be 'Dynamic', as differenced vhd files are not compatible with modifications to base size."
    }
  }
  elseif ($nodeValue.Length -eq 0) {
    $node.$valProp = "Differencing"
    return
  }
}

rule -Individual /Configuration/LoadMembers/LoadMember/UsrClass `
     -PrereqScript {
  $nodeValue -notin "n/a","none"
} `
     -Script {
  $usrClassBase = Get-Path UsrClass

  if ($nodeValue.Length -eq 0) {
    $usrClass = @(
      Get-ChildItem -LiteralPath $usrClassBase -File |
        Where-Object Extension -eq .dat |
        Where-Object BaseName -match \.default$ |
        ForEach-Object FullName
    )

    if ($usrClass.Count -ne 1) {
      throw "Unable to target a default UsrClass hive file."
    }
  }
  else {
    $usrClass = @(
      Get-ChildItem -LiteralPath $usrClassBase |
        Where-Object Extension -eq .dat |
        Where-Object {
          $comparisonName = $_.BaseName -replace "\.default$",""
          $comparisonName -eq $nodeValue
        } |
        ForEach-Object FullName
    )

    if ($usrClass.Count -ne 1) {
      throw "Unable to target a UsrClass hive file using the value provided."
    }
  }

  $node.$valProp = $usrClass[0]
}

rule -Individual /Configuration/LoadMembers/LoadMember/OfflineScript `
     -PrereqScript {
  $nodeValue.Length -eq 0
} `
     -Script {
  $node.$valProp = "none"
}

rule -Individual /Configuration/LoadMembers/LoadMember/Unattend `
     -PrereqScript {
  $nodeValue -in "n/a","none"
} `
     -Script $notApplicable `
     -Params @{
  NANodeNames = @(
    "../UnattendTransforms/ComputerName"
    "../UnattendTransforms/UseMemberNameAsComputerName"
  )
}

rule -Individual /Configuration/LoadMembers/LoadMember/UnattendTransforms/UseMemberNameAsComputerName `
     -PrereqScript {
  $nodeValue -ne "n/a"
} `
     -Script {
  $cnNode = $node.SelectSingleNode("../ComputerName")

  if ($cnNode.InnerXml.Length -gt 0 -and $nodeValue -eq "true") {
    throw "Using ComputerName and UseMemberNameAsComputerName on the same LoadMember is not supported; the two are mutually exclusive."
  }
  elseif ($cnNode.InnerXml.Length -gt 0) {
    $node.$valProp = 'false'
    return
  }

  if ($nodeValue -eq 'false') {
    return
  }

  $memberName = $node.SelectSingleNode("../../Name").InnerXml

  $memberNameIsValid = Test-IsValidComputerName $memberName

  if ($nodeValue -eq 'true' -and (-not $memberNameIsValid)) {
    throw "UseMemberNameAsComputerName was explicitly set to 'true'. However, the Name value assigned to this load member was not a valid computer name."
  }

  $node.$valProp = $memberNameIsValid.ToString().ToLower()

  if ($node.$valProp -eq 'true') {
    $cnNode.InnerXml = $memberName
  }
}

rule -Individual /Configuration/LoadMembers/LoadMember/UnattendTransforms/ComputerName `
     -PrereqScript {
  $nodeValue -ne "n/a"
} `
     -Script {
  if ($nodeValue.Length -eq 0) {
    $node.$valProp = "*"
    return
  }

  if (-not (Test-IsValidComputerName $nodeValue)) {
    throw "ComputerName value was not a valid computer name."
  }
}

rule -Individual /Configuration/LoadMembers/LoadMember/Unattend `
     -PrereqScript {
  $nodeValue -notin "n/a","none"
} `
     -Script {
  $unattendBase = Get-Path Unattends
  $os = $node.SelectSingleNode("../OS").InnerXml
  $osEdition = $node.SelectSingleNode("../OSEdition").InnerXml

  $filePrefix = $OSData.OperatingSystems |
                  Where-Object Name -eq $OS |
                  ForEach-Object FilePrefix

  $subPath = $filePrefix,$osEdition -join " - "

  $unattendBase = Join-Path -Path $unattendBase -ChildPath $subPath

  if (-not (Test-Path -LiteralPath $unattendBase)) {
    throw "Could not find a path for unattend files specific to the provided os/edition."
  }

  if ($nodeValue.Length -eq 0) {
    $unattend = @(
      Get-ChildItem -LiteralPath $unattendBase |
        Where-Object BaseName -match \.default$ |
        ForEach-Object FullName
    )

    if ($unattend.Count -ne 1) {
      throw "Unable to target a default unattend xml file."
    }
  }
  else {
    $unattend = @(
      Get-ChildItem -LiteralPath $unattendBase |
        Where-Object {
          $comparisonName = $_.BaseName -replace "\.default$",""
          $comparisonName -eq $nodeValue
        } |
        ForEach-Object FullName
    )

    if ($unattend.Count -ne 1) {
      throw "Unable to target a unattend xml file using the value provided."
    }
  }

  $unattendXml = [xml](
    Get-Content -LiteralPath $unattend -Raw
  )

  $cn = $node.SelectSingleNode("../UnattendTransforms/ComputerName").InnerXml

  $nsm = [System.Xml.XmlNamespaceManager]::new($unattendXml.NameTable)
  $nsm.AddNamespace("urn", $unattendXml.unattend.xmlns)

  $cnNode = $unattendXml.SelectNodes(
    "/urn:unattend/urn:settings[@pass='specialize']/urn:component[@name='Microsoft-Windows-Shell-Setup']/urn:ComputerName",
    $nsm
  )

  # If the cn to be assigned is a random ('*') value lack of a ComputerName
  # node has no impact, since this is default behavior.
  if ($cnNode.Count -gt 1 -or ($cnNode.Count -eq 0 -and $cn -ne "*")) {
    throw "Unable to target an unambiguous 'ComputerName' node in the unattend markup. $($cnNode.Count) matching node(s) were found."
  }
  elseif ($cnNode.Count -eq 1) {
    $cnNode = $cnNode[0]

    $cnNode.InnerXml = $cn
  }

  $node.InnerText = $unattendXml.OuterXml
}

rule -Individual /Configuration/LoadMembers/LoadMember/Script `
     -PrereqScript {
  $nodeValue.Length -eq 0
} `
     -Script {
  $node.$valProp = "none"
}

# Requires knowing Script and OfflineScript
rule -Individual /Configuration/LoadMembers/LoadMember/ScriptParameters `
     -PrereqScript {
  $nodeValue -ne "n/a"
} `
     -Script {
  $offlineScript = $node.SelectSingleNode("../OfflineScript").InnerXml
  $script        = $node.SelectSingleNode("../Script").InnerXml

  if ($offlineScript -eq "none" -and $script -eq "none" -and $nodeValue.Length -eq 0) {
    $node.$valProp = "n/a"
    return
  }
  elseif ($offlineScript -eq "none" -and $script -eq "none") {
    throw "ScriptParameters are only relevant in the context of the OfflineScript and Script, and should not be specified when neither are provided."
  }

  # Write-Warning when "Modules" does not contain "Common", which exposes ScriptParameters to the online Script?

}

rule -Individual /Configuration/LoadMembers/LoadMember/ScriptParameters/ScriptParameter/@Name `
     -Script $constrainedString `
     -Params @{
  Pattern   = "^[A-Za-z0-9]+$"
  MinLength = 1
  MaxLength = 20
}
1..$loadMemberCount |
  ForEach-Object {
    rule -Aggregate "/Configuration/LoadMembers/LoadMember[$_]/ScriptParameters/ScriptParameter/@Name" `
         -Script $uniqueness
  }

rule -Individual /Configuration/LoadMembers/LoadMember/Drivers/Package/@Source `
     -Script $packageSource `
     -Params @{
  PackageType = "Drivers"
}
rule -Individual /Configuration/LoadMembers/LoadMember/Drivers/Package/@Source `
     -Script {
  $infs = @(
    Get-ChildItem -LiteralPath $nodeValue -File -Recurse |
      Where-Object Extension -eq .inf
  )

  if ($infs.Count -eq 0) {
    throw "Each driver source path must contain one or more .inf files."
  }
}
rule -Individual /Configuration/LoadMembers/LoadMember/Drivers/Package/@Destination `
     -Script $packageDest `
     -Params @{
  PackageType = "Drivers"
}

rule -Individual /Configuration/LoadMembers/LoadMember/OfflinePackages/Package/@Source `
     -Script $packageSource `
     -Params @{
  PackageType = "OfflinePackages"
}
rule -Individual /Configuration/LoadMembers/LoadMember/OfflinePackages/Package/@Source `
     -Script {
  $item = Get-Item -LiteralPath $nodeValue

  if ($item -is [System.IO.DirectoryInfo]) {
    $item = @(
      $item |
        Get-ChildItem -File |
        Where-Object Extension -in .cab,.msu
    )

    if ($item.Count -ne 1) {
      throw "If a folder is provided, it must contain exactly one file with the extension '.cab' or '.msu'. $($item.Count) files matching this criteria were found."
    }

    $item = $item[0]
  }

  if ($item.Extension -notin ".cab",".msu") {
    throw "An OfflinePackage source must be a single .cab or .msu file, or a folder containing exactly one file that matches this description."
  }

  $node.OwnerElement.SetAttribute("Source", $item.FullName)
}
rule -Individual /Configuration/LoadMembers/LoadMember/OfflinePackages/Package/@Destination `
     -Script $packageDest `
     -Params @{
  PackageType = "OfflinePackages"
}

rule -Individual /Configuration/LoadMembers/LoadMember/Modules/Package/@Source `
     -Script $packageSource `
     -Params @{
  PackageType = "Modules"
}
rule -Individual /Configuration/LoadMembers/LoadMember/Modules/Package/@Destination `
     -Script $packageDest `
     -Params @{
  PackageType = "Modules"
}

rule -Individual /Configuration/LoadMembers/LoadMember/Packages/Package/@Source `
     -Script $packageSource `
     -Params @{
  PackageType = "Packages"
}
rule -Individual /Configuration/LoadMembers/LoadMember/Packages/Package/@Destination `
     -Script $packageDest `
     -Params @{
  PackageType = "Packages"
}

rule -Individual /Configuration/LoadMembers/LoadMember `
     -Script {
  $properties = [ordered]@{
    MemberName = $node.SelectSingleNode("Name").InnerXml
    VMName     = $node.SelectSingleNode("VM/Name").InnerXml
    VMId       = ""
  }

  $compiledMembers = $node.SelectSingleNode("/Configuration/CompiledMembers")

  $compiledMember = $compiledMembers.AppendChild(
    $node.
      OwnerDocument.
      CreateElement("CompiledMember")
  )

  $properties.GetEnumerator() |
    ForEach-Object {
      $compiledMember.AppendChild(
        $node.
          OwnerDocument.
          CreateElement($_.Key)
      ) | Out-Null

      $compiledMember.($_.Key) = $_.Value
    }
}
#endregion

rule -Aggregate /Configuration/CompiledMembers/CompiledMember/MemberName $uniqueness
rule -Aggregate /Configuration/CompiledMembers/CompiledMember/VMName $uniqueness
rule -Aggregate /Configuration/CompiledMembers/CompiledMember/VMId $uniqueness_nonEmpty

rule -Aggregate /Configuration/CompiledMembers/CompiledMember $atLeastOne

rule -Individual /Configuration/Credentials/Credential/Domain `
     -PrereqScript {
  $nodeValue -ne "."
} `
     -Script $constrainedString `
     -Params @{
  MinLength = 1
  MaxLength = 15
  Pattern   = "^[A-Za-z0-9]+$"
}

# Validation here is more stringent than it has to be -- I'll loosen if I find
# or am presented with a use case.
rule -Individual /Configuration/Credentials/Credential/UserName `
     -Script $constrainedString `
     -Params @{
  MinLength = 1
  MaxLength = 15
  Pattern   = "^[A-Za-z]+$"
}

# No validation on credential passwords.

#region /Configuration/Actions
$actionCount = $Xml.SelectNodes("/Configuration/Actions/Action").Count

rule -Individual /Configuration/Actions/Action/Targets `
     -PrereqScript {
  $nodeValue.Length -eq 0
} `
     -Script {
  $memberNames = $node.SelectNodes("/Configuration/CompiledMembers/CompiledMember/MemberName") |
                   ForEach-Object InnerXml

  $memberNames |
    ForEach-Object {
      $targetNode = $node.AppendChild(
        $node.
        OwnerDocument.
        CreateElement("Target")
      )

      $targetNode.InnerXml = $_
    }
}
rule -Individual /Configuration/Actions/Action/Targets/Target `
     -Script {
  $memberNames = $node.SelectNodes("/Configuration/CompiledMembers/CompiledMember/MemberName") |
                   ForEach-Object InnerXml

  if ($nodeValue -notin $memberNames) {
    throw "Each action target must be the name of a load member defined or imported by the configuration."
  }
}

1..$actionCount |
  ForEach-Object {
    rule -Aggregate /Configuration/Actions/Action[$_]/Targets/Target `
         -Script $uniqueness

    rule -Individual /Configuration/Actions/Action[$_] `
         -Script {
      $targets = $node.SelectNodes("Targets/Target")

      $countLimits = @{
        #Start
        #Stop
        Wait        = 1
        Poke        = 1
        Inject      = 1
        #Custom
        Attended    = 1
        #Checkpoint
        #ExportVM
        #ExportLoad
      }

      # We're straight using $node.type here because navigating to that value
      # using XPath would require negotiating the xsi namespace. This is much
      # easier.
      $type = $node.Type -replace "Action$",""
      $countLimit = $countLimits.$type

      if ($countLimit -ne $null -and $targets.Count -ne $countLimit) {
        throw "An action of type '$type' must apply to only $($countLimit) target member(s)."
      }
    }
  }

rule -Individual "/Configuration/Actions/Action[@xsi:type='CustomAction']/MountVhd" `
     -Script {
  $targets = $node.SelectNodes("../Targets/Target")

  if ($nodeValue.Length -eq 0 -and $targets.Count -eq 1) {
    $node.$valProp = "none"
    return
  }
  elseif ($nodeValue.Length -eq 0 -and $targets.Count -gt 1) {
    $node.$valProp = "n/a"
    return
  }

  if ($targets.Count -gt 1) {
    throw "A custom action may only be configured to mount a vhd when it targets a single member."
  }
}

rule -Individual "/Configuration/Actions/Action[@xsi:type='ExportVMAction']/Destination" `
     -PrereqScript {
  $nodeValue.Length -eq 0     
} `
     -Script {
  $node.$valProp = Get-Path VMExport
}
rule -Individual "/Configuration/Actions/Action[@xsi:type='ExportVMAction']/Destination" `
     -Script {
  if (-not (Test-IsValidRootedPath -Path $nodeValue -ShouldExist $true -ItemType ([System.IO.DirectoryInfo]))) {
    throw "An export destination must be a path to an existing folder on a local volume or network share."
  }
}

rule -Individual "/Configuration/Actions/Action[@xsi:type='ExportLoadAction']/Destination" `
     -PrereqScript {
  $nodeValue.Length -eq 0     
} `
     -Script {
  $node.$valProp = Get-Path LoadExport
}
rule -Individual "/Configuration/Actions/Action[@xsi:type='ExportLoadAction']/Destination" `
     -Script {
  if (-not (Test-IsValidRootedPath -Path $nodeValue -ShouldExist $true -ItemType ([System.IO.DirectoryInfo]))) {
    throw "An export destination must be a path to an existing folder on a local volume or network share."
  }
}

rule -Individual /Configuration/Actions/Action/ScriptParameters/ScriptParameter/@Name `
     -Script $constrainedString `
     -Params @{
  Pattern   = "^[A-Za-z0-9]+$"
  MinLength = 1
  MaxLength = 20
}
1..$actionCount |
  ForEach-Object {
    rule -Aggregate "/Configuration/Actions/Action[$_]/ScriptParameters/ScriptParameter/@Name" `
         -Script $uniqueness
  }

rule -Aggregate /Configuration/Actions/Action $atLeastOne
#endregion

if ($ResolveMode -eq "NamedConfiguration") {
  . $PSScriptRoot\LoadBuilder.RuleEvaluator.Rules.NamedConfiguration.ps1
}
elseif ($ResolveMode -eq "SuppliedConfiguration") {
  . $PSScriptRoot\LoadBuilder.RuleEvaluator.Rules.SuppliedConfiguration.ps1
}

#region Path data for realization
rule -Individual /Configuration `
     -Script {
  $node.AppendChild(
    $node.
    OwnerDocument.
    CreateElement("Paths.Realized")
  ).InnerXml = Join-Path -Path (Get-Path RealizedLoads) -ChildPath $node.Name
}

rule -Individual /Configuration/BaseMembers/BaseMember `
     -Script {
  $cfgNode = $node.SelectSingleNode("/Configuration")

  $realized_vm = $cfgNode."Paths.Realized" | Join-Path -ChildPath $node.VMName
  $realized_vm_config = $realized_vm | Join-Path -ChildPath $node."Paths.Relative.VM.Config"

  $node.AppendChild(
    $node.
    OwnerDocument.
    CreateElement("Paths.Realized.VM")
  ).InnerXml = $realized_vm

  $node.AppendChild(
    $node.
    OwnerDocument.
    CreateElement("Paths.Realized.VM.Config")
  ).InnerXml = $realized_vm_config
}

rule -Individual /Configuration/LoadMembers/LoadMember `
     -Script {
  $cfgNode = $node.SelectSingleNode("/Configuration")

  $realized = Join-Path -Path ($cfgNode."Paths.Realized") -ChildPath $node.VM.Name
  $realized_vhds = Join-Path -Path $realized -ChildPath "Virtual Hard Disks"
  $realized_vhd = Join-Path -Path $realized_vhds -ChildPath "$($node.VM.Name).$($node.VHDFormat)"

  $node.AppendChild(
    $node.
    OwnerDocument.
    CreateElement("Paths.Realized")
  ).InnerXml = $realized

  $node.AppendChild(
    $node.
    OwnerDocument.
    CreateElement("Paths.Realized.VHDs")
  ).InnerXml = $realized_vhds

  $node.AppendChild(
    $node.
    OwnerDocument.
    CreateElement("Paths.Realized.VHD")
  ).InnerXml = $realized_vhd
}

rule -Individual /Configuration/LoadMembers/LoadMember/VM/VHDs/VHD `
     -Script {
  $memberNode = $node.SelectSingleNode("../../..")

  $node.AppendChild(
    $node.
    OwnerDocument.
    CreateElement("Paths.Realized")
  ).InnerXml = Join-Path -Path $memberNode."Paths.Realized.VHDs" `
                         -ChildPath "$($memberNode.VM.Name) $($node.Name).$($memberNode.VHDFormat)"
}
#endregion