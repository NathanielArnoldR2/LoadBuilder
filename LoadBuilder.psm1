param(
  [Parameter(
    Position = 0
  )]
  [bool]
  $ExportConfigurationCommands,

  [Parameter(
    Position = 1
  )]
  [bool]
  $ExportRealizationCommands,

  [Parameter(
    Position = 2
  )]
  [bool]
  $UseDefaultResourcePaths
)
<#

TODO -- REPLICATE PREVIOUS CAPABILITY

- Invoke-LoadBuilderAction_*

  - Basic operation of 'Poke' remains to be tested.

  - Behavior of 'Custom' action Script when output is expected.

  - Operation of 'Wait'/'Poke' when a shim is needed.

  - Operation of 'Attended'.

- Monitoring

  - Basic operation.

  - HOWEVER, restoring basic functionality will not produce very useful data
    for modeling. Much more work will be needed to do so.

TODO -- NEW CAPABILITIES

- Build-LoadBuilderMember_ServiceOSVHD

  - UsrClass Application via SetupComplete.cmd

As of Windows 10 v1703, applying a custom UsrClass.dat file to the default user
profile is a two-step process. The temporary user created for the OS OOBE will
inherit any hive present at the "real" path, and a resulting chain of adverse
events will prevent successful completion of setup in at least one of every
three attempts.

Instead, I now copy the UsrClass.dat file to a temporary location, and use the
SetupComplete.cmd construct provided by Windows setup to copy it to the real
location just before (auto)logon of the first interactive user.

This method is problematic because it consumes the SetupComplete.cmd construct
instead of wrapping, augmenting, and exposing it to this tool via PowerShell,
but given the number of things on my plate at the moment a better solution
will have to wait.

  - OfflineScript Invocation

OfflineScript is currently invoked synchronously, directly in parent script
scope, to give its content access to the FileSystem and Registry PSDrives
defined in this function. At some point, I must find a way to invoke this
script asynchronously, with timeout, and in a way that better protects
the parent scope while still providing access to these PSDrives.

Additionally, resources handles within mounted registry hives that are not
closed within the OfflineScript can prevent dismount, and thus cleanup of
resources if indicated by Start-LoadBuilder run parameters. I'm not sure
how my framing environment in this function can account for that.

- Invoke-LoadBuilderAction*

  - Invoke-LoadBuilderAction_Inject

As with 'OfflineScript' above, re: asynchronicity and protecting the parent
scope.

  - Invoke-LoadBuilderAction_Custom

As with 'OfflineScript' above, re: asynchronicity and protecting the parent
scope.

Should also be invoked in a way that does not require specifying the param()
block in the supplied action Script.

Finally, an $AllMembers variable should be available in the custom action
Script in case some other member must be referenced by name in an action
that targets one member for VHD mount.

  - Invoke-LoadBuilderAction_ExportVM

Make it possible to export a vm with the full range of import functionality
(for which the export.data.json file must be present), while preventing
automated overwrite.

This would involve a bespoke property in the json file, which would also
need to be parsed and read in the context of this function.

#>

. $PSScriptRoot\LoadBuilder.WriteOutputTime.ps1

. $PSScriptRoot\LoadBuilder.ResourcePathManager.ps1

if ((-not ($PSBoundParameters.ContainsKey("UseDefaultResourcePaths"))) -or $UseDefaultResourcePaths) {
  . $PSScriptRoot\LoadBuilder.ResourcePaths.ps1
}

$resources = @{}

$resources.ConfigurationCommands = Get-Content -LiteralPath $PSScriptRoot\LoadBuilder.ConfigurationCommands.ps1 -Raw
$resources.ConfigurationAliases = Get-Content -LiteralPath $PSScriptRoot\LoadBuilder.ConfigurationAliases.ps1 -Raw

$resources.ConfigurationSchema = [System.Xml.Schema.XmlSchema]::Read(
  [System.Xml.XmlNodeReader]::new(
    [xml](Get-Content -LiteralPath $PSScriptRoot\LoadBuilder.Configuration.xsd -Raw)
  ),
  $null
)

$resources.ModuleImportScript = {

param(
  [string[]]
  $Filter = @()
)

$directories = Get-ChildItem -LiteralPath $PSScriptRoot |
                 Where-Object {$_ -is [System.IO.DirectoryInfo]}

if ($Filter.Count -gt 0) {
  $directories = $directories |
                   Where-Object {$_.Name -in $Filter}
}

$directories |
  ForEach-Object {
    $directory = $_

    $directory |
      Get-ChildItem |
      Where-Object {
        $_.BaseName -eq $directory.Name -and
        $_.Extension -in ".psd1",".psm1"
      } |
      Sort-Object {$_.Extension -eq ".psd1"} -Descending |
      Select-Object -First 1 |
      ForEach-Object {$_.FullName} |
      Import-Module
  }

if ((Get-Module).Name -contains "CTPackage") {
  Add-CTPackageSource -Name Local -Path C:\CT\Packages
}

}.ToString().Trim()

function Resolve-LoadBuilderConfiguration_EachPass {
  param(
    [Parameter(
      Mandatory = $true
    )]
    [System.Xml.XmlDocument]
    $Xml,

    [Parameter(
      Mandatory = $true
    )]
    [ValidateSet("NamedConfiguration","SuppliedConfiguration")]
    [string]
    $ResolveMode
  )
  try {
    . $PSScriptRoot\LoadBuilder.RuleEvaluator.ps1

    New-Alias -Name rule -Value New-EvaluationRule

    . $PSScriptRoot\LoadBuilder.Rules.ps1

    Remove-Item alias:\rule

    Invoke-EvaluationRules -Xml $Xml -Rules $Rules
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}
function Get-LoadBuilderScriptParameterObject {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [System.Xml.XmlElement]
    $Node
  )

  $ScriptParameters = $Node.SelectNodes("ScriptParameters/ScriptParameter")

  if ($ScriptParameters.Count -eq 0) {
    return
  }

  $outHash = @{}

  foreach ($parameter in $ScriptParameters) {
    $val = $parameter.GetAttribute("Value")

    if ($val -ceq "true") {
      $val = $true
    }
    elseif ($val -ceq "false") {
      $val = $false
    }

    $outHash.$($parameter.GetAttribute("Name")) = $val
  }

  return [PSCustomObject]$outHash
}

#region Load Member Import & Build
function Import-LoadBuilderMember {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Member
  )
  process {
    Write-Verbose "Importing member '$($Member.Name)'."

    $allowDifferenced = $Member.SelectSingleNode("/Configuration/Settings/AllowDifferencedImportFromFastLoadExport").InnerXml -eq "true"
    $useDifferenced = $allowDifferenced -and $Member.PathType -eq "Fast"

    $itemsForDifference = @()
    $itemsForCopy = @(
      Get-ChildItem -LiteralPath $Member.Paths.Source.VM -Recurse -File
    )

    if ($useDifferenced) {
      $itemsForDifference = @($itemsForCopy | Where-Object Extension -in '.vhd','.vhdx')
      $itemsForCopy = @($itemsForCopy | Where-Object Extension -notin '.vhd','.vhdx')
    }

    $itemsForCopy |
      ForEach-Object {
        $destPath = $_.DirectoryName.Replace(
          $Member.Paths.Source.VM,
          $Member.Paths.Realized.VM
        )

        if (-not (Test-Path -LiteralPath $destPath)) {
          New-Item -Path $destPath -ItemType Directory -Force |
            Out-Null
        }

        $_ |
          Copy-Item -Destination $destPath
      }

    $itemsForDifference |
      ForEach-Object {
        $destPath = $_.DirectoryName.Replace(
          $Member.Paths.Source.VM,
          $Member.Paths.Realized.VM
        )

        $destLoc = $destPath | Join-Path -ChildPath $_.Name

        if (-not (Test-Path -LiteralPath $destPath)) {
          New-Item -Path $destPath -ItemType Directory -Force |
            Out-Null
        }

        New-VHD -Path $destLoc -ParentPath $_.FullName |
          Out-Null
      }

    Import-VM -Path $Member.Paths.Realized.VMConfig |
      Out-Null
  }
}

function Build-LoadBuilderMember {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Member
  )
  process {
    Write-Verbose "Building member '$($Member.Name)'."

    New-Item -Path $Member.Paths.Realized.VHDs -ItemType Directory -Force |
      Out-Null

    Write-Verbose "  - Acquiring primary/os vhd."
    if ($Member.OS -ne "none" -and $Member.VHDType -eq "Differencing") {
      if (-not (Test-Path -LiteralPath $Member.Paths.Realized_Base.VHD -PathType Leaf)) {
        Copy-Item -LiteralPath $Member.Paths.Source.VHD `
                  -Destination $Member.Paths.Realized_Base.VHD
      }

      New-VHD -ParentPath $Member.Paths.Realized_Base.VHD `
              -Path $Member.Paths.Realized.VHD |
        Out-Null
    }
    elseif ($Member.OS -ne 'none') {
      Copy-Item -LiteralPath $Member.Paths.Source.VHD `
                -Destination $Member.Paths.Realized.VHD
    }
    elseif ($Member.OS -eq 'none') {
      New-VHD -Path $Member.Paths.Realized.VHD -SizeBytes $Member.VHDSizeBytes |
        Out-Null
    }

    $Member.SelectNodes("VM/VHDs/VHD") |
      Build-LoadBuilderMember_BuildAdditionalVHD

    $Member |
      Build-LoadBuilderMember_BuildVM

    $Member |
      Build-LoadBuilderMember_ServiceOSVHD
  }
}

function Copy-LoadBuilderVHDPackage {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Package,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $VolumeRoot
  )
  process {
    $DestinationPath = Join-Path -Path $VolumeRoot -ChildPath $Package.GetAttribute("Destination")

    $Destination = Join-Path -Path $DestinationPath `
                             -ChildPath (Split-Path -Path $Package.GetAttribute("Source") -Leaf)

    if (Test-Path -LiteralPath $Destination) {
      throw "Package already exists at intended destination."
    }

    if (-not (Test-Path -LiteralPath $DestinationPath)) {
      New-Item -Path $DestinationPath -ItemType Directory -Force |
        Out-Null
    }

    Copy-Item -LiteralPath $Package.GetAttribute("Source") `
              -Destination $DestinationPath `
              -Recurse
  }
}

function Build-LoadBuilderMember_BuildAdditionalVHD {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $VHD
  )
  process {
    Write-Verbose "  - Building additional vhd '$($VHD.Name)'."

    New-VHD -Path $VHD.Paths.Realized -SizeBytes $VHD.SizeBytes |
      Out-Null

    if ($VHD.AutoPartition -ne "true") {
      return
    }

    $partitionStyle = $VHD.SelectSingleNode("../../../VHDPartitionStyle").InnerXml

    $disk = Mount-VHD -Path $VHD.Paths.Realized -Passthru |
              Get-Disk |
              Initialize-Disk -PartitionStyle $partitionStyle -PassThru

    $disk |
      New-Partition -UseMaximumSize |
      Out-Null

    $disk |
      Get-Partition |
      Get-Volume |
      Format-Volume -NewFileSystemLabel $VHD.Name |
      Out-Null

    $packages = $VHD.SelectNodes("Packages/Package")

    if ($packages.Count -gt 0) {
      $disk |
        Get-Partition |
        Where-Object Size -gt 1gb |
        Add-PartitionAccessPath -AssignDriveLetter

      do {
        Start-Sleep -Milliseconds 250

        $volumeRoot = $disk |
                        Get-Partition |
                        Where-Object DriveLetter |
                        ForEach-Object {$_.DriveLetter + ":\"}
      } until ($volumeRoot -ne $null -and (Get-PSDrive | Where-Object Root -eq $volumeRoot) -ne $null)

      $packages |
        Copy-LoadBuilderVHDPackage -VolumeRoot $volumeRoot
    }

    Dismount-VHD -Path $VHD.Paths.Realized
  }
}

function Build-LoadBuilderMember_BuildVM {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Member
  )
  process {

    Write-Verbose "  - Building vm."

    # For the "Path" attribute, New-VM expects the location where the full
    # "VMName/Virtual Machines/GUID.vmcx" folder structure will reside,
    # which is the path of the realized load entire, rather than any
    # associated with the member itself.
    $VMPath = $Member.SelectSingleNode("/Configuration").Paths.Realized

    $VM = New-VM -Name $Member.VM.Name `
                 -Path $VMPath `
                 -VHDPath $Member.Paths.Realized.VHD `
                 -Generation $Member.VM.Generation `
                 -Version $Member.VM.Version

    $SetParameters = @{
      AutomaticStartAction = "Nothing"
      ProcessorCount = $Member.VM.ProcessorCount
    }

    # The "if" framing is needed to retain compatibility w/ Windows builds -lt
    # 15063 (v1703) -- which includes my own NA-SVR-STORAGE.
    if ((Get-Command Set-VM).Parameters.ContainsKey("AutomaticCheckpointsEnabled")) {
      $SetParameters.AutomaticCheckpointsEnabled = $false
    }

    if (
      $Member.VM.Memory.MinimumBytes -eq $Member.VM.Memory.StartupBytes -and
      $Member.VM.Memory.StartupBytes -eq $Member.VM.Memory.MaximumBytes  
    ) {
      $SetParameters.StaticMemory = $true
      $SetParameters.MemoryStartupBytes = $Member.VM.Memory.StartupBytes
    }
    else {
      $SetParameters.DynamicMemory = $true
      $SetParameters.MemoryMinimumBytes = $Member.VM.Memory.MinimumBytes
      $SetParameters.MemoryStartupBytes = $Member.VM.Memory.StartupBytes
      $SetParameters.MemoryMaximumBytes = $Member.VM.Memory.MaximumBytes
    }

    $VM |
      Set-VM @SetParameters

    $VM |
      Get-VMNetworkAdapter |
      Remove-VMNetworkAdapter

    $NetworkAdapters = $Member.SelectNodes("VM/NetworkAdapters/NetworkAdapter") |
                         ForEach-Object InnerXml

    foreach ($SwitchName in $NetworkAdapters) {
      if ($SwitchName -eq "none") {
        $VM |
          Add-VMNetworkAdapter
      }
      else {
        $VM |
          Add-VMNetworkAdapter -SwitchName $SwitchName
      }
    }

   $Member.SelectNodes("VM/VHDs/VHD") |
      Where-Object AutoAttach -eq true |
      ForEach-Object {
        $VM |
          Add-VMHardDiskDrive -Path $_.Paths.Realized
      }

    $CompiledMember = $Member.SelectNodes("/Configuration/CompiledMembers/CompiledMember") |
                        Where-Object MemberName -eq $Member.Name

    $CompiledMember.VMId = $VM.Id.ToString()
  }
}

function Build-LoadBuilderMember_ServiceOSVHD {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Member
  )
  process {
    if ($Member.OS -eq "none") {
      return
    }

    $Drivers = $Member.SelectNodes("Drivers/Package") |
                 ForEach-Object GetAttribute Source
    $OfflinePackages = $Member.SelectNodes("OfflinePackages/Package") |
                         ForEach-Object GetAttribute Source
    $Modules = $Member.SelectNodes("Modules/Package")
    $Packages = $Member.SelectNodes("Packages/Package")

    if (
      $Member.VHDSizeBytes -eq 40gb -and
      $Member.UsrClass -eq "none" -and
      $Member.OfflineScript -eq "none" -and
      $Member.Unattend -eq "none" -and
      $Member.Script -eq "none" -and
      $Drivers.Count -eq 0 -and
      $OfflinePackages.Count -eq 0 -and
      $Modules.Count -eq 0 -and
      $Packages.Count -eq 0
    ) {
      return
    }

    Write-Verbose "  - Servicing os vhd."

    if ($Member.VHDSizeBytes -ne 40gb) {
      Resize-VHD -Path $Member.Paths.Realized.VHD -SizeBytes $Member.VHDSizeBytes
    }

    $partition = Mount-VHD -Path $Member.Paths.Realized.VHD -Passthru |
                   Get-Partition |
                   Where-Object Size -gt 1gb

    $volumeRoot = $partition |
                    ForEach-Object {$_.DriveLetter + ":\"}

    do {
      Start-Sleep -Milliseconds 250
    } until ((Get-PSDrive | Where-Object Root -eq $volumeRoot) -ne $null)

    if ($Member.VHDSizeBytes -ne 40gb) {
      $sizeMax = $partition |
                   Get-PartitionSupportedSize |
                   ForEach-Object SizeMax

      $partition |
        Resize-Partition -Size $sizeMax
    }

    $paths = @{
      Def_NTUSER_OL = Join-Path -Path $volumeRoot -ChildPath Users\Default\NTUSER.DAT
      Def_UsrClass_Staged_REL = "Users\Default\AppData\Local\Microsoft\Windows\UsrClass.dat.Staged"
      Def_UsrClass_Final_OS = "C:\Users\Default\AppData\Local\Microsoft\Windows\UsrClass.dat"
      SetupComplete = Join-Path -Path $volumeRoot -ChildPath Windows\Setup\Scripts\SetupComplete.cmd
    }

    $paths.Def_UsrClass_Staged_OL = Join-Path -Path $volumeRoot -ChildPath $paths.Def_UsrClass_Staged_REL
    $paths.Def_UsrClass_Staged_OS = Join-Path -Path C:\ -ChildPath $paths.Def_UsrClass_Staged_REL

    if ($Member.UsrClass -ne "none") {
      Copy-Item -LiteralPath $Member.UsrClass -Destination $paths.Def_UsrClass_Staged_OL

      New-Item -Path $paths.SetupComplete `
               -ItemType File `
               -Value "move $($paths.Def_UsrClass_Staged_OS) $($paths.Def_UsrClass_Final_OS)" `
               -Force |
        Out-Null
    }

    if ($Member.OfflineScript -ne "none") {
      $paths.Hive_Backup = New-Item -Path (Join-Path -Path $volumeRoot -ChildPath 'CT\Temp\Hive Backup') `
                                     -ItemType Directory `
                                     -Force |
                             ForEach-Object FullName

      $paths.Def_NTUSER_OL,
      $paths.Def_UsrClass_Staged_OL |
        Where-Object {Test-Path -LiteralPath $_} |
        Copy-Item -Destination $paths.Hive_Backup

      Invoke-LoadBuilderServicingScript `
      -ImageRoot $volumeRoot `
      -ImageRootName IMG `
      -ServicingScript $Member.OfflineScript `
      -ScriptParameters (Get-LoadBuilderScriptParameterObject -Node $Member) `
      -MountRegistryResources
    }

    if ($Member.Unattend -ne "none") {
      New-Item -Path $volumeRoot `
               -Name unattend.xml `
               -Value $Member.Unattend `
               -Force |
        Out-Null
    }

    if ($Member.Script -ne "none") {
      $scriptPath = Join-Path -Path $volumeRoot -ChildPath CT\script.ps1

      New-Item -Path $scriptPath -Value $Member.Script -Force |
        Out-Null
    }

    if ($Drivers.Count -gt 0) {
      $Drivers |
        ForEach-Object {
          Add-WindowsDriver -Driver $_ `
                            -Path $volumeRoot `
                            -Recurse `
                            -ForceUnsigned `
                            -WarningAction SilentlyContinue
        } |
        Out-Null
    }

    if ($OfflinePackages.Count -gt 0) {
      $OfflinePackages |
        ForEach-Object {
          Add-WindowsPackage -PackagePath $_ -Path $volumeRoot -Verbose:$false
        } |
        Out-Null
    }

    if ($Modules.Count -gt 0) {
      $ModulesPath = Join-Path -Path $volumeRoot -ChildPath $Modules[0].GetAttribute("Destination")

      $Modules |
        Copy-LoadBuilderVHDPackage -VolumeRoot $volumeRoot

      New-Item -Path $ModulesPath `
               -Name import.ps1 `
               -Value $script:resources.ModuleImportScript `
               -Force |
        Out-Null


      $commonPath = Join-Path -Path $ModulesPath -ChildPath Common
      $scriptParameters = Get-LoadBuilderScriptParameterObject -Node $Member

      if ((Test-Path -LiteralPath $commonPath -PathType Container) -and $scriptParameters -is [PSCustomObject]) {
        New-Item -Path $commonPath `
                 -Name ScriptParameters.json `
                 -ItemType File `
                 -Value ($scriptParameters | ConvertTo-Json) `
                 -Force |
          Out-Null
      }
    }

    if ($Packages.Count -gt 0) {
      $Packages |
        Copy-LoadBuilderVHDPackage -VolumeRoot $volumeRoot
    }

    Dismount-VHD -Path $Member.Paths.Realized.VHD
 
  }
}

function Invoke-LoadBuilderServicingScript {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $ImageRoot,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $ImageRootName,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $ServicingScript,

    [PSCustomObject]
    $ScriptParameters,

    [switch]
    $MountRegistryResources
  )

  function New-PSDriveObj ($Name, $PSProvider, $Root, $Description) {
    [PSCustomObject]@{
      Name        = $Name
      PSProvider  = $PSProvider
      Root        = $Root
      Description = $Description
    }
  }

  $drives = @(
    New-PSDriveObj -Name $ImageRootName `
                   -PSProvider FileSystem `
                   -Root $ImageRoot `
                   -Description "FileSystem Root"
  )

  if ($MountRegistryResources) {
    $drives += @(
      New-PSDriveObj -Name "$($ImageRootName)_REG_SYS" `
                     -PSProvider Registry `
                     -Root (Join-Path -Path $ImageRoot -ChildPath Windows\System32\config\SYSTEM) `
                     -Description "System Registry"

      New-PSDriveObj -Name "$($ImageRootName)_REG_SW" `
                     -PSProvider Registry `
                     -Root (Join-Path -Path $ImageRoot -ChildPath Windows\System32\config\SOFTWARE) `
                     -Description "Software Registry"

      New-PSDriveObj -Name "$($ImageRootName)_REG_DEF" `
                     -PSProvider Registry `
                     -Root (Join-Path -Path $ImageRoot -ChildPath Users\Default\NTUSER.DAT) `
                     -Description "Default Profile Registry"

      New-PSDriveObj -Name "$($ImageRootName)_REG_DEF_CLS" `
                     -PSProvider Registry `
                     -Root (Join-Path -Path $ImageRoot -ChildPath Users\Default\AppData\Local\Microsoft\Windows\UsrClass.dat.Staged) `
                     -Description "Default Profile Classes Registry"
    )
  }

  foreach ($drive in $drives) {
    if (-not (Test-Path -LiteralPath $drive.Root)) {
      continue
    }

    if ($drive.PSProvider -eq "Registry") {
      & reg load "HKLM\$($drive.Name)" $drive.Root |
        Out-Null

      $drive.Root = "HKLM:\$($drive.Name)"
    }

    New-PSDrive -Name $drive.Name `
                -PSProvider $drive.PSProvider `
                -Root $drive.Root `
                -Description $drive.Description |
      Out-Null
  }

  $pl = $Host.Runspace.CreateNestedPipeline()
  $cmd = [System.Management.Automation.Runspaces.Command]::new('param($scriptParameters)', $true)
  $cmd.Parameters.Add(
    [System.Management.Automation.Runspaces.CommandParameter]::new(
      'scriptParameters',
      $ScriptParameters
    )
  )
  $pl.Commands.Add($cmd)
  $pl.Commands.AddScript('$scriptParams = $scriptParameters')
  $pl.Commands.AddScript($ServicingScript)
  $pl.Invoke() | Out-Null

  # Mandatory before registry unload.
  [System.GC]::Collect()

  foreach ($drive in $drives) {
    if ((Get-PSDrive | where-Object Name -eq $drive.Name) -eq $null) {
      continue
    }

    Remove-PSDrive -Name $drive.Name

    if ($drive.PSProvider -eq "Registry") {
      & reg unload "HKLM\$($drive.Name)" |
        Out-Null
    }
  }
}
#endregion

#region Monitoring (Currently inoperative; Rework and Reimplement)
function Start-LoadBuilderMonitoring ($config) {
  Start-Task "Initializing performance monitoring"

  $collXml = @"
<DataCollectorSet>
    <OutputLocation />
    <RootPath />
	<PerformanceCounterDataCollector>
        <SampleInterval>1</SampleInterval>
		<Counter>\Hyper-V Dynamic Memory Balancer(System Balancer)\Available Memory</Counter>
		<Counter>\Hyper-V Dynamic Memory VM(*)\Average Pressure</Counter>
		<Counter>\Hyper-V Dynamic Memory VM(*)\Physical Memory</Counter>
		<Counter>\Hyper-V Hypervisor Logical Processor(*)\% Total Run Time</Counter>
		<Counter>\Hyper-V Hypervisor Logical Processor(*)\Context Switches/sec</Counter>
		<Counter>\Hyper-V Hypervisor Root Virtual Processor(_Total)\% Guest Run Time</Counter>
		<Counter>\Hyper-V Hypervisor Virtual Processor(*)\% Guest Run Time</Counter>
		<Counter>\Hyper-V Virtual Network Adapter(*)\Bytes/sec</Counter>
		<Counter>\Hyper-V Virtual Storage Device(*)\Read Bytes/sec</Counter>
		<Counter>\Hyper-V Virtual Storage Device(*)\Write Bytes/sec</Counter>
		<Counter>\Hyper-V Virtual Storage Device(*)\Read Operations/Sec</Counter>
		<Counter>\Hyper-V Virtual Storage Device(*)\Write Operations/Sec</Counter>
		<Counter>\Hyper-V VM Vid Partition(*)\Remote Physical Pages</Counter>
		<Counter>\LogicalDisk(*)\Avg. Disk sec/Transfer</Counter>
		<Counter>\LogicalDisk(*)\% Idle Time</Counter>
		<Counter>\LogicalDisk(*)\Free Megabytes</Counter>
		<Counter>\LogicalDisk(*)\Disk Bytes/sec</Counter>
		<Counter>\LogicalDisk(*)\Disk Transfers/sec</Counter>
		<Counter>\Network Interface(*)\Bytes Total/sec</Counter>
	</PerformanceCounterDataCollector>
</DataCollectorSet>
"@ -as [xml]

  $commitMode = @{
    Create         = 0x1
    Modify         = 0x2
    CreateOrModify = 0x3
  }

  $collName = "$($config.Name)_$((Get-Date).ToString("yyy_MM_dd_HH_mm_ss"))"

  $path = Join-Path -Path (Get-Path PerfMonLogs) -ChildPath "$($config.Name)\$((Get-Date).ToString("yyy_MM_dd_HH_mm_ss"))"

  $collXml.DataCollectorSet.OutputLocation = $path.ToString()
  $collXml.DataCollectorSet.RootPath = $path.ToString()

  $collObj = New-Object -ComObject Pla.DataCollectorSet
  $collObj.SetXml($collXml.OuterXml) | Out-Null
  $collObj.Commit(
    $collName,
    $null, # Commit to this computer
    $commitMode.Create
  ) | Out-Null

  $collObj.Start($true) |
    Out-Null

  Complete-Task -Status Info "Done!"

  return $collName
}

function Stop-LoadBuilderMonitoring ($collName) {
  Start-Task "Stopping performance monitoring"

  $collObj = New-Object -ComObject Pla.DataCollectorSet
  $collObj.Query(
    $buildData.DataCollectorSetName,
    $null # From local computer.
  ) | Out-Null

  $collObj.Stop($true) |
    Out-Null

  $collObj.Delete() |
    Out-Null

  Complete-Task -Status Info "Done!"
}
#endregion

#region Actions Orchestration
function Do-LoadBuilderPokeAction ($Action, $TargetId, $TargetCredentials) {
  Test-LoadBuilderActionTargetState $TargetId Poke Running

  $params = @{
    VMId = $TargetId
  }

  if ($Action.UseShim) {
    $params.UseShim = $true
    $params.Credentials = @(
      $TargetCredentials |
        ForEach-Object {
          [pscredential]::new(
            "$($_.Domain)\$($_.UserName)",
            (ConvertTo-SecureString -String $_.Password -AsPlainText -Force)
          )
        }
    )
  }

  Start-KvpPokeAckHandshake @params
}

function Test-LoadBuilderActionTargetState {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [Microsoft.HyperV.PowerShell.VirtualMachine]
    $VM,

    [Parameter(
      Mandatory = $true
    )]
    [Microsoft.HyperV.PowerShell.VMState]
    $RequiredState
  )
  process {
    try {
      $currentState = $VM |
                        Get-VM |
                        ForEach-Object State

      if ($currentState -ne $RequiredState) {
        throw "Action requires VM be in '$RequiredState' state."
      }
    } catch {
      $PSCmdlet.ThrowTerminatingError($_)
    }
  }
}

function Invoke-LoadBuilderAction_Start {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Action,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $Targets,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $AllMembers
  )
  process {
    $Targets |
      ForEach-Object VMId |
      Get-VM |
      Test-LoadBuilderActionTargetState -RequiredState Off

    $Targets |
      ForEach-Object VMId |
      Get-VM |
      Start-VM

    if ($Action.WaitForHeartbeat -ne "true") {
      return
    }

    Write-Verbose "  - Waiting for heartbeat(s)."

    do {
      Start-Sleep -Seconds 60

      $vmHeartbeat = @(
        $Targets |
          ForEach-Object VMId |
          Get-VM |
          ForEach-Object {$_.Heartbeat.ToString().Substring(0, 2)} |
          Sort-Object -Unique
      )

    } until ($vmHeartbeat.Count -eq 1 -and $vmHeartbeat[0] -ceq "Ok")
  }
}
function Invoke-LoadBuilderAction_Stop {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Action,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $Targets,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $AllMembers
  )
  process {
    $Targets |
      ForEach-Object VMId |
      Get-VM |
      Test-LoadBuilderActionTargetState -RequiredState Running

    $Targets |
      ForEach-Object VMId |
      Get-VM |
      Stop-VM -Force

    Write-Verbose "  - Waiting for shutdown."

    do {
      Start-Sleep -Seconds 5

      $VMState = @(
        $Targets |
          ForEach-Object VMId |
          Get-VM |
          ForEach-Object State |
          Sort-Object -Unique
      )
    } until ($VMState.Count -eq 1 -and $VMState[0] -eq "Off")
  }
}
function Invoke-LoadBuilderAction_Wait {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Action,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $Targets,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $AllMembers
  )
  process {
    $Targets |
      ForEach-Object VMId |
      Get-VM |
      Test-LoadBuilderActionTargetState -RequiredState Running

    $params = @{
      VMId = $Targets | ForEach-Object VMId
    }

    if ($Action.UseShim -eq "true") {
      $params.UseShim = $true
      $params.Credentials = @(
        $Action.SelectNodes("/Configuration/Credentials/Credential") |
          ForEach-Object {
            [pscredential]::new(
              "$($_.Domain)\$($_.UserName)",
              (ConvertTo-SecureString -String $_.Password -AsPlainText -Force)
            )
          }
      )
    }

    Start-KvpFinAckHandshake @params
  }
}
function Invoke-LoadBuilderAction_Poke {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Action,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $Targets,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $AllMembers
  )
  process {
    $Targets |
      ForEach-Object VMId |
      Get-VM |
      Test-LoadBuilderActionTargetState -RequiredState Running

    $params = @{
      VMId = $Targets | ForEach-Object VMId
    }

    if ($Action.UseShim -eq "true") {
      $params.UseShim = $true
      $params.Credentials = @(
        $Action.SelectNodes("/Configuration/Credentials/Credential") |
          ForEach-Object {
            [pscredential]::new(
              "$($_.Domain)\$($_.UserName)",
              (ConvertTo-SecureString -String $_.Password -AsPlainText -Force)
            )
          }
      )
    }

    Start-KvpPokeAckHandshake @params
  }
}
function Invoke-LoadBuilderAction_Inject {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Action,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $Targets,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $AllMembers
  )
  process {
    $Targets |
      ForEach-Object VMId |
      Get-VM |
      Test-LoadBuilderActionTargetState -RequiredState Running

    Write-Verbose "  - Targeting credential for PowerShell Direct."

    $Credentials = @(
      $Action.SelectNodes("/Configuration/Credentials/Credential") |
        ForEach-Object {
          [pscredential]::new(
            "$($_.Domain)\$($_.UserName)",
            (ConvertTo-SecureString -String $_.Password -AsPlainText -Force)
          )
        }
    )
    $VMId = $Targets | ForEach-Object VMId
    $Credential = $null

    $shout = {"The mountains are singing, and the Lady comes."}

    $inc = 1
    do {
      foreach ($CredentialCandidate in $Credentials) {
        $echo = Invoke-Command -VMId $VMId `
                               -ScriptBlock $shout `
                               -Credential $CredentialCandidate `
                               -ErrorAction Ignore

        if ($echo -eq $shout.Invoke()) {
          $Credential = $CredentialCandidate
          break
        }
      }

      $inc++
    } while ($Credential -eq $null -and $inc -le 5)

    if ($Credential -eq $null) {
      throw "Unable to target working PowerShell Direct credential for action script."
    }

    Write-Verbose "  - Invoking PowerShell Direct."

    $session = New-PSSession -VMId $VMId -Credential $Credential

    Invoke-Command -Session $session `
                   -ScriptBlock {param($ScriptParameters)} `
                   -ArgumentList (Get-LoadBuilderScriptParameterObject -Node $Action) |
      Out-Null

    $Script = [scriptblock]::Create($Action.Script)

    Invoke-Command -Session $session -ScriptBlock $Script |
      Out-Null

    Remove-PSSession -Session $session
  }
}
function Invoke-LoadBuilderAction_Custom {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Action,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $Targets,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $AllMembers
  )
  process {
    if ($Action.MountVhd -notin 'none','n/a') {
      $Targets |
        ForEach-Object VMId |
        Get-VM |
        Test-LoadBuilderActionTargetState -RequiredState Off

      $item = $Targets |
                ForEach-Object VMId |
                Get-VM |
                Get-VMHardDiskDrive |
                Select-Object -Index $Action.MountVhd |
                ForEach-Object Path |
                Get-Item

      if ($item -isnot [System.IO.FileInfo]) {
        throw "No vhd associated with member '$($Targets | ForEach-Object Name)' was found at index $($Action.MountVhd)."
      }

      if ($item.Extension -notin '.vhd','.vhdx') {
        throw "The selected vhd has an invalid extension. Only .vhd and .vhdx files are supported; resources associated with vm checkpoints are not."
      }

      $partition = Mount-VHD -Path $item.FullName -Passthru |
                     Get-Partition |
                     Where-Object Size -gt 1gb

      if ($partition.DriveLetter -eq [char]$null) {
        $partition |
          Add-PartitionAccessPath -AssignDriveLetter

        $partition = $partition |
                       Get-Partition
      }

      $volumeRoot = $partition |
                      ForEach-Object {$_.DriveLetter + ":\"}

      do {
        Start-Sleep -Milliseconds 250
      } until ((Get-PSDrive | Where-Object Root -eq $volumeRoot) -ne $null)

      New-PSDrive -Name VHD -PSProvider FileSystem -Root $volumeRoot |
        Out-Null
    }

    if ($Action.ExpectOutput -eq "true") {
      Write-Verbose ("-" * 80)
    }

    $pl = $Host.Runspace.CreateNestedPipeline()
    if ($Targets.Count -eq 1) {
      $cmd = [System.Management.Automation.Runspaces.Command]::new('param($VM, $ScriptParameters, $AllMembers)', $true)
      $cmd.Parameters.Add(
        [System.Management.Automation.Runspaces.CommandParameter]::new('VM', (Get-VM -Id $Targets[0].VMId))
      )
    }
    else {
      $cmd = [System.Management.Automation.Runspaces.Command]::new('param($Targets, $ScriptParameters, $AllMembers)', $true)
      $cmd.Parameters.Add(
        [System.Management.Automation.Runspaces.CommandParameter]::new('Targets', $Targets)
      )
    }
    $cmd.Parameters.Add(
      [System.Management.Automation.Runspaces.CommandParameter]::new(
        'ScriptParameters',
        (Get-LoadBuilderScriptParameterObject -Node $Action)
      )
    )
    $cmd.Parameters.Add(
      [System.Management.Automation.Runspaces.CommandParameter]::new('AllMembers', $AllMembers)
    )
    $pl.Commands.Add($cmd)
    $pl.Commands.AddScript($Action.Script)
    $pl.Invoke() | Out-Null

    if ($Action.ExpectOutput -eq "true") {
      Write-Verbose ("-" * 80)
    }

    if ($item -is [System.IO.FileInfo]) {
      Dismount-VHD -Path $item.FullName
    }
  }
}
function Invoke-LoadBuilderAction_Attended {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Action,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $Targets,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $AllMembers
  )
  process {
    $Targets |
      ForEach-Object VMId |
      Get-VM |
      Test-LoadBuilderActionTargetState -RequiredState Running

    Write-UserAlertMessage

    Write-Verbose "  - $($Action.Description)"
    Write-Verbose "  - When finished, simply close the vm connection to continue."
    Write-Verbose "  - Press [Enter] to connect to the vm."

    do {
      $keyInfo = [Console]::ReadKey($true)
    }
    while ($keyInfo.Key -ne [System.ConsoleKey]::Enter)

    $process = Start-Process "$env:SystemRoot\System32\vmconnect.exe" "localhost -G $($Targets | ForEach-Object VMId)" -PassThru

    $process | Wait-Process

    Write-Verbose "  - VM connection has closed."
  }
}
function Invoke-LoadBuilderAction_Checkpoint {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Action,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $Targets,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $AllMembers
  )
  process {

    $Targets |
      ForEach-Object VMId |
      Get-VM |
      Test-LoadBuilderActionTargetState -RequiredState Off

    if ($Action.OptimizeVhds -eq "true") {
      Write-Verbose "  - Optimizing vm storage."
      $Targets |
        ForEach-Object VMId |
        Get-VM |
        Get-VMHardDiskDrive |
        ForEach-Object Path |
        Optimize-VHD -Mode Full
    }

    $Targets |
      ForEach-Object VMId |
      Get-VM |
      Checkpoint-VM -SnapshotName $Action.CheckpointName

  }
}
function Invoke-LoadBuilderAction_ExportVM {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Action,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $Targets,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $AllMembers
  )
  process {
    $Targets |
      ForEach-Object VMId |
      Get-VM |
      Test-LoadBuilderActionTargetState -RequiredState Off

    if ($Action.OptimizeVhds -eq "true") {
      Write-Verbose "  - Optimizing vm storage."
      $Targets |
        ForEach-Object VMId |
        Get-VM |
        Get-VMHardDiskDrive |
        ForEach-Object Path |
        Optimize-VHD -Mode Full
    }

    $ExportSourceItems = @(
      $Targets |
        ForEach-Object VMId |
        Get-VM |
        ForEach-Object Path |
        Get-Item
    )

    # Philosophical question: How carefully should I validate VM state at this
    # juncture? Should I try to do so at all? There are a limited number of
    # ways to get an export right, and a nearly unlimited number of ways
    # to get it wrong. Am I responsible for trying to intercept all of
    # them?
    #
    # Consider that even Microsoft's System Center Configuration Manager limits
    # the scenarios in which it will fail gracefully. Try to attach read-only
    # storage to a site system server without applying the no_sms_on_drive
    # file, for example, and SCCM on that server will fail HARD!

    $ExportDestinationPaths = @(
      $ExportSourceItems |
        ForEach-Object {
          Join-Path -Path $Action.Destination -ChildPath $_.Name
        }
    )

    $HasProtectedItems = @(
      $ExportDestinationPaths |
        Where-Object {Test-Path -LiteralPath $_} |
        Where-Object {-not (Test-Path -LiteralPath $_\export.data.json -PathType Leaf)}
    ).Count -gt 0

    if ($HasProtectedItems) {
      throw "Some items meant for export already exist in the export path, and are not flagged for automated regeneration."
    }

    $ExportDestinationPaths |
      Where-Object {Test-Path -LiteralPath $_} |
      Remove-Item -Recurse

    $ExportDate = [datetime]::Now

    $ExportSourceItems |
      ForEach-Object {
        Write-Verbose "  - Exporting vm '$($_.Name)'."

        $_ |
          Copy-Item -Destination $Action.Destination -Recurse

        $jsonPath = $Action.Destination |
                      Join-Path -ChildPath $_.Name |
                      Join-Path -ChildPath export.data.json

        $jsonData = [PSCustomObject]@{
          Origin          = "LoadBuilder"
          ExportDate      = $ExportDate
          SpecialHandling = $Action.SpecialHandling
        } | ConvertTo-Json

        New-Item -Path $jsonPath -ItemType File -Value $jsonData |
          Out-Null
      }

    if ($Action.RemoveRealizedLoad) {
      Remove-LoadBuilderRealizedLoad -Name $Action.SelectSingleNode("/Configuration/Name").InnerXml
    }
  }
}
function Invoke-LoadBuilderAction_ExportLoad {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Action,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $Targets,

    [Parameter(
      Mandatory = $true
    )]
    [Object[]]
    $AllMembers
  )
  process {
    $Targets |
      ForEach-Object VMId |
      Get-VM |
      Test-LoadBuilderActionTargetState -RequiredState Off

    if ($Action.OptimizeVhds -eq "true") {
      Write-Verbose "  - Optimizing vm storage."
      $Targets |
        ForEach-Object VMId |
        Get-VM |
        Get-VMHardDiskDrive |
        ForEach-Object Path |
        Optimize-VHD -Mode Full
    }

    $ExportSourceItems = @(
      $Targets |
        ForEach-Object VMId |
        Get-VM |
        ForEach-Object Path |
        Get-Item
    )

    $ExportDestinationPath = Join-Path -Path $Action.Destination -ChildPath $Action.SelectSingleNode("/Configuration/Name").InnerXml
    $ExportJsonPath = Join-Path -Path $ExportDestinationPath -ChildPath export.data.json

    if (
      (Test-Path -LiteralPath $ExportDestinationPath) -and
      (-not (Test-Path -LiteralPath $ExportJsonPath -PathType Leaf))
    ) {
      throw "An exported version of this load already exists in the export path, but is not flagged for automated regeneration."
    }
    elseif (Test-Path -LiteralPath $ExportDestinationPath) {
      Remove-Item -LiteralPath $ExportDestinationPath -Recurse
    }

    New-Item -Path $ExportDestinationPath -ItemType Directory -ErrorAction Stop |
      Out-Null

    $ExportSourceItems |
      ForEach-Object {
        Write-Verbose "  - Exporting vm '$($_.Name)'."

        $_ |
          Copy-Item -Destination $ExportDestinationPath -Recurse
      }

    Write-Verbose "  - Writing export data json."

    $ExportJson = @(
      $Targets |
        ForEach-Object {
          [PSCustomObject]@{
            MemberName = $_.Name
            VMName     = Get-VM $_.VMId | ForEach-Object Name
            VMId       = $_.VMId
          }
        }
    ) | ConvertTo-Json

    New-Item -Path $ExportJsonPath -Value $ExportJson |
      Out-Null

    if ($Action.RemoveRealizedLoad) {
      Remove-LoadBuilderRealizedLoad -Name $Action.SelectSingleNode("/Configuration/Name").InnerXml
    }
  }
}

function Invoke-LoadBuilderAction {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Xml.XmlElement]
    $Action
  )
  process {
    try {
      $type = $Action.type -replace "Action$",""

      $targetNames = $Action.SelectNodes("Targets/Target") |
                       ForEach-Object InnerXml

      $compiledMembers = $Action.SelectNodes("/Configuration/CompiledMembers/CompiledMember")

      # Due to an obscure bug, live VM objects cannot be passed to the
      # constituent Action functions -- they tend to unexpectedly
      # acquire a "$null" value while being passed along the
      # pipeline to the "Test-TargetState" function.
      $AllMembers = @(
        $compiledMembers |
          ForEach-Object {
            [PSCustomObject]@{
              Name = $_.MemberName
              VMId = [guid]$_.VMId
            }
          }
      )
      $Targets = @(
        $AllMembers |
          Where-Object Name -in $targetNames
      )

      if ($Targets.Count -eq 1) {
        $msgAug = "member '$($Targets[0].Name)'"
      }
      elseif ($Targets.Count -lt $AllMembers.Count) {
        $msgAug = "$($Targets.Count) of $($AllMembers.Count) members"
      }
      else {
        $msgAug = "all members"
      }

      # I really don't want to embed all constituent Action_type functions in
      # the try/catch framing. Hopefull, the ErrorAction Stop here will make
      # errors throw, and suspend the load before an export-related teardown.
      Write-Verbose "Invoking action '$type' with $msgAug."
      $Action |
        & "Invoke-LoadBuilderAction_$type" -Targets $Targets -AllMembers $AllMembers -ErrorAction Stop
    } catch {
      $PSCmdlet.ThrowTerminatingError($_)
    }
  }
}
#endregion

#region Exported Functions
function New-LoadBuilderConfigurationFile {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Name
  )
  try {
    $configItem = @(
      Get-ChildItem -LiteralPath (Get-Path Configurations) -File -Recurse |
        Where-Object Extension -eq .ps1 |
        Where-Object BaseName -eq $Name
    )

    if ($configItem.Count -gt 0) {
      $exception = [System.Exception]::new("A configuration file with this name already exists in the defined configurations path or a subfolder thereof.")
      $exception.Data.Add("Name", $Name)

      throw $exception
    }

    $configPath = Join-Path -Path (Get-Path Configurations) -ChildPath "$($Name).ps1"

    Copy-Item -LiteralPath (Get-Path ConfigTemplate) -Destination $configPath

    New-LoadBuilderShortcuts -Name $Name
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Get-LoadBuilderConfiguration {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Name
  )

  try {
    Write-Verbose "Retrieving configuration from file w/ basename '$Name'."
    $configItem = @(
      Get-ChildItem -LiteralPath (Get-Path Configurations) -File -Recurse |
        Where-Object Extension -eq .ps1 |
        Where-Object BaseName -eq $Name
    )

    if ($configItem.Count -eq 0) {
      $exception = [System.Exception]::new("Named configuration not found in the defined configurations path or a subfolder thereof.")
      $exception.Data.Add("Name", $Name)

      throw $exception
    }

    if ($configItem.Count -gt 1) {
      $exception = [System.Exception]::new("Named configuration exists at multiple locations within the defined configurations path.")
      $exception.Data.Add("Name", $Name)
      $exception.Data.Add("Path1", $configItem[0].DirectoryName)
      $exception.Data.Add("Path2", $configItem[1].DirectoryName)

      throw $exception
    }

    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $rs.Open()

    $rs.CreatePipeline($script:resources.ConfigurationCommands).Invoke() | Out-Null
    $rs.CreatePipeline($script:resources.ConfigurationAliases).Invoke() | Out-Null
    $rs.CreatePipeline('$config = New-LoadBuilderConfiguration').Invoke() | Out-Null
    
    try {
      $rs.CreatePipeline((Get-Content -LiteralPath $configItem[0].FullName -Raw)).Invoke() | Out-Null
    } catch {
      $exception = [System.Exception]::new(
        "Error while processing config definition file.",
        $_.Exception
      )

      throw $exception
    }

    $config = $rs.CreatePipeline('$config').Invoke()[0]
    $rs.Close()

    if ($config -isnot [System.Xml.XmlElement]) {
      throw "Error while retrieving config definition. Object retrieved was not an XmlElement."
    }

    $nameNode = $config.SelectSingleNode("/Configuration/Name")

    if ($nameNode -isnot [System.Xml.XmlElement]) {
      throw "Error while retrieving config definition. Could not select element node for Name assignment."
    }

    $nameNode.InnerXml = $configItem.BaseName

    Write-Verbose "Validating retrieved configuration against xml schema."
    Test-LoadBuilderConfiguration -Configuration $config

    $config
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Test-LoadBuilderConfiguration {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [System.Xml.XmlNode]
    $Configuration
  )
  try {
    if ($Configuration -is [System.Xml.XmlElement]) {
      $Configuration = $Configuration.OwnerDocument
    }

    $TestXml = $Configuration.OuterXml -as [xml]
    $TestXml.Schemas.Add($script:resources.ConfigurationSchema) |
      Out-Null
    $TestXml.Validate($null)
  } catch {
    $exception = [System.Exception]::new(
      "Error while validating config definition",
      $_.Exception
    )

    throw $exception
  }
}

function Resolve-LoadBuilderConfiguration {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [System.Xml.XmlNode]
    $Configuration,

    [Parameter(
      Mandatory = $true
    )]
    [ValidateSet("NamedConfiguration","SuppliedConfiguration")]
    [string]
    $ResolveMode,
    
    [string]
    $Alternate
  )
  try {
    if ($Configuration -is [System.Xml.XmlElement]) {
      $Configuration = $Configuration.OwnerDocument
    }

    $OutputXml = $BasePassXml = $Configuration.OuterXml -as [xml]

    # This pass of Test-LoadBuilderConfiguration is verbose-silent because a
    # "Named" configuration will already have been validated on retrieval,
    # while a "Supplied" configuration should have been validated before
    # being submitted for resolution. This is included as a failsafe.
    Test-LoadBuilderConfiguration -Configuration $BasePassXml

    Write-Verbose "Validating & resolving configuration against available resources."
    Resolve-LoadBuilderConfiguration_EachPass -Xml $BasePassXml -ResolveMode $ResolveMode

    if ($ResolveMode -eq "NamedConfiguration" -and $Alternate.Length -gt 0) {
      $OutputXml = $AltPassXml = $Configuration.OuterXml -as [xml]

      $AltPassXml.SelectSingleNode("/Configuration/AlternateName").InnerXml = ""
      $AltPassXml.SelectSingleNode("/Configuration/Alternates").InnerXml = ""

      Write-Verbose "Targeting a compiled alternate configuration with name '$Alternate'."
      $compiledAlternates = $BasePassXml.SelectNodes("/Configuration/CompiledAlternates/CompiledAlternate")
      $compiledAlternate = $compiledAlternates |
                             Where-Object Name -eq $Alternate

      if ($compiledAlternate -isnot [System.Xml.XmlElement]) {
        $exception = [System.Exception]::new("Alternate configuration not found.")
        $exception.Data.Add("ConfigurationName", $BasePassXml.Name)
        $exception.Data.Add("AlternateName", $Alternate)

        throw $exception
      }

      $originalName = $Configuration.SelectSingleNode("/Configuration/Name").InnerXml
      $scripts = $compiledAlternate.SelectNodes("Scripts/Script") |
                   ForEach-Object InnerText

      Write-Verbose "Applying $($scripts.Count) transformation script(s) to unresolved configuration to derive the alternate configuration."
      $scriptIndex = 0
      foreach ($script in $scripts) {
        $scriptIndex++

        $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
        $rs.Open()

        $rs.CreatePipeline($script:resources.ConfigurationCommands).Invoke() | Out-Null
        $rs.CreatePipeline($script:resources.ConfigurationAliases).Invoke() | Out-Null

        $pl = $rs.CreatePipeline()
        $cmd = [System.Management.Automation.Runspaces.Command]::new('param($config)', $true)
        $cmd.Parameters.Add(
          [System.Management.Automation.Runspaces.CommandParameter]::new('config', $AltPassXml.SelectSingleNode("/Configuration"))
        )
        $pl.Commands.Add($cmd)
        $pl.Invoke() | Out-Null

        try {
          $rs.CreatePipeline($script).Invoke() | Out-Null
        } catch {
          $exception = [System.Exception]::new(
            "Error while processing transform script for alternate configuration.",
            $_.Exception
          )

          $exception.Data.Add("ConfigurationName", $originalName)
          $exception.Data.Add("AlternateName", $compiledAlternate.Name)
          $exception.Data.Add("ScriptNumber", "$($scriptIndex) of $($scripts.Count)")

          throw $exception
        } finally {
          $rs.Close()
        }
      }

      Write-Verbose "Validating alternate configuration against xml schema."
      Test-LoadBuilderConfiguration -Configuration $AltPassXml

      if ($AltPassXml.SelectSingleNode("/Configuration/Name").InnerXml -ne $originalName) {
        throw "Alternate configuration transform scripts may not change the original configuration name."
      }

      Write-Verbose "Validating & resolving alternate configuration against available resources."
      Resolve-LoadBuilderConfiguration_EachPass -Xml $AltPassXml -ResolveMode "SuppliedConfiguration"

      $AltPassXml.SelectSingleNode("/Configuration/AlternateName").InnerXml = $compiledAlternate.Name
    }
    elseif ($Alternate.Length -gt 0) {
      throw "An alternate configuration may not be targeted in this context."
    }

    return $OutputXml.SelectSingleNode("/Configuration")
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function New-LoadBuilderShortcuts {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $Name
  )
  try {
    $config = Get-LoadBuilderConfiguration -Name $Name
    $config = Resolve-LoadBuilderConfiguration -Configuration $config -ResolveMode NamedConfiguration

    $configPath = Get-ChildItem -LiteralPath (Get-Path Configurations) -File -Recurse |
                    Where-Object Extension -eq .ps1 |
                    Where-Object BaseName -eq $Name |
                    ForEach-Object FullName

    $interfacePath = $configPath.Replace(
      (Get-Path Configurations),
      (Get-Path Interface)
    ) -replace "\.ps1$",""

    if (-not (Test-Path -LiteralPath $interfacePath)) {
      New-Item -Path $interfacePath -ItemType Directory -Force |
        Out-Null
    }
    else {
      Get-ChildItem -LiteralPath $interfacePath |
        Remove-Item -Force
    }

    function New-ShortcutData ($Name, $Params, [switch]$NoExit, [switch]$RunAsAdministrator) {
      [PSCustomObject]@{
        Name               = $Name
        Params             = $Params
        NoExit             = [bool]$NoExit
        RunAsAdministrator = [bool]$RunAsAdministrator
      }
    }

    $shortcutData = @()

    $shortcutData += New-ShortcutData "Update Shortcuts" "Update Shortcuts",$config.Name
    $shortcutData += $null

    $shortcutName = "Start Load"
    if ($config.AlternateName -ne 'n/a') {
      $shortcutName += " ($($config.AlternateName))"
    }
    $shortcutData += New-ShortcutData $shortcutName "Start Load",$config.Name -RunAsAdministrator

    $compiledAlternates = $config.SelectNodes("/Configuration/CompiledAlternates/CompiledAlternate/Name") |
                            ForEach-Object InnerXml

    foreach ($alternate in $compiledAlternates) {
      $shortcutData += New-ShortcutData "Start Load ($alternate)" "Start Load",$config.Name,$alternate -RunAsAdministrator
    }

  $shortcutData += New-ShortcutData "End Load" "End Load",$config.Name -RunAsAdministrator

  $inc = 1
  foreach ($dataObj in $shortcutData) {
    if ($dataObj -ne $null) {
      $params = @{
        ScriptPath = Get-Path ShortcutHandler
        ShortcutPath = Join-Path -Path $interfacePath -ChildPath "$inc $($dataObj.Name).lnk"
        ScriptParameters = $dataObj.Params
        NoExit = $dataObj.NoExit
        RunAsAdministrator = $dataObj.RunAsAdministrator
      }

      New-ScriptShortcut @params
    }

    $inc++
  }

  New-Shortcut -ShortcutPath (Join-Path -Path $interfacePath -ChildPath "2 Edit Config.lnk") `
               -TargetPath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" `
               -Arguments "/File `"$configPath`""
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Start-LoadBuilder {
  [CmdletBinding(
    PositionalBinding = $false,
    DefaultParameterSetName = "NamedConfiguration"
  )]
  param(
    [Parameter(
      ParameterSetName = "NamedConfiguration",
      Mandatory = $true
    )]
    [string]
    $Name,

    [Parameter(
      ParameterSetName = "NamedConfiguration"
    )]
    [string]
    $Alternate,

    [Parameter(
      ParameterSetName = "SuppliedConfiguration",
      Mandatory = $true
    )]
    [System.Xml.XmlElement]
    $Configuration
  )
  $resultObj = [PSCustomObject]@{
    "Load Origin"            = $null
    "Configuration Name"     = $null
    "Alternate Name"         = $null
    "Raw Configuration"      = $null
    "Resolved Configuration" = $null
    "Processing Status"      = "Initial"
    "Start Time"             = [datetime]::Now
    "End Time"               = $null
    "Duration"               = $null
    "Error Record"           = $null
  }

  try {
    if ($PSCmdlet.ParameterSetName -eq "NamedConfiguration") {
      $resultObj."Load Origin" = "Named"
      $resultObj."Processing Status" = "Retrieving and validating to schema."

      $Configuration = Get-LoadBuilderConfiguration -Name $Name
    }
    else {
      $resultObj."Load Origin" = "Supplied"
      $resultObj."Processing Status" = "Validating to schema."

      Write-Verbose "Validating supplied configuration against xml schema."
      Test-LoadBuilderConfiguration -Configuration $Configuration
    }

    $resultObj."Configuration Name" = $Configuration.Name
    $resultObj."Raw Configuration" = $Configuration
    $resultObj."Processing Status" = "Validating and resolving to available resources."

    $resultObj."Resolved Configuration" = 
    $Configuration = 
    Resolve-LoadBuilderConfiguration `
    -Configuration $Configuration `
    -ResolveMode $PSCmdlet.ParameterSetName `
    -Alternate $Alternate `
    -ErrorAction Stop

    $resultObj."Alternate Name" = $Configuration.AlternateName
    $resultObj."Processing Status" = "Constructing load members."

    if (Test-Path -LiteralPath $Configuration.Paths.Realized) {
      Remove-LoadBuilderRealizedLoad -Name $Configuration.Name -ErrorAction Stop
    }

    New-Item -Path $Configuration.Paths.Realized -ItemType Directory -Force |
      Out-Null

    $Configuration |
      ForEach-Object VirtualSwitchDefinitions |
      ForEach-Object VirtualSwitchDefinition |
      Where-Object Present -eq false |
      ForEach-Object {
        Write-Verbose "Building '$($_.Type)' virtual switch with name '$($_.Name)'."
        New-VMSwitch -Name $_.Name -SwitchType $_.Type
      } |
      Out-Null

    $Configuration.SelectNodes("BaseMembers/BaseMember") |
      Import-LoadBuilderMember |
      Out-Null

    $Configuration.SelectNodes("LoadMembers/LoadMember") |
      Build-LoadBuilderMember |
      Out-Null

    $resultObj."Processing Status" = "Orchestrating actions."

    $Configuration |
      ForEach-Object Actions |
      ForEach-Object Action |
      Invoke-LoadBuilderAction |
      Out-Null

    $resultObj."End Time" = [datetime]::Now
    $resultObj."Duration" = $resultObj."End Time" - $resultObj."Start Time"
    $resultObj."Processing Status" = "Complete"
  } catch {
    $resultObj."Error Record" = $_
  }
  $resultObj
}

function Remove-LoadBuilderRealizedLoad {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    $Name
  )
  try {
    Write-Verbose "Removing existing realized load with name '$Name'."

    $loadPath = Join-Path -Path (Get-Path RealizedLoads) -ChildPath $Name

    if (-not (Test-Path -LiteralPath $loadPath)) {
      throw "No realized load by this name was found at the expected path."
    }

    $vms = @(
      Get-VM |
        Where-Object Path -like $loadPath*
    )

    Get-Process |
      Where-Object Name -eq vmconnect |
      Where-Object {
        $vmName = $_.MainWindowTitle -replace " on (?:$([System.Net.Dns]::GetHostName())|localhost) - Virtual Machine Connection$",""

        $vmName -in @($vms | ForEach-Object Name)
      } |
      Stop-Process

    $vms |
      Where-Object State -ne Off |
      Stop-VM -TurnOff -Force

    $vms |
      Get-VMSnapshot |
      Where-Object ParentSnapshotId -eq $null |
      Restore-VMSnapshot -Confirm:$false

    $vms |
      Remove-VM -Force

    # Troubleshooting inability to remove the path immediately after VM removal.
    Start-Sleep -Milliseconds 250

    Remove-Item $loadPath -Recurse -Force
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}
#endregion

$exportFunctions = @(
  "Set-LoadBuilderPath"
  "Get-LoadBuilderPath"
  "New-LoadBuilderConfigurationFile"
  "Get-LoadBuilderConfiguration"
  "Test-LoadBuilderConfiguration"
  "Resolve-LoadBuilderConfiguration"
  "New-LoadBuilderShortcuts"
  "Start-LoadBuilder"
  "Remove-LoadBuilderRealizedLoad"
)

if ((-not ($PSBoundParameters.ContainsKey("ExportConfigurationCommands"))) -or $ExportConfigurationCommands) {
  $cmdScript = [scriptblock]::Create($script:resources.ConfigurationCommands)

  . $cmdScript

  $exportFunctions += $cmdScript.Ast.EndBlock.Statements |
                        ForEach-Object Name
}

Export-ModuleMember -Function $exportFunctions