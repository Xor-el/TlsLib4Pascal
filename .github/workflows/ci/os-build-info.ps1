$ErrorActionPreference = 'Stop'

$version = [System.Environment]::OSVersion.Version
$key = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$dll = (Get-Item 'C:\Windows\System32\bcryptprimitives.dll').VersionInfo
$primitives = @($dll.FileMajorPart, $dll.FileMinorPart, $dll.FileBuildPart,
  $dll.FilePrivatePart) -join '.'
$osArch = 'n/a'
$procArch = 'n/a'
try {
  $ri = [System.Runtime.InteropServices.RuntimeInformation]
  $osArch = [string]$ri::OSArchitecture
  $procArch = [string]$ri::ProcessArchitecture
} catch {
  $osArch = "n/a (PROCESSOR_ARCHITEW6432=$($env:PROCESSOR_ARCHITEW6432))"
  $procArch = "n/a (PROCESSOR_ARCHITECTURE=$($env:PROCESSOR_ARCHITECTURE))"
}
$firmware = 'n/a'
try {
  Add-Type -Namespace TlsLibCi -Name Firmware -MemberDefinition `
    '[DllImport("kernel32.dll")] public static extern bool GetFirmwareType(out uint type);'
  $type = [uint32]0
  if ([TlsLibCi.Firmware]::GetFirmwareType([ref]$type)) {
    $firmware = @{ 1 = 'BIOS'; 2 = 'UEFI' }[[int]$type]
    if (-not $firmware) { $firmware = "other ($type)" }
  }
} catch {
  $firmware = 'n/a (no firmware query)'
}
$lines = @(
  "OSVersion: $version",
  "ProductName: $($key.ProductName)",
  "EditionID: $($key.EditionID)",
  "Firmware: $firmware",
  "CurrentBuild: $($key.CurrentBuild)",
  "UBR: $($key.UBR)",
  "DisplayVersion: $($key.DisplayVersion)",
  "Build: 10.0.$($key.CurrentBuild).$($key.UBR)",
  "bcryptprimitives.dll: $primitives",
  "OSArchitecture: $osArch",
  "ProcessArchitecture: $procArch",
  "Is64BitOperatingSystem: $([System.Environment]::Is64BitOperatingSystem)",
  "Is64BitProcess: $([System.Environment]::Is64BitProcess)"
)
$lines | ForEach-Object { Write-Host $_ }
if ($env:GITHUB_STEP_SUMMARY) {
  Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value '### Windows build'
  $lines | ForEach-Object { Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value "- $_" }
}
