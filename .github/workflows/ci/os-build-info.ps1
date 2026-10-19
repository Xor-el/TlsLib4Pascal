$ErrorActionPreference = 'Stop'

$version = [System.Environment]::OSVersion.Version
$key = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$dll = (Get-Item 'C:\Windows\System32\bcryptprimitives.dll').VersionInfo
$primitives = "$($dll.FileMajorPart).$($dll.FileMinorPart).$($dll.FileBuildPart).$($dll.FilePrivatePart)"
$lines = @(
  "OSVersion: $version",
  "ProductName: $($key.ProductName)",
  "CurrentBuild: $($key.CurrentBuild)",
  "UBR: $($key.UBR)",
  "DisplayVersion: $($key.DisplayVersion)",
  "Build: 10.0.$($key.CurrentBuild).$($key.UBR)",
  "bcryptprimitives.dll: $primitives"
)
$lines | ForEach-Object { Write-Host $_ }
if ($env:GITHUB_STEP_SUMMARY) {
  Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value '### Windows build'
  $lines | ForEach-Object { Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value "- $_" }
}
