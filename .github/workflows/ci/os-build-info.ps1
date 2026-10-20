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
$indicator = @()
try {
  Add-Type -Namespace TlsLibCi -Name Cng -MemberDefinition @'
[DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
public static extern int BCryptOpenAlgorithmProvider(out IntPtr h, string a, string i, uint f);
[DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
public static extern int BCryptGetProperty(IntPtr h, string p, byte[] o, int c, out int r, uint f);
'@
  $alg = [IntPtr]::Zero
  $open = [TlsLibCi.Cng]::BCryptOpenAlgorithmProvider([ref]$alg, 'TLS1_2_KDF', $null, 0)
  foreach ($name in 'Key Derivation', 'KeyDerivation', 'ServiceIndicator', 'FIPS', 'ObjectLength') {
    $buf = New-Object byte[] 64
    $res = 0
    $st = [TlsLibCi.Cng]::BCryptGetProperty($alg, $name, $buf, 64, [ref]$res, 0)
    $indicator += ('Property {0} (open 0x{1:X8}): status 0x{2:X8} len {3}' -f
      $name, $open, $st, $res)
  }
} catch {
  $indicator = @("Property probe: n/a ($($_.Exception.Message))")
}
try {
  $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Include'
  $hdrs = Get-ChildItem -Path $kits -Recurse -Include 'bcrypt.h', 'ncrypt.h' -ErrorAction Stop |
    Select-Object -First 4
  $hits = $hdrs | Select-String -Pattern 'FIPS|INDICATOR|APPROVED' | Select-Object -First 20
  $indicator += @($hits | ForEach-Object { 'Header {0}:{1}: {2}' -f $_.Filename, $_.LineNumber,
    $_.Line.Trim() })
  if (-not $hits) { $indicator += 'Header scan: no FIPS/INDICATOR/APPROVED matches' }
} catch {
  $indicator += "Header scan: n/a ($($_.Exception.Message))"
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
) + $indicator
$lines | ForEach-Object { Write-Host $_ }
if ($env:GITHUB_STEP_SUMMARY) {
  Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value '### Windows build'
  $lines | ForEach-Object { Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value "- $_" }
}
