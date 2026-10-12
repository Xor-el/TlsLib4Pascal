# Helper for run-trust.sh's AUTOROOT probe: one action per call, one machine-readable line out.
# Only certificates whose subject equals the fixture intermediate's issuer are ever touched.
param(
  [Parameter(Mandatory)][ValidateSet('ctl', 'strip', 'build', 'restore')][string]$Action,
  [Parameter(Mandatory)][string]$Work,
  [string]$Flags = '0',
  [ValidateSet('plain', 'ex')][string]$Para = 'plain'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$X509 = 'System.Security.Cryptography.X509Certificates'

# ISRG "E5" (issuer ISRG Root X2), SHA-256 E788D14B0436B5120BBEE3F15C15BADF08C1407FE72568A4F16F9151C380E1E3
$Pem = @'
MIICtDCCAjugAwIBAgIQGG511O6woF39Lagghl0eMTAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yNDAzMTMwMDAwMDBaFw0y
NzAzMTIyMzU5NTlaMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNy
eXB0MQswCQYDVQQDEwJFNTB2MBAGByqGSM49AgEGBSuBBAAiA2IABA0LOoprYY62
79xfWOfGQkVUq2P2ZmFICi5ZdbSBAjdQtz8WedyY7KEol3IgHCzP1XxSIE5UeFuE
FGvAkK6F7MBRQTxah38GTdT+YNH6bC3hfZUQiKIIVA+ZGkzm6gqs2KOB+DCB9TAO
BgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFJ8rX888IU+dBLftKyzExnCL0tcN
MB8GA1UdIwQYMBaAFHxClq7eS0g7+pL4nozPbYupcjeVMDIGCCsGAQUFBwEBBCYw
JDAiBggrBgEFBQcwAoYWaHR0cDovL3gyLmkubGVuY3Iub3JnLzATBgNVHSAEDDAK
MAgGBmeBDAECATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veDIuYy5sZW5jci5v
cmcvMAoGCCqGSM49BAMDA2cAMGQCMBttLkVBHEU+2V80GHRnE3m6qym1thBOgydK
i0VOx3vP9EAwHWGl5hxtpJAJkm5GSwIwRikYhDR6vPve2BvYGacE9ct+522E2dqO
6s42MLmigEws5mASS6l2quhtlUfacgkM
'@
$Inter = New-Object "$X509.X509Certificate2" (, [Convert]::FromBase64String(($Pem -replace '\s', '')))
$IssuerDer = [BitConverter]::ToString($Inter.IssuerName.RawData)

$Stores = @(
  @('LocalMachine', 'Root'), @('LocalMachine', 'AuthRoot'), @('LocalMachine', 'CA'),
  @('CurrentUser', 'Root'), @('CurrentUser', 'AuthRoot'), @('CurrentUser', 'CA'))
$SstDir = Join-Path $Work 'sst'
$Saved = Join-Path $Work 'saved.txt'

function Open-Store($loc, $name, $write) {
  $s = New-Object "$X509.X509Store" ($name, $loc)
  $mode = 'IncludeArchived,OpenExistingOnly'
  if ($write) { $mode = "ReadWrite,$mode" } else { $mode = "ReadOnly,$mode" }
  try { $s.Open($mode) } catch { return $null }
  return $s
}

function Find-Issuers($write) { # every R-subject certificate: @{Loc; Name; Store; Cert}
  foreach ($e in $Stores) {
    $s = Open-Store $e[0] $e[1] $write
    if ($null -eq $s) { continue }
    foreach ($c in @($s.Certificates)) {
      if ([BitConverter]::ToString($c.SubjectName.RawData) -eq $IssuerDer) {
        [pscustomobject]@{ Loc = $e[0]; Name = $e[1]; Store = $s; Cert = $c }
      }
    }
    if (-not $write) { $s.Close() }
  }
}

function Add-Sst($loc, $name, $file) {
  $u = @(); if ($loc -eq 'CurrentUser') { $u = @('-user') }
  & certutil @u -addstore -f $name $file | Out-Null
}

switch ($Action) {
  'ctl' {
    $f = Join-Path $Work 'wu.sst'
    Remove-Item $f -ErrorAction SilentlyContinue
    & certutil -generateSSTFromWU $f | Out-Null
    if (-not (Test-Path $f)) { 'ERR generateSSTFromWU produced no file'; break }
    $col = New-Object "$X509.X509Certificate2Collection"
    $col.Import($f)
    $aki = [BitConverter]::ToString(($Inter.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.35' }).RawData) -replace '-', ''
    $hit = $false
    foreach ($c in $col) {
      if ([BitConverter]::ToString($c.SubjectName.RawData) -ne $IssuerDer) { continue }
      $ski = ($c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.14' }).SubjectKeyIdentifier
      if ($ski -and $aki.Contains($ski)) { $hit = $true; "sha1=$($c.Thumbprint)" }
    }
    if ($hit) { 'LISTED' } else { 'NOTLISTED' }
  }
  'strip' {
    New-Item -ItemType Directory -Force $SstDir | Out-Null
    $found = @(Find-Issuers $true)
    if (-not (Test-Path $Saved)) {
      $ok = $true
      try {
        foreach ($g in ($found | Group-Object { "$($_.Loc)_$($_.Name)" })) {
          $col = New-Object "$X509.X509Certificate2Collection"
          foreach ($x in $g.Group) { [void]$col.Add($x.Cert) }
          [IO.File]::WriteAllBytes((Join-Path $SstDir "$($g.Name).sst"), $col.Export('SerializedStore'))
        }
        $rows = [string[]]@($found | ForEach-Object { "$($_.Loc)|$($_.Name)|$($_.Cert.Thumbprint)" })
        [IO.File]::WriteAllLines($Saved, $rows)
      } catch { $ok = $false }
      if (-not $ok) { $found = @() }
    }
    foreach ($x in $found) { try { $x.Store.Remove($x.Cert) } catch { } }
    foreach ($x in $found) { $x.Store.Close() }
    & certutil -urlcache '*' delete | Out-Null
    $left = @(Find-Issuers $false)
    "remaining=$($left.Count)"
  }
  'build' {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AutoRootChain {
  [StructLayout(LayoutKind.Sequential)] struct ENHKEY { public uint c; public IntPtr rg; }
  [StructLayout(LayoutKind.Sequential)] struct UMATCH { public uint type; public ENHKEY usage; }
  [StructLayout(LayoutKind.Sequential)] struct PARA { public uint cb; public UMATCH req; }
  [StructLayout(LayoutKind.Sequential)] struct PARAEX {
    public uint cb; public UMATCH req; public UMATCH pol; public uint timeout; public int fresh;
    public uint freshTime; public IntPtr resync; public IntPtr strong; public uint strongFlags; }
  [StructLayout(LayoutKind.Sequential)] struct TS { public uint err; public uint info; }
  [StructLayout(LayoutKind.Sequential)] struct CCTX { public uint cb; public TS ts; public uint cChain; public IntPtr rgp; }
  [StructLayout(LayoutKind.Sequential)] struct SCHAIN { public uint cb; public TS ts; public uint cElem; public IntPtr rgp; }
  [StructLayout(LayoutKind.Sequential)] struct ELEM { public uint cb; public IntPtr cert; public TS ts; }
  [StructLayout(LayoutKind.Sequential)] struct CCERT { public uint enc; public IntPtr pb; public uint cb; }
  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CertGetCertificateChain(IntPtr engine, IntPtr cert, IntPtr time, IntPtr store,
    IntPtr para, uint flags, IntPtr reserved, out IntPtr ctx);
  [DllImport("crypt32.dll")] static extern void CertFreeCertificateChain(IntPtr ctx);

  public static string Build(IntPtr cert, bool ex, uint flags, uint timeout) {
    IntPtr oid = Marshal.StringToHGlobalAnsi("1.3.6.1.5.5.7.3.1");
    IntPtr arr = Marshal.AllocHGlobal(IntPtr.Size);
    Marshal.WriteIntPtr(arr, oid);
    UMATCH um = new UMATCH();
    um.type = 0;
    um.usage.c = 1;
    um.usage.rg = arr;
    IntPtr para;
    if (ex) {
      PARAEX p = new PARAEX();
      p.req = um; p.timeout = timeout;
      p.cb = (uint)Marshal.SizeOf(typeof(PARAEX));
      para = Marshal.AllocHGlobal((int)p.cb);
      Marshal.StructureToPtr(p, para, false);
    } else {
      PARA p = new PARA();
      p.req = um;
      p.cb = (uint)Marshal.SizeOf(typeof(PARA));
      para = Marshal.AllocHGlobal((int)p.cb);
      Marshal.StructureToPtr(p, para, false);
    }
    IntPtr ctx;
    if (!CertGetCertificateChain(IntPtr.Zero, cert, IntPtr.Zero, IntPtr.Zero, para, flags, IntPtr.Zero, out ctx))
      return "FAILED " + Marshal.GetLastWin32Error();
    try {
      CCTX c = (CCTX)Marshal.PtrToStructure(ctx, typeof(CCTX));
      IntPtr sp = Marshal.ReadIntPtr(c.rgp);
      SCHAIN sc = (SCHAIN)Marshal.PtrToStructure(sp, typeof(SCHAIN));
      IntPtr ep = Marshal.ReadIntPtr(sc.rgp, (int)(sc.cElem - 1) * IntPtr.Size);
      ELEM el = (ELEM)Marshal.PtrToStructure(ep, typeof(ELEM));
      CCERT cc = (CCERT)Marshal.PtrToStructure(el.cert, typeof(CCERT));
      byte[] der = new byte[cc.cb];
      Marshal.Copy(cc.pb, der, 0, (int)cc.cb);
      return c.ts.err + ";" + sc.ts.err + ";" + el.ts.err + ";" + sc.cElem + ";" + Convert.ToBase64String(der);
    } finally { CertFreeCertificateChain(ctx); }
  }
}
'@
    $r = [AutoRootChain]::Build($Inter.Handle, ($Para -eq 'ex'), [Convert]::ToUInt32($Flags, 16), 15000)
    if ($r.StartsWith('FAILED')) { "top=build-failed($r) reappeared=none"; break }
    $p = $r.Split(';')
    $top = New-Object "$X509.X509Certificate2" (, [Convert]::FromBase64String($p[4]))
    $err = [uint32]$p[0] -bor [uint32]$p[1] -bor [uint32]$p[2]
    $isR = [BitConverter]::ToString($top.SubjectName.RawData) -eq $IssuerDer
    if ($err -band 0x20) { $st = 'untrusted-root' }
    elseif ($err -band 0x10000) { $st = 'partial-chain' }
    elseif ($isR) { $st = 'trusted' }
    else { $st = ('other-0x{0:X}' -f $err) }
    $where = @(Find-Issuers $false | ForEach-Object { "$($_.Loc)\$($_.Name)" })
    if ($where.Count -eq 0) { $where = @('none') }
    "top=$st reappeared=$($where -join ',')"
  }
  'restore' {
    $removed = 0; $missing = 0
    if (Test-Path $Saved) {
      $rows = @(Get-Content $Saved | Where-Object { $_ })
      $removed = $rows.Count
      foreach ($sst in Get-ChildItem $SstDir -Filter '*.sst') {
        $loc, $name = $sst.BaseName.Split('_')
        Add-Sst $loc $name $sst.FullName
      }
      $keep = @{}
      foreach ($r in $rows) { $keep[$r] = $true }
      foreach ($x in @(Find-Issuers $true)) {
        $key = "$($x.Loc)|$($x.Name)|$($x.Cert.Thumbprint)"
        if (-not $keep.ContainsKey($key)) { try { $x.Store.Remove($x.Cert) } catch { } }
        $x.Store.Close()
      }
      $now = @{}
      foreach ($x in @(Find-Issuers $false)) { $now["$($x.Loc)|$($x.Name)|$($x.Cert.Thumbprint)"] = $true }
      foreach ($r in $rows) { if (-not $now.ContainsKey($r)) { $missing++ } }
    }
    "removed=$removed restored=$($removed - $missing) missing=$missing"
  }
}
