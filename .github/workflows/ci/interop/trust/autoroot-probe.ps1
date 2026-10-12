# Helper for run-trust.sh's AUTOROOT probe: one action per call, one machine-readable line out.
# Only certificates whose subject equals the fixture intermediate's issuer are ever touched.
param(
  [Parameter(Mandatory)][ValidateSet('ctl', 'diag', 'leaf', 'capion', 'capioff', 'capidump', 'strip', 'build', 'restore')][string]$Action,
  [Parameter(Mandatory)][string]$Work,
  [string]$Flags = '0',
  [ValidateSet('plain', 'ex')][string]$Para = 'plain',
  [ValidateSet('inter', 'leaf')][string]$Target = 'inter',
  [string]$Thumb = '',
  [int]$Poll = 10,
  [switch]$KeepCache
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
  'diag' {
    function Say($t) { "  diag $t" }
    function Head($u) {
      try {
        $r = Invoke-WebRequest -Uri $u -Method Head -UseBasicParsing -TimeoutSec 15
        return "status=$([int]$r.StatusCode)"
      } catch {
        if ($_.Exception.Response) { return "status=$([int]$_.Exception.Response.StatusCode)" }
        return "exception=$($_.Exception.Message)"
      }
    }
    function Fmt($v) {
      if ($v -is [byte[]]) { return 'bytes[' + $v.Length + ']:' + ([BitConverter]::ToString($v, 0, [Math]::Min(8, $v.Length))) }
      return "$v"
    }
    try {
      $os = Get-CimInstance Win32_OperatingSystem
      Say "os=$($os.Caption) version=$($os.Version) build=$($os.BuildNumber)"
    } catch { Say "os=unreadable" }
    try { $sv = Get-Service CryptSvc; Say "CryptSvc=$($sv.Status)/$($sv.StartType)" } catch { Say "CryptSvc=unreadable" }
    $keys = @(
      'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot',
      'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot',
      'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate')
    foreach ($k in $keys) {
      try {
        if (-not (Test-Path $k)) { Say "reg $k=absent"; continue }
        $p = Get-ItemProperty $k
        $vals = @($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "$($_.Name)=$(Fmt $_.Value)" })
        if ($vals.Count -eq 0) { $vals = @('(no values)') }
        Say "reg $k $($vals -join ' ')"
      } catch { Say "reg $k=unreadable" }
    }
    $sys = "$env:SystemRoot\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache"
    $usr = "$env:USERPROFILE\AppData\LocalLow\Microsoft\CryptnetUrlCache"
    foreach ($d in @("$env:SystemRoot\System32\CatRoot2", "$sys\MetaData", "$sys\Content", "$usr\MetaData", "$usr\Content")) {
      try {
        if (-not (Test-Path $d)) { Say "dir $d=absent"; continue }
        $fs = @(Get-ChildItem $d -Recurse -File -Force -ErrorAction SilentlyContinue)
        $ctl = @($fs | Where-Object { $_.Name -match 'authroot|stl|\.sst' } | ForEach-Object { $_.Name } | Select-Object -First 4)
        Say "dir $d files=$($fs.Count) ctl=$($ctl -join ',')"
      } catch { Say "dir $d=unreadable" }
    }
    $aia = 'none'
    try {
      $ext = $Inter.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.5.5.7.1.1' }
      if ($ext) { $aia = ($ext.Format($false) -replace '\s+', ' ') }
    } catch { }
    Say "E5 AIA: $aia"
    $base = 'http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr'
    Say "head authrootstl.cab $(Head "$base/en/authrootstl.cab")"
    if ($Thumb) { Say "head R .crt $(Head "$base/certs/$Thumb.crt")" }
    if ($aia -match 'URL=(http\S+)') { Say "head AIA $(Head $Matches[1])" }
  }
  'leaf' {
    $out = Join-Path $Work 'leaf.txt'
    Remove-Item $out -ErrorAction SilentlyContinue
    $hostName = 'valid-isrgrootx2.letsencrypt.org'
    $script:got = @()
    try {
      $tcp = New-Object Net.Sockets.TcpClient
      $iar = $tcp.BeginConnect($hostName, 443, $null, $null)
      if (-not $iar.AsyncWaitHandle.WaitOne(10000)) { 'ERR connect timeout'; break }
      $tcp.EndConnect($iar)
      $tcp.ReceiveTimeout = 10000
      $tcp.SendTimeout = 10000
      $cb = [Net.Security.RemoteCertificateValidationCallback]{
        param($s, $c, $ch, $e)
        $script:got = @($ch.ChainElements | ForEach-Object { $_.Certificate })
        return $true
      }
      $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, $cb)
      $ssl.AuthenticateAsClient($hostName, $null, [Security.Authentication.SslProtocols]::Tls12, $false)
      $ssl.Close()
      $tcp.Close()
    } catch { "ERR $($_.Exception.Message)"; break }
    if ($script:got.Count -lt 2) { 'ERR no chain captured'; break }
    $rows = @()
    foreach ($c in $script:got) {
      $self = [BitConverter]::ToString($c.SubjectName.RawData) -eq [BitConverter]::ToString($c.IssuerName.RawData)
      if ($rows.Count -eq 0 -or -not $self) { $rows += [Convert]::ToBase64String($c.RawData) }
    }
    [IO.File]::WriteAllLines($out, [string[]]$rows)
    "LEAF host=$hostName issuer=$($script:got[0].GetNameInfo('SimpleName', $true)) intermediates=$($rows.Count - 1)"
  }
  'capion' {
    $log = 'Microsoft-Windows-CAPI2/Operational'
    $state = Join-Path $Work 'capi2.state'
    $was = 'off'
    if (@(& wevtutil gl $log) -match 'enabled:\s*true') { $was = 'on' }
    if (-not (Test-Path $state)) { Set-Content $state $was }
    & wevtutil sl $log /ms:67108864 | Out-Null
    & wevtutil sl $log /e:true | Out-Null
    & wevtutil cl $log | Out-Null
    "capi2=enabled was=$was"
  }
  'capioff' {
    $log = 'Microsoft-Windows-CAPI2/Operational'
    $state = Join-Path $Work 'capi2.state'
    if (Test-Path $state) {
      if ((Get-Content $state) -eq 'off') { & wevtutil sl $log /e:false | Out-Null }
      Remove-Item $state -ErrorAction SilentlyContinue
    }
    'capi2=restored'
  }
  'capidump' {
    $log = 'Microsoft-Windows-CAPI2/Operational'
    $raw = Join-Path $Work 'capi2-events.txt'
    & wevtutil qe $log /f:text /c:1000 /rd:true | Out-File $raw -Encoding utf8
    $lines = @(Get-Content $raw)
    $ids = @{}
    foreach ($l in $lines) { if ($l -match '^\s*Event ID:\s*(\d+)') { $ids[$Matches[1]] = 1 + [int]$ids[$Matches[1]] } }
    $idText = ($ids.GetEnumerator() | Sort-Object { [int]$_.Name } | ForEach-Object { "$($_.Name)x$($_.Value)" }) -join ' '
    "  capi2 events=$(@($lines | Where-Object { $_ -match '^\s*Event ID:' }).Count) ids: $idText raw=$raw"
    $pat = 'trustedr|authrootstl|ctldl|windowsupdate|CertDownload|RootUpdate|Root update|Auto ?update|lencr|Url|URL|Result|Error|Revocation'
    $seen = @{}
    $n = 0
    foreach ($l in $lines) {
      $t = $l.Trim()
      if ($t -match '^Event ID:\s*\d+' -or $t -match $pat) {
        if ($seen.ContainsKey($t)) { continue }
        $seen[$t] = $true
        "  capi2 | $t"
        $n++
        if ($n -ge 80) { break }
      }
    }
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
    if (-not $KeepCache) { & certutil -urlcache '*' delete | Out-Null }
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
  [DllImport("crypt32.dll", SetLastError = true)]
  static extern IntPtr CertOpenStore(IntPtr provider, uint enc, IntPtr prov, uint flags, IntPtr para);
  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CertAddEncodedCertificateToStore(IntPtr store, uint enc, byte[] pb, uint cb, uint disp, IntPtr ctx);
  [DllImport("crypt32.dll")] static extern bool CertCloseStore(IntPtr store, uint flags);
  [StructLayout(LayoutKind.Sequential)] struct SSLPARA { public uint cb; public uint authType; public uint checks; public IntPtr name; }
  [StructLayout(LayoutKind.Sequential)] struct POLPARA { public uint cb; public uint flags; public IntPtr extra; }
  [StructLayout(LayoutKind.Sequential)] struct POLSTATUS { public uint cb; public uint error; public int chainIdx; public int elemIdx; public IntPtr extra; }
  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CertVerifyCertificateChainPolicy(IntPtr policy, IntPtr ctx, ref POLPARA para, ref POLSTATUS status);

  // "chain|chainElemErrs|policy|elemErr,derB64;..." with every element from leaf to top
  public static string Build(IntPtr cert, byte[][] extras, bool ex, uint flags, uint timeout, bool policy) {
    IntPtr extra = IntPtr.Zero;
    if (extras != null && extras.Length > 0) {
      extra = CertOpenStore((IntPtr)2, 0, IntPtr.Zero, 0, IntPtr.Zero);
      foreach (byte[] d in extras) CertAddEncodedCertificateToStore(extra, 1, d, (uint)d.Length, 4, IntPtr.Zero);
    }
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
    if (!CertGetCertificateChain(IntPtr.Zero, cert, IntPtr.Zero, extra, para, flags, IntPtr.Zero, out ctx)) {
      int e = Marshal.GetLastWin32Error();
      if (extra != IntPtr.Zero) CertCloseStore(extra, 0);
      return "FAILED " + e;
    }
    try {
      CCTX c = (CCTX)Marshal.PtrToStructure(ctx, typeof(CCTX));
      IntPtr sp = Marshal.ReadIntPtr(c.rgp);
      SCHAIN sc = (SCHAIN)Marshal.PtrToStructure(sp, typeof(SCHAIN));
      string els = "";
      for (int i = 0; i < sc.cElem; i++) {
        IntPtr ep = Marshal.ReadIntPtr(sc.rgp, i * IntPtr.Size);
        ELEM el = (ELEM)Marshal.PtrToStructure(ep, typeof(ELEM));
        CCERT cc = (CCERT)Marshal.PtrToStructure(el.cert, typeof(CCERT));
        byte[] der = new byte[cc.cb];
        Marshal.Copy(cc.pb, der, 0, (int)cc.cb);
        if (i > 0) els += ";";
        els += el.ts.err + "," + Convert.ToBase64String(der);
      }
      string pol = "-";
      if (policy) {
        SSLPARA sp2 = new SSLPARA();
        sp2.cb = (uint)Marshal.SizeOf(typeof(SSLPARA));
        sp2.authType = 2;
        IntPtr spp = Marshal.AllocHGlobal((int)sp2.cb);
        Marshal.StructureToPtr(sp2, spp, false);
        POLPARA pp = new POLPARA();
        pp.cb = (uint)Marshal.SizeOf(typeof(POLPARA));
        pp.extra = spp;
        POLSTATUS ps = new POLSTATUS();
        ps.cb = (uint)Marshal.SizeOf(typeof(POLSTATUS));
        pol = CertVerifyCertificateChainPolicy((IntPtr)4, ctx, ref pp, ref ps) ? ps.error.ToString() : "call-failed";
      }
      return c.ts.err + "|" + sc.ts.err + "|" + pol + "|" + els;
    } finally {
      CertFreeCertificateChain(ctx);
      if (extra != IntPtr.Zero) CertCloseStore(extra, 0);
    }
  }
}
'@
    $subject = $Inter
    $extras = [byte[][]]@()
    if ($Target -eq 'leaf') {
      $rows = @()
      $leafFile = Join-Path $Work 'leaf.txt'
      if (Test-Path $leafFile) { $rows = @(Get-Content $leafFile | Where-Object { $_ }) }
      if ($rows.Count -lt 2) { 'top=build-failed(no-leaf) reappeared=none'; break }
      $subject = New-Object "$X509.X509Certificate2" (, [Convert]::FromBase64String($rows[0]))
      $extras = [byte[][]]@($rows | Select-Object -Skip 1 | ForEach-Object { , [Convert]::FromBase64String($_) })
    }
    $r = [AutoRootChain]::Build($subject.Handle, $extras, ($Para -eq 'ex'), [Convert]::ToUInt32($Flags, 16), 15000, ($Target -eq 'leaf'))
    if ($r.StartsWith('FAILED')) { "top=build-failed($r) reappeared=none"; break }
    $p = $r.Split('|')
    $elems = @($p[3].Split(';') | ForEach-Object {
      $q = $_.Split(',')
      [pscustomobject]@{ Err = [uint32]$q[0]; Cert = (New-Object "$X509.X509Certificate2" (, [Convert]::FromBase64String($q[1]))) }
    })
    $top = $elems[$elems.Count - 1]
    $err = [uint32]$p[0] -bor [uint32]$p[1] -bor $top.Err
    $isR = [BitConverter]::ToString($top.Cert.SubjectName.RawData) -eq $IssuerDer
    $aia = $false
    foreach ($e in $elems) {
      if ([BitConverter]::ToString($e.Cert.SubjectName.RawData) -eq $IssuerDer -and
          [BitConverter]::ToString($e.Cert.IssuerName.RawData) -ne $IssuerDer) { $aia = $true }
    }
    if ($err -band 0x20) { $st = 'untrusted-root' }
    elseif ($err -band 0x10000) { $st = 'partial-chain' }
    elseif ($err -eq 0) { $st = 'trusted' }
    else { $st = ('other-0x{0:X}' -f $err) }
    $where = @()
    for ($i = 0; $i -le $Poll; $i++) {
      $where = @(Find-Issuers $false | ForEach-Object { "$($_.Loc)\$($_.Name)" })
      if ($where.Count -gt 0 -or $i -eq $Poll) { break }
      Start-Sleep -Seconds 1
    }
    if ($where.Count -eq 0) { $where = @('none') }
    $els = ($elems | ForEach-Object { '{0}(0x{1:X})' -f $_.Cert.GetNameInfo('SimpleName', $false), $_.Err }) -join '>'
    $pol = $p[2]
    if ($pol -match '^\d+$') { $pol = '0x{0:X}' -f [uint32]$pol }
    "top=$st reappeared=$($where -join ',') after=${i}s topIsR=$isR aia=$aia chain=0x$('{0:X}' -f [uint32]$p[0]),0x$('{0:X}' -f [uint32]$p[1]) policy=$pol els=$els"
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
