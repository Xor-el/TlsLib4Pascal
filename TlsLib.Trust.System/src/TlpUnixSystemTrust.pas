{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpUnixSystemTrust;

{$I ..\..\TlsLib\src\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpICryptoProvider,
  TlpFileSystemTrust;

type
  /// <summary>
  /// The Unix instantiation of the filesystem anchor store: it supplies the
  /// concrete SSL_CERT_FILE / SSL_CERT_DIR environment variables and the
  /// well-known CA bundle/directory table shared by Linux, the BSDs and
  /// Solaris/illumos, then defers all resolution and harvesting to
  /// TFileSystemRootSource. Adding a Unix flavour is a new row in the table.
  /// </summary>
  TUnixRootSource = class sealed(TFileSystemRootSource)
  strict protected
    function SourceName: string; override;
  public
    /// <summary>Uses the process SSL_CERT_FILE / SSL_CERT_DIR environment and the
    /// built-in path table.</summary>
    constructor Create(const AProvider: ICryptoProvider); overload;
  end;

implementation

type
  /// <summary>
  /// The Unix trust-store discovery table: the environment override variable
  /// names plus the ordered well-known CA bundle files and certificate
  /// directories.
  /// </summary>
  TUnixTrustPaths = class sealed(TObject)
  public
    class function EnvFileVar: string; static;
    class function EnvDirVar: string; static;
    class function CandidateFiles: TArray<string>; static;
    class function CandidateDirs: TArray<string>; static;
  end;

{ TUnixTrustPaths }

class function TUnixTrustPaths.EnvFileVar: string;
begin
  Result := 'SSL_CERT_FILE';
end;

class function TUnixTrustPaths.EnvDirVar: string;
begin
  Result := 'SSL_CERT_DIR';
end;

class function TUnixTrustPaths.CandidateFiles: TArray<string>;
begin
  Result := TArray<string>.Create(
    '/etc/ssl/certs/ca-certificates.crt',     // Debian, Ubuntu, Alpine, Gentoo
    '/etc/pki/tls/certs/ca-bundle.crt',        // Fedora, RHEL, CentOS
    '/etc/ssl/ca-bundle.pem',                  // openSUSE
    '/etc/ssl/cert.pem',                       // OpenBSD, Alpine, DragonFly
    '/usr/local/etc/ssl/cert.pem',             // FreeBSD
    '/usr/local/share/certs/ca-root-nss.crt'   // FreeBSD (ports)
  );
end;

class function TUnixTrustPaths.CandidateDirs: TArray<string>;
begin
  Result := TArray<string>.Create(
    '/etc/ssl/certs',                // Debian, SLES hashed directory
    '/etc/openssl/certs',            // NetBSD
    '/etc/certs/CA'                  // Solaris, illumos
  );
end;

{ TUnixRootSource }

constructor TUnixRootSource.Create(const AProvider: ICryptoProvider);
begin
  inherited Create(AProvider,
    GetEnvironmentVariable(TUnixTrustPaths.EnvFileVar),
    GetEnvironmentVariable(TUnixTrustPaths.EnvDirVar),
    TUnixTrustPaths.CandidateFiles,
    TUnixTrustPaths.CandidateDirs);
end;

function TUnixRootSource.SourceName: string;
begin
  Result := 'Unix';
end;

end.
