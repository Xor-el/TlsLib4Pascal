{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEchRegistryExtension;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpExtensionContext,
  TlpITlsExtension;

type
  /// <summary>
  /// encrypted_client_hello (RFC 9849 sec. 5) as a registry extension, so the block
  /// codec owns its vector position instead of each hello builder splicing it in by
  /// hand. It only frames the body the ECH machinery hands it through the context
  /// (EchExtensionData): the outer/inner ClientHello form, the retry_configs in
  /// EncryptedExtensions, or the 8-byte HelloRetryRequest confirmation. Registered
  /// immediately before pre_shared_key, it lands last (else just before the PSK) in a
  /// ClientHello and last in HelloRetryRequest/EncryptedExtensions - the exact wire
  /// positions the former splices produced.
  /// </summary>
  TEncryptedClientHelloExtension = class sealed(TInterfacedObject, ITlsExtension)
  public
    function ExtensionType: UInt16;
    function ValidContexts: TTlsExtensionContexts;
    function Produce(const AContext: TExtensionContext; out ABody: TBytes): Boolean;
    procedure Consume(const AContext: TExtensionContext; const AExtensionData: TBytes);
  end;

implementation

uses
  TlpCoreExtensions,
  TlpEchExtension;

{ TEncryptedClientHelloExtension }

function TEncryptedClientHelloExtension.ExtensionType: UInt16;
begin
  Result := TExtensionTypes.EncryptedClientHello;
end;

function TEncryptedClientHelloExtension.ValidContexts: TTlsExtensionContexts;
begin
  Result := [TTlsExtensionContextKind.ClientHello,
    TTlsExtensionContextKind.HelloRetryRequest,
    TTlsExtensionContextKind.EncryptedExtensions];
end;

function TEncryptedClientHelloExtension.Produce(const AContext: TExtensionContext;
  out ABody: TBytes): Boolean;
begin
  // the ECH machinery stages the exact body for this message kind; an empty body omits it
  ABody := AContext.EchExtensionData;
  Result := System.Length(ABody) > 0;
end;

procedure TEncryptedClientHelloExtension.Consume(const AContext: TExtensionContext;
  const AExtensionData: TBytes);
begin
  // a HelloRetryRequest carries only the fixed 8-byte accept confirmation; validate its
  // length here (a wrong length is a decode_error) so a malformed one is rejected at parse.
  // The ClientHello (outer/inner) and EncryptedExtensions (retry_configs) forms are recorded
  // raw - the ECH machinery decodes and acts on them with its own status-dependent rules.
  if AContext.MessageContext = TTlsExtensionContextKind.HelloRetryRequest then
    TEchExtension.DecodeHrrConfirmation(AExtensionData);
  AContext.EchPresent := True;
  AContext.EchExtensionData := System.Copy(AExtensionData);
end;

end.
