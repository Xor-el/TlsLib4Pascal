{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpEchOuterExtensions;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpCoreExtensions,
  TlpEchExtension,
  TlpExtensionVector,
  TlpTlsAlert,
  TlpTlsLibExceptions;

type
  /// <summary>
  /// The ClientHelloInner extension compression of RFC 9849 sec. 5.1. The client
  /// replaces a chosen set of extensions in the EncodedClientHelloInner with one
  /// ech_outer_extensions block; the server reconstructs the full inner extensions by
  /// copying the referenced extensions out of the ClientHelloOuter. The compressible
  /// set is a non-normative client choice; reconstruction is the security-sensitive
  /// side and is done with a single forward cursor so the four RFC failure conditions
  /// (missing, duplicate reference, encrypted_client_hello referenced, out of order)
  /// hold by construction.
  /// </summary>
  TEchOuterExtensions = class sealed(TObject)
  strict private
    class function CheckNoDuplicate(const ATypes: TArray<UInt16>): Boolean; static;
  public
    /// <summary>
    /// Whether an extension type may be compressed into ech_outer_extensions. Maximal
    /// compression (RFC 9849 sec. 5.1) is the ecosystem norm and the smaller, less
    /// distinguishable ClientHelloOuter: every extension is eligible except the three the
    /// inner and outer never share - server_name (real vs public_name), the
    /// encrypted_client_hello marker, and pre_shared_key (real binder vs GREASE). Byte
    /// identity is still verified per extension before one is actually compressed.
    /// </summary>
    class function IsCompressible(AExtType: UInt16): Boolean; static;

    /// <summary>
    /// Reconstructs the full ClientHelloInner extensions from the inner extensions
    /// AInner (one entry being ech_outer_extensions) and the ClientHelloOuter extensions
    /// AOuter. Walks AOuter with one never-rewinding cursor: each referenced type is
    /// found at or after the cursor, or the connection aborts with illegal_parameter
    /// (missing / out of order); a duplicate reference or a reference to
    /// encrypted_client_hello also aborts. If AInner has no ech_outer_extensions block
    /// it is returned unchanged.
    /// </summary>
    class function Reconstruct(const AOuter,
      AInner: TExtensionVector): TExtensionVector; static;
  end;

implementation

resourcestring
  SEchReferenced = 'ech_outer_extensions must not reference encrypted_client_hello ' +
    'or ech_outer_extensions itself';
  SMissingOrOutOfOrder =
    'a referenced outer extension is missing or out of order';
  SDuplicateReference = 'ech_outer_extensions references an extension twice';
  SDuplicateOuterExtensions = 'more than one ech_outer_extensions block';

{ TEchOuterExtensions }

class function TEchOuterExtensions.IsCompressible(AExtType: UInt16): Boolean;
begin
  // the three extensions the inner and outer never share are ineligible; everything else may compress
  case AExtType of
    TExtensionTypes.ServerName,
    TExtensionTypes.EncryptedClientHello,
    TExtensionTypes.PreSharedKey:
      Result := False;
  else
    Result := True;
  end;
end;

class function TEchOuterExtensions.CheckNoDuplicate(
  const ATypes: TArray<UInt16>): Boolean;
var
  LI, LJ: Int32;
begin
  for LI := 0 to System.High(ATypes) do
    for LJ := LI + 1 to System.High(ATypes) do
      if ATypes[LI] = ATypes[LJ] then
        Exit(False);
  Result := True;
end;

class function TEchOuterExtensions.Reconstruct(const AOuter,
  AInner: TExtensionVector): TExtensionVector;
var
  LResult: TExtensionVector;
  LRefTypes: TArray<UInt16>;
  LCursor, LI, LJ, LK, LFound: Int32;
  LType: UInt16;
  LSeenOuterExtensions: Boolean;
begin
  LResult := TExtensionVector.Empty;
  LCursor := 0;
  LSeenOuterExtensions := False;
  for LI := 0 to AInner.Count - 1 do
  begin
    if AInner.Entries[LI].ExtensionType <> TExtensionTypes.EchOuterExtensions then
    begin
      LResult.Append(AInner.Entries[LI]);
      Continue;
    end;

    // ech_outer_extensions is itself a ClientHelloInner extension, so it may appear at most once
    // (RFC 8446 4.2 forbids a repeated extension type)
    if LSeenOuterExtensions then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SDuplicateOuterExtensions);
    LSeenOuterExtensions := True;

    LRefTypes := TEchExtension.DecodeOuterExtensions(AInner.Entries[LI].Data);
    if not CheckNoDuplicate(LRefTypes) then
      raise EFatalAlertTlsLibException.CreateRes(
        TTlsAlertDescription.IllegalParameter, @SDuplicateReference);

    for LJ := 0 to System.High(LRefTypes) do
    begin
      LType := LRefTypes[LJ];
      // the reference list MUST NOT name encrypted_client_hello or ech_outer_extensions itself
      // (RFC 9849 sec. 5.1)
      if (LType = TExtensionTypes.EncryptedClientHello) or
        (LType = TExtensionTypes.EchOuterExtensions) then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SEchReferenced);
      // a single forward cursor: the match must be at or after it, never behind,
      // which is exactly "present, in the same relative order, referenced once"
      LFound := -1;
      for LK := LCursor to AOuter.Count - 1 do
        if AOuter.Entries[LK].ExtensionType = LType then
        begin
          LFound := LK;
          Break;
        end;
      if LFound < 0 then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SMissingOrOutOfOrder);
      LResult.Append(AOuter.Entries[LFound]);
      LCursor := LFound + 1;
    end;
  end;
  Result := LResult;
end;

end.
