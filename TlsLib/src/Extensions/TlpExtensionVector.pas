{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpExtensionVector;

{$I ..\Include\TlsLib.inc}

interface

uses
  SysUtils,
  TlpTlsAlert,
  TlpTlsLibExceptions,
  TlpWireReader,
  TlpWireVectorMarker,
  TlpIWireWriter,
  TlpWireWriter;

type
  /// <summary>One extension: its 2-byte type and opaque extension_data.</summary>
  TExtensionEntry = record
    ExtensionType: UInt16;
    Data: TBytes;
    /// <summary>The absolute offset of Data in the buffer Parse/ParseFrom read, so a received
    /// message can be patched in place (the Encrypted Client Hello AAD zeroing and the
    /// HelloRetryRequest confirmation, RFC 9849 5.2 / 7.2.1) without re-encoding; -1 when the
    /// entry was constructed rather than parsed.</summary>
    DataOffset: Int32;
    class function Create(AType: UInt16; const AData: TBytes): TExtensionEntry; static;
  end;

  /// <summary>
  /// The extensions&lt;0..2^16-1&gt; vector of RFC 8446 4.2 as a value type: ordered entries,
  /// no repeated type (illegal_parameter), at most MaxEntries (decode_error), nothing after
  /// the vector (decode_error). Parse and Encode round-trip byte-exact with the wire framing.
  /// Copy-on-write: every mutator uniquifies the entry array first, so a copy never aliases its
  /// source. Never write an entry's Data in place - replace it wholesale.
  /// </summary>
  TExtensionVector = record
  public const
    // a hello never legitimately carries this many extensions; a larger block is abuse
    MaxEntries = Int32(64);
  strict private
  var
    FEntries: TArray<TExtensionEntry>;
    procedure MakeUnique;
    function GetCount: Int32;
    function GetEntry(AIndex: Int32): TExtensionEntry;
    class procedure AppendRaw(var AEntries: TArray<TExtensionEntry>;
      const AEntry: TExtensionEntry); static;
  public
    class function Empty: TExtensionVector; static;
    /// <summary>Parses a 2-byte-length-prefixed extensions field; nothing may follow it. An empty
    /// field is a decode_error (a present-but-empty vector is two zero bytes) - the omitted TLS 1.2
    /// hello field is the caller's concern, not this codec's.</summary>
    class function Parse(const AField: TBytes): TExtensionVector; static;
    /// <summary>Parses one 2-byte-length-prefixed vector from AReader, leaving the cursor after it
    /// (an EncodedClientHelloInner is followed by padding).</summary>
    class function ParseFrom(var AReader: TWireReader): TExtensionVector; static;
    /// <summary>The 2-byte-length-prefixed field, byte-identical to the hand-rolled framing.</summary>
    function Encode: TBytes;

    function Types: TArray<UInt16>;
    function IndexOf(AType: UInt16): Int32;
    function Contains(AType: UInt16): Boolean;
    function TryFind(AType: UInt16; out AEntry: TExtensionEntry): Boolean;
    /// <summary>Whether the last entry has AType (False on an empty vector).</summary>
    function IsLast(AType: UInt16): Boolean;

    procedure Append(const AEntry: TExtensionEntry);
    procedure InsertAt(AIndex: Int32; const AEntry: TExtensionEntry);
    /// <summary>Inserts before the first entry of AAnchorType, or appends when it is absent.</summary>
    procedure InsertBefore(AAnchorType: UInt16; const AEntry: TExtensionEntry);
    /// <summary>Replaces entry AIndex's data (its type is unchanged; DataOffset resets to -1).</summary>
    procedure SetData(AIndex: Int32; const AData: TBytes);
    /// <summary>Replaces ACount entries from AStart with one entry.</summary>
    procedure ReplaceRange(AStart, ACount: Int32; const AEntry: TExtensionEntry);
    procedure Delete(AIndex: Int32);

    property Count: Int32 read GetCount;
    property Entries[AIndex: Int32]: TExtensionEntry read GetEntry;
  end;

implementation

resourcestring
  SDuplicateExtension = 'a duplicate extension type appears in the block';
  STooManyExtensions = 'the extension block carries too many extensions';

{ TExtensionEntry }

class function TExtensionEntry.Create(AType: UInt16;
  const AData: TBytes): TExtensionEntry;
begin
  Result.ExtensionType := AType;
  Result.Data := AData;
  Result.DataOffset := -1;
end;

{ TExtensionVector }

class function TExtensionVector.Empty: TExtensionVector;
begin
  Result.FEntries := nil;
end;

class procedure TExtensionVector.AppendRaw(var AEntries: TArray<TExtensionEntry>;
  const AEntry: TExtensionEntry);
begin
  if System.Length(AEntries) >= MaxEntries then
    raise EDecodeErrorTlsLibException.CreateRes(@STooManyExtensions);
  System.SetLength(AEntries, System.Length(AEntries) + 1);
  AEntries[System.High(AEntries)] := AEntry;
end;

procedure TExtensionVector.MakeUnique;
begin
  // a copy shares the entry array until the first write; uniquify so a mutation never
  // reaches through an assignment to another vector's entries
  FEntries := System.Copy(FEntries);
end;

class function TExtensionVector.Parse(const AField: TBytes): TExtensionVector;
var
  LReader: TWireReader;
begin
  LReader := TWireReader.Create(AField);
  Result := ParseFrom(LReader);
  LReader.ExpectEnd; // nothing may follow the extensions vector
end;

class function TExtensionVector.ParseFrom(
  var AReader: TWireReader): TExtensionVector;
var
  LEntries, LData: TWireReader;
  LEntry: TExtensionEntry;
  LI: Int32;
begin
  Result.FEntries := nil;
  LEntries := AReader.OpenVector(2);
  while not LEntries.EndReached do
  begin
    LEntry.ExtensionType := LEntries.ReadUInt16;
    LData := LEntries.OpenVector(2);
    // duplicate check first, so a repeated type - even an unoffered/bogus one - is the
    // duplicate it is (illegal_parameter) rather than any later semantic verdict
    for LI := 0 to System.High(Result.FEntries) do
      if Result.FEntries[LI].ExtensionType = LEntry.ExtensionType then
        raise EFatalAlertTlsLibException.CreateRes(
          TTlsAlertDescription.IllegalParameter, @SDuplicateExtension);
    // OpenVector leaves the sub-reader at the data start; Position is absolute in AReader's buffer
    LEntry.DataOffset := LData.Position;
    LEntry.Data := LData.ReadBytes(LData.Remaining);
    AppendRaw(Result.FEntries, LEntry);
  end;
end;

function TExtensionVector.Encode: TBytes;
var
  LWriter: IWireWriter;
  LOuter, LInner: TWireVectorMarker;
  LI: Int32;
begin
  LWriter := TWireWriter.Create;
  LOuter := LWriter.OpenVector(2);
  for LI := 0 to System.High(FEntries) do
  begin
    LWriter.WriteUInt16(FEntries[LI].ExtensionType);
    LInner := LWriter.OpenVector(2);
    LWriter.WriteBytes(FEntries[LI].Data);
    LWriter.CloseVector(LInner);
  end;
  LWriter.CloseVector(LOuter);
  Result := LWriter.ToBytes;
end;

function TExtensionVector.GetCount: Int32;
begin
  Result := System.Length(FEntries);
end;

function TExtensionVector.GetEntry(AIndex: Int32): TExtensionEntry;
begin
  Result := FEntries[AIndex];
end;

function TExtensionVector.Types: TArray<UInt16>;
var
  LI: Int32;
begin
  System.SetLength(Result, System.Length(FEntries));
  for LI := 0 to System.High(FEntries) do
    Result[LI] := FEntries[LI].ExtensionType;
end;

function TExtensionVector.IndexOf(AType: UInt16): Int32;
var
  LI: Int32;
begin
  for LI := 0 to System.High(FEntries) do
    if FEntries[LI].ExtensionType = AType then
      Exit(LI);
  Result := -1;
end;

function TExtensionVector.Contains(AType: UInt16): Boolean;
begin
  Result := IndexOf(AType) >= 0;
end;

function TExtensionVector.TryFind(AType: UInt16;
  out AEntry: TExtensionEntry): Boolean;
var
  LIndex: Int32;
begin
  LIndex := IndexOf(AType);
  Result := LIndex >= 0;
  if Result then
    AEntry := FEntries[LIndex]
  else
    AEntry := Default(TExtensionEntry);
end;

function TExtensionVector.IsLast(AType: UInt16): Boolean;
begin
  Result := (System.Length(FEntries) > 0) and
    (FEntries[System.High(FEntries)].ExtensionType = AType);
end;

procedure TExtensionVector.Append(const AEntry: TExtensionEntry);
begin
  MakeUnique;
  AppendRaw(FEntries, AEntry);
end;

procedure TExtensionVector.InsertAt(AIndex: Int32; const AEntry: TExtensionEntry);
var
  LI: Int32;
begin
  if System.Length(FEntries) >= MaxEntries then
    raise EDecodeErrorTlsLibException.CreateRes(@STooManyExtensions);
  MakeUnique;
  System.SetLength(FEntries, System.Length(FEntries) + 1);
  for LI := System.High(FEntries) downto AIndex + 1 do
    FEntries[LI] := FEntries[LI - 1];
  FEntries[AIndex] := AEntry;
end;

procedure TExtensionVector.InsertBefore(AAnchorType: UInt16;
  const AEntry: TExtensionEntry);
var
  LIndex: Int32;
begin
  LIndex := IndexOf(AAnchorType);
  if LIndex < 0 then
    Append(AEntry)
  else
    InsertAt(LIndex, AEntry);
end;

procedure TExtensionVector.SetData(AIndex: Int32; const AData: TBytes);
begin
  MakeUnique;
  FEntries[AIndex].Data := AData;
  FEntries[AIndex].DataOffset := -1;
end;

procedure TExtensionVector.ReplaceRange(AStart, ACount: Int32;
  const AEntry: TExtensionEntry);
var
  LI, LShift: Int32;
begin
  MakeUnique;
  FEntries[AStart] := AEntry;
  LShift := ACount - 1;
  if LShift > 0 then
  begin
    for LI := AStart + 1 to System.High(FEntries) - LShift do
      FEntries[LI] := FEntries[LI + LShift];
    System.SetLength(FEntries, System.Length(FEntries) - LShift);
  end;
end;

procedure TExtensionVector.Delete(AIndex: Int32);
var
  LI: Int32;
begin
  MakeUnique;
  for LI := AIndex to System.High(FEntries) - 1 do
    FEntries[LI] := FEntries[LI + 1];
  System.SetLength(FEntries, System.Length(FEntries) - 1);
end;

end.
