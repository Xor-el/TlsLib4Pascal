{ *********************************************************************************** }
{ *                                 TlsLib Library                                  * }
{ *                          Author - Ugochukwu Mmaduekwe                           * }
{ *                  Github Repository <https://github.com/Xor-el>                  * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TlpITlsConfigMemo;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  TlpITlsConfig;

type
  /// <summary>A bounded, thread-safe memo of frozen server configs keyed by signature.</summary>
  ITlsServerConfigMemo = interface(IInterface)
    ['{4B1F7C2A-8E63-4D19-9A5C-2F7E1B8D3A46}']
    /// <summary>Returns a previously stored config for this signature, if any.</summary>
    function TryGet(const ASignature: string; out AConfig: ITlsServerConfig): Boolean;
    /// <summary>Stores ABuilt under ASignature and returns it - unless another thread stored one
    /// for the same signature first, in which case that canonical config is returned and ABuilt is
    /// dropped, so every connection binds to a single config identity.</summary>
    function StoreOrAdopt(const ASignature: string;
      const ABuilt: ITlsServerConfig): ITlsServerConfig;
    /// <summary>Forgets every memoised config (e.g. after an in-place certificate rotation that a
    /// same-size, same-second stat would miss).</summary>
    procedure Clear;
  end;

  /// <summary>The client-side counterpart of ITlsServerConfigMemo.</summary>
  ITlsClientConfigMemo = interface(IInterface)
    ['{9D2A6E51-3C74-4F82-B1E6-7A0C4F9B2D18}']
    function TryGet(const ASignature: string; out AConfig: ITlsClientConfig): Boolean;
    function StoreOrAdopt(const ASignature: string;
      const ABuilt: ITlsClientConfig): ITlsClientConfig;
    procedure Clear;
  end;

implementation

end.
