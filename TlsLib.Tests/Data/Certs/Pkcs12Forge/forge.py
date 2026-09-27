#!/usr/bin/env python3
# Regenerates the PKCS#12 leaf-selection fixtures in ../../Data/Certs/Pkcs12.txt
# (nolink_cafirst_pfx, orphanlink_pfx, wronglink_pfx, nomatch_pfx).
#
# These stores are plaintext (no encryption, no MAC) with SafeBag orderings and localKeyId
# attributes that OpenSSL will not emit, so TlsLib's "pick the leaf by matching the private key"
# path can be exercised. They reuse chain_pfx's leaf + CA (extracted with OpenSSL), so ca_cert_der
# stays the trust anchor.
#
# Requires: OpenSSL on PATH and `pip install asn1crypto`. Run from anywhere:
#     python forge.py            # prints name=hex lines for Pkcs12.txt
# Then paste the output over the matching lines in Data/Certs/Pkcs12.txt.
import os
import subprocess
import tempfile
from asn1crypto import pkcs12, core, keys, x509

HERE = os.path.dirname(os.path.abspath(__file__))
PKCS12_TXT = os.path.join(HERE, '..', 'Pkcs12.txt')
PASSWORD = 'tlslib'
LOCAL_KEY_ID_OID = '1.2.840.113549.1.9.21'
KID_A = b'\xA1' * 20        # the leaf's id
KID_B = b'\xB2' * 20        # the CA's id
KID_ORPHAN = b'\xC3' * 20   # an id no certificate carries


def read_field(name):
    with open(PKCS12_TXT, 'r') as fh:
        for line in fh:
            if line.startswith(name + '='):
                return bytes.fromhex(line.split('=', 1)[1].strip())
    raise SystemExit('field not found in Pkcs12.txt: ' + name)


def openssl(args, stdin_bytes=None):
    return subprocess.run(['openssl'] + args, input=stdin_bytes,
                          check=True, stdout=subprocess.PIPE).stdout


def extract_pieces():
    # split chain_pfx into leaf cert, CA cert and the (PKCS#8) private key, all DER
    with tempfile.TemporaryDirectory() as d:
        pfx = os.path.join(d, 'chain.pfx')
        open(pfx, 'wb').write(read_field('chain_pfx'))
        leaf_pem = openssl(['pkcs12', '-in', pfx, '-passin', 'pass:' + PASSWORD,
                            '-nokeys', '-clcerts'])
        ca_pem = openssl(['pkcs12', '-in', pfx, '-passin', 'pass:' + PASSWORD,
                          '-nokeys', '-cacerts'])
        key_pem = openssl(['pkcs12', '-in', pfx, '-passin', 'pass:' + PASSWORD,
                           '-nocerts', '-nodes'])
        leaf = openssl(['x509', '-outform', 'DER'], leaf_pem)
        ca = openssl(['x509', '-outform', 'DER'], ca_pem)
        key = openssl(['pkcs8', '-topk8', '-nocrypt', '-outform', 'DER'], key_pem)
        return leaf, ca, key


def attrs(local_key_id):
    if local_key_id is None:
        return None
    return pkcs12.Attributes([
        pkcs12.Attribute({'type': LOCAL_KEY_ID_OID,
                          'values': [core.OctetString(local_key_id)]})
    ])


def cert_bag(cert_der, local_key_id):
    bag = pkcs12.SafeBag({'bag_id': 'cert_bag',
                          'bag_value': pkcs12.CertBag({'cert_id': 'x509',
                                                       'cert_value': x509.Certificate.load(cert_der)})})
    a = attrs(local_key_id)
    if a is not None:
        bag['bag_attributes'] = a
    return bag


def key_bag(key_der, local_key_id):
    bag = pkcs12.SafeBag({'bag_id': 'key_bag',
                          'bag_value': keys.PrivateKeyInfo.load(key_der)})
    a = attrs(local_key_id)
    if a is not None:
        bag['bag_attributes'] = a
    return bag


def pfx(bags):
    safe_contents = pkcs12.SafeContents(bags)
    inner = core.OctetString(safe_contents.dump())
    auth_safe = pkcs12.AuthenticatedSafe([
        pkcs12.ContentInfo({'content_type': 'data', 'content': inner})
    ])
    p = pkcs12.Pfx({'version': 3,
                    'auth_safe': pkcs12.ContentInfo({'content_type': 'data',
                                                     'content': core.OctetString(auth_safe.dump())})})
    return p.dump()


def main():
    leaf, ca, key = extract_pieces()
    vectors = {
        'nolink_cafirst_pfx': pfx([cert_bag(ca, None), cert_bag(leaf, None), key_bag(key, None)]),
        'orphanlink_pfx': pfx([key_bag(key, KID_ORPHAN), cert_bag(leaf, None), cert_bag(ca, None)]),
        'wronglink_pfx': pfx([key_bag(key, KID_A), cert_bag(leaf, KID_B), cert_bag(ca, KID_A)]),
        'nomatch_pfx': pfx([key_bag(key, KID_ORPHAN), cert_bag(ca, None)]),
    }
    for name, der in vectors.items():
        print('%s=%s' % (name, der.hex()))


if __name__ == '__main__':
    main()
