library jwt.jwa.test;

import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import "package:pointycastle/asymmetric/api.dart";
import 'package:dart_jwt/src/jwa.dart';
import 'package:dart_jwt/src/jws.dart';
import 'package:dart_jwt/src/util.dart';
import 'package:test/test.dart';

void main() {
  group('[HS256]', () {
    String sign(String signingInput, String sharedSecret) {
      final jwsSignature = new JwsSignature.create(
          signingInput,
          JsonWebAlgorithm.HS256,
          new JwaSymmetricKeySignatureContext(sharedSecret));
      return jwsSignature.encode();
    }

    // TODO: very adhoc - just two examples
    test('case 1', () {
      expect(
          sign(
              'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
              'eyJpYXQiOjEzOTU3MjUxMzYsImV4cCI6MTM5NTcyNTMxNiwiaXNzIjoiZm9v'
              'LWJhci1hZGRvbiIsInFzaCI6IjEzODU2Zjk3ZWU3ZTE2ZjE1YmFmY2QxYjZh'
              'MzE3MDQ4NWE2Mjk2NGIzYWU5MTU0ZTMyZWUyNjdhNjA4OTM0M2MifQ',
              '5b51a6d1-0628-4ade-b9d7-83290e7e433a'),
          equals('s4WJ6h4glblp-GiVVAOuGxQRQ0Sb3wpnRvKXbmZXgT8'));
    });
    test('case 2', () {
      expect(
          sign(
              'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
              'eyJpYXQiOjEzOTU3Mjg5MzcsImV4cCI6MTM5NTcyOTExNywiaXNzIjoiZm9v'
              'LWJhci1hZGRvbiIsInFzaCI6IjEzODU2Zjk3ZWU3ZTE2ZjE1YmFmY2QxYjZh'
              'MzE3MDQ4NWE2Mjk2NGIzYWU5MTU0ZTMyZWUyNjdhNjA4OTM0M2MifQ',
              'bd630768-3f4c-49c7-a414-4f44b4ec021b'),
          equals('NDrBMAzry_r-VRFM2r0hVaKAQdFtlTht_Qs4Mn5l0MI'));
    });
    test('case 3 bitbucket', () {
      expect(
          sign(
              'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.'
              'eyJpc3MiOiAiY29ubmVjdGlvbjoxNjYiLCAiaWF0IjogMTQxMDkwNTA0Miwg'
              'InFzaCI6ICI4Y2VmMTcyNDM5ZWM2Y2ZhNGZlOGM1OGZiZTZkNDU0ODgzOGRh'
              'YjkwODFjYWM0YzhhNmIzZTNkNjUzNDlmMzg3IiwgImF1ZCI6ICJjb25uZWN0'
              'aW9uOjE2NiIsICJleHAiOiAxNDE0NTA1MDQyfQ',
              '3dab1f24-72c6-4d74-ab19-1f254313a19b'),
          equals('YFYWzvqUBugYopOdefxqKpdw_zws55A8HFINovpNA14'));
    });
  });

  RSAPublicKey _pkcs1PublicKey(String keyString) {
    var key_bytes = _toBytes(keyString);
    var p = new ASN1Parser(key_bytes);
    ASN1Sequence seq = p.nextObject();
    var modulus = (seq.elements[0] as ASN1Integer).valueAsBigInteger;
    var publicExponent =
        (seq.elements[1] as ASN1Integer).valueAsBigInteger;
    RSAPublicKey key = new RSAPublicKey(modulus, publicExponent);
    return key;
  }

  RSAPrivateKey _pkcs1PrivateKey(String keyString) {
    var key_bytes = _toBytes(keyString);
    var p = new ASN1Parser(key_bytes);
    ASN1Sequence seq = p.nextObject();
    var modulus = (seq.elements[1] as ASN1Integer).valueAsBigInteger;
    var privateExponent = (seq.elements[3] as ASN1Integer).valueAsBigInteger;
    var prime1 = (seq.elements[4] as ASN1Integer).valueAsBigInteger;
    var prime2 = (seq.elements[5] as ASN1Integer).valueAsBigInteger;
    RSAPrivateKey key =
        new RSAPrivateKey(modulus, privateExponent, prime1, prime2);
    return key;
  }

  RSAPrivateKey _pkcs8PrivateKey(String keyString) {
    var key_bytes = _toBytes(keyString);
    var p = new ASN1Parser(key_bytes);
    ASN1Sequence seq = p.nextObject();
    ASN1OctetString os = seq.elements[2];
    ASN1Parser p2 = new ASN1Parser(os.valueBytes());
    seq = p2.nextObject();
    var modulus = (seq.elements[1] as ASN1Integer).valueAsBigInteger;
    var privateExponent = (seq.elements[3] as ASN1Integer).valueAsBigInteger;
    var prime1 = (seq.elements[4] as ASN1Integer).valueAsBigInteger;
    var prime2 = (seq.elements[5] as ASN1Integer).valueAsBigInteger;
    RSAPrivateKey key =
        new RSAPrivateKey(modulus, privateExponent, prime1, prime2);
    return key;
  }

  // Generate pub/private RSA key:
  // openssl req -x509 -days 365 -newkey rsa:2048 -sha1 -nodes  \
  // -subj '/C=DK/L=Copenhagen/CN=www.example.com' \
  // -keyout testkey.pem -out testcert.pem
  group('[RS256]', () {
    var rsaPrivateKeyPkcs8Pem = '''
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDN/NANYyAzimKV
TXZpttmnpJORcK1iQZOkHmyFO/bbM5tR4Z5b1Mu5kMJq+Nf0SmgRsrEGxF8uL3Sy
sZjbMa2DtS9lEdB8rSJvzjlI552CGpwmqtSNOe4e56vMHYB45OYH+EZEUb4oRyLq
+ZSUURL/du1HXVEzrx8dedCLsMtGKLiQcpolVRzydJJLJIIbg8fzin6X5KIgM06L
M3NpB3MaKFc1ouzgNWlJ3BbwLOBKIlyKhQPXpw5cUPcIJ+VGGA/JbcrCMFnAqVaR
IYwKbcFP983hsDLbQJKfZogsXhdi8W+7LnHtBD80kusZbgwC52mP1VQmoDT+zcWF
UAp9ZLCPAgMBAAECggEAAweo98lxe9CZSqDtEPkDkpe1I/qIUl2skklwRzVumCLW
Mgojji4/IOekNHaclpdRmJEMUZEp5UAFc2txWCgO6VUM8WulqW/Shdp+tTfS9Ur2
6QqyPbGQcxvtRv9YGG8lgxB/2BlrtqP1O4eYS+Y1ZVSWgOo6e4wj5QcZrjRXiRyh
c48XPRsA/RUfMgOmVYUsEFeBgvXLIT1PqSG2eqC40E8CDChwRdWNy5b5zgvHWN7r
+2O+iu7dumJkxiGXcSWOvdHlPqP51p2dn4pf1k6hVJS+sIazYm8U/mJ6AmhXC1dh
8xF/1JUfLbJZhUXvME85Y5SZXlGxYoraOwx6ZHqs4QKBgQD4cfCvTAc3yWszYGo+
zavOWK23WwKR/mQstK1NCjTPDhHlFU0JYyT4KCNiElVIqJ4kpttk9JxqUBrrH9Eo
TFVDmnrFZC6tqpZdgF+A+oJxMc/SVfh85KPN3IWb+2WtzHy8tTQW1Rb3TD7HuKo5
VkO/DTX1L//+yKGkMV98KR+dbQKBgQDUQFrvC7JAfXSVUhJWHRyZmeoYYB8eMrAW
kR0XaJhdqmisxWKFaGWFArY2MEbB8rTa3EyxS9RKfMa8GaLNPoqHTZXKzTe4JRco
jypO3VayDavk5rN8TQ+kgSkM4s2JiiBwg3f+ICwEPObvbagU/+pimGbR+P/kW0mq
6g76bGr0awKBgQDexOvXgwiF0Sk6bB1YKvr+jy1U11o6piwUmf06swgfELKjArKM
1EV17ier7FxkRi1nF+ZpY5xNB37bjS/yPl/FumKTU/0241rohA8ei4EjFlMOet/Q
vQLTuARllMnbSRwf6SrHvlJVdBxm4QJhXyRnzuSu8VdNkYC+xTalEgqzEQKBgQCW
hCi4OlgnCZCCT5g3Px/IAXET5h5LIPDkn/W8Yu0iBzWBx9wM9TKA96JVnTigU0hT
qEQuurKKPCAGxjtAR2ifeLKQBaXMzWi114jOMoJHdBCBG+UOcet04i9FNxVAwxYs
E98k9JWiT7oI8n9unOkPEDpiDq0QuHfuX1tN1VKnjwKBgDNSEXqmRHew/C0GSaf5
fQL612f4I8zU9BCZeXASHgCjYkIo9+d1Amz0HFbYYuwACK5l9GxEO7TsBv8S3CcM
HZf48zF7B158wdSXno1Rd1vIZoHkDZYlWxjBAk60LZLzggiYnpNpL/JJh+SI/CYz
K+g1U8zsBcMm15Hf+bJnIr+A
''';

    RSAPrivateKey rsaPrivateKey() => _pkcs8PrivateKey(rsaPrivateKeyPkcs8Pem);

    String sign(String signingInput, RSAPrivateKey rsaPrivateKey) {
      final jwsSignature = new JwsSignature.create(
          signingInput,
          JsonWebAlgorithm.RS256,
          new JwaRsaSignatureContext.withKeys(rsaPrivateKey: rsaPrivateKey));
      return jwsSignature.encode();
    }

    test('simple', () {
      expect(
          sign(
              'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.'
              'eyJpYXQiOjEzOTQxNjYxODcsImV4cCI6MTM5NDE2NjM2NywiaXNzIjoiamly'
              'YTphZTM5MGQyOS0zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJzdWIi'
              'OiJhZG1pbiIsImF1ZCI6ImZvb2JhciJ9',
              rsaPrivateKey()),
          equals(
              'YUU-mhNuoVHti6ZPA5WcNVxBk_Y5m2grTSW1Biea0p9IcWao7QplG4ZMcnNCRW_2uYgENakUVvKFF7dSR0srt435OCznJCHgefsAAtSwKgrTZetThBsrc9NBxys-C0bp-u6UpUgbNUnZa-JH7_VElkdTsnqgvtCGo3xGtTeuSoPKQMu7aE7eMS2qof4QX-H0Ym1zrC4rWKf9sO4gdOyh9CmoWYHwkPrlc3IMwsm-1yxOUcNZvPRy63-hq7bsKZKc_MvGjjk7zpBO8K6PRWLiHmi7hilQKMw8iGskAtj7OWp_YidvBbem5TfM8BQxncGbtXySn6ygdP6M9DuJgxWA8w'));
    });
  });

  group('[Assymetric RS256]', () {
    // This is the public key that corresponds to the private key
    var rsaPublicKeyPkcs1Pem = '''
MIIBCgKCAQEAqiwZWsX8I+5EQlnOJVOBvsxiDd33+9OYJUM7WMn3Vvibg8M2qgWtIZUBNy8LB3G
VFWWcoLNf1Pjs0yA5yZUuuOp5f3v1PvI4V1fkosyJZd+Iqe966W5P+uzHTLtOFQmNpjTcHKKYHw
tD8KZPy17oETJ92OlaxJdXZVNCo6rFL3znrdJJvl4fvYnW93CdQiR90cDjn/B+gRZbGreSnr0zq
5+bOtX3VOVnOJs672v5Y5XlZUjbAE93kZS8qwt578ay+ABhPUgkk/lHPMWnkKEmtxiAbKY4Ro+R
Gkk5i+QHO1gw8gYbi1lGr9OWjfxEl33Z7eXZBwa6E73NT2inGK1v0wIDAQAB
''';

    // This is the private key that corresponds to the public key
    var rsaPrivateKeyPkcs1Pem = '''
MIIEowIBAAKCAQEAqiwZWsX8I+5EQlnOJVOBvsxiDd33+9OYJUM7WMn3Vvibg8M2
qgWtIZUBNy8LB3GVFWWcoLNf1Pjs0yA5yZUuuOp5f3v1PvI4V1fkosyJZd+Iqe96
6W5P+uzHTLtOFQmNpjTcHKKYHwtD8KZPy17oETJ92OlaxJdXZVNCo6rFL3znrdJJ
vl4fvYnW93CdQiR90cDjn/B+gRZbGreSnr0zq5+bOtX3VOVnOJs672v5Y5XlZUjb
AE93kZS8qwt578ay+ABhPUgkk/lHPMWnkKEmtxiAbKY4Ro+RGkk5i+QHO1gw8gYb
i1lGr9OWjfxEl33Z7eXZBwa6E73NT2inGK1v0wIDAQABAoIBACj3Xs80dGOt+27B
sdfYh5aIG17dPdK4+JqX2dShIlMknEOXHjTGEwzPkzBWud/73vj8sj0ZkYtytYiJ
7H9z04Ceqcsf60VRCHE2bosmlDkbHApU5ZEGhmiQ0dXODZkQ6LHHbenS1q46hwuK
7hC2c0WYkyVB4CENkfOJnLRL6xZoJdiLDk0DZJby8bmYGP8iyRb3Xg7y6mN/j4e5
fysISuc3tXjrOSI1mozUCOudM4RRZwWeQ6/Zf66rnmq4MxhsaANurSlUVVL+oHYq
hRBdBgqhIpJsfmeq7Hdp919RVjgaJKRLOsg72/Ow6JA478S+rJQhxugqli8+9xNG
ZkxTK8kCgYEA0/SOomzfExTEzmDU8Dpm816cZkCGy9dn4SZQA3W8Z7WdXcll2c0K
5W9raccVoDegwV/1Z2i+kqBBdWuq3xs1clljbnjV7XTeggxwQG2IJsVR1Cx9f75B
+ceBI04bf9W6OesHJzE39Kww01Jb5o4viZztf7COIg1JpGEyfJJdiX0CgYEAzYjM
YK9N/O45o9TWmYXJ5sfV7Bxuhx8P9m/mvdWPjjIqVwFebZE4ZTiJkWT9GjSwRXqS
ToNxSxmLiHBSWFNRZTp4ZbrEcFiHm57qRireWhYagpbKF7qIr0Bfxb0hgSBj8cNR
l9KyP9T85Q/0KMmL0mNlskY0V0kbvQXQHEx9n48CgYB7PWV598e1NoxAW3k0vSCD
PW2+3qICABt8hGRdvqVvv9/iWmoIO/qr8R8JgCKI6A9moL72A6dbZibpeVL/Krjm
5ia0YzowOZXvFABo1ccmk/DCZ6QJFL0T2PazaoT+zWzcpFWiajHY6A3zsZ2R7vah
E0fcyPG7xvIczA8o84nDmQKBgQDLchiTr5LrxUcK0zfk2RiENtSalX4Wg/nB/vwQ
dl9V6nQckT9OB0wibXdGkwcxtGuzKmO+Eb/IDa4fTMdFpJtSLzFTyS5+4jLBKOlO
sUpNM8nj76x1FnALwRXL3q1WaqBjg+m09Zr5MjNt7X/KC846X6cfcvyGVdh+H03j
ZReIIwKBgBvYljGfJ3y4YmE+F0z0OF1Es/sk1r500zUQcLpAPiqeeXMPFc2Pn3PZ
z/A2yTklgZ7fHFswlMD0mj/SYDpjN8Coxk4I2erBWD9ylodUNWDj5zCd8oobakjs
blFWEc1PbdLx5V/thEG7GXpkNR+W4RyXcwUOtzO05Xg9d1WncMzN
''';

    var signingInput = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.'
        'eyJpYXQiOjEzOTQxNjYxODcsImV4cCI6MTM5NDE2NjM2NywiaXNzIjoiamly'
        'YTphZTM5MGQyOS0zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJzdWIi'
        'OiJhZG1pbiIsImF1ZCI6ImZvb2JhciJ9';

    RSAPrivateKey rsaPrivateKey() => _pkcs1PrivateKey(rsaPrivateKeyPkcs1Pem);
    RSAPublicKey rsaPublicKey() => _pkcs1PublicKey(rsaPublicKeyPkcs1Pem);

    test('sign', () {
      final jwsSignature = new JwsSignature.create(
          signingInput,
          JsonWebAlgorithm.RS256,
          new JwaRsaSignatureContext.withKeys(rsaPrivateKey: rsaPrivateKey()));
      var signature = jwsSignature.encode();
      expect(
          signature,
          equals('WqJ6jfYd2Pnp9vxn8CcVsbxwB1oAkIdH_QR9l1mF4-N__0JAhwNdcE'
              'HF5DSxXEbfQuYJ8ybdFQoGPJ5aBmmnCfuY_mbCqWmnkNJTof3vAshfbemPhv7RBgMIBKPjcz3ZXEL6R'
              'JW34eeKkgT-Mcc5QmftQVBJuECr1F6Y82emIeB5dlFaKmR0hT0qu7DmlsAERNIPuKbqa-_vf8O_QIzB'
              '5XHXw37fMpRzA_lIVQz2cL_ETpfFINcU0PriSxN2w-rsew2YfaB328QacfXSDC4grOEcmg6dLxuHXXx'
              'QyKs8P07iNXE9VoGJrTzVBBhOZP7a1znBjgzxs0TdzztbjC-H4Q'));
    });

    test('validate', () {
      Uint8List signatureBytes = new Uint8List.fromList([
        0x5a,
        0xa2,
        0x7a,
        0x8d,
        0xf6,
        0x1d,
        0xd8,
        0xf9,
        0xe9,
        0xf6,
        0xfc,
        0x67,
        0xf0,
        0x27,
        0x15,
        0xb1,
        0xbc,
        0x70,
        0x07,
        0x5a,
        0x00,
        0x90,
        0x87,
        0x47,
        0xfd,
        0x04,
        0x7d,
        0x97,
        0x59,
        0x85,
        0xe3,
        0xe3,
        0x7f,
        0xff,
        0x42,
        0x40,
        0x87,
        0x03,
        0x5d,
        0x70,
        0x41,
        0xc5,
        0xe4,
        0x34,
        0xb1,
        0x5c,
        0x46,
        0xdf,
        0x42,
        0xe6,
        0x09,
        0xf3,
        0x26,
        0xdd,
        0x15,
        0x0a,
        0x06,
        0x3c,
        0x9e,
        0x5a,
        0x06,
        0x69,
        0xa7,
        0x09,
        0xfb,
        0x98,
        0xfe,
        0x66,
        0xc2,
        0xa9,
        0x69,
        0xa7,
        0x90,
        0xd2,
        0x53,
        0xa1,
        0xfd,
        0xef,
        0x02,
        0xc8,
        0x5f,
        0x6d,
        0xe9,
        0x8f,
        0x86,
        0xfe,
        0xd1,
        0x06,
        0x03,
        0x08,
        0x04,
        0xa3,
        0xe3,
        0x73,
        0x3d,
        0xd9,
        0x5c,
        0x42,
        0xfa,
        0x44,
        0x95,
        0xb7,
        0xe1,
        0xe7,
        0x8a,
        0x92,
        0x04,
        0xfe,
        0x31,
        0xc7,
        0x39,
        0x42,
        0x67,
        0xed,
        0x41,
        0x50,
        0x49,
        0xb8,
        0x40,
        0xab,
        0xd4,
        0x5e,
        0x98,
        0xf3,
        0x67,
        0xa6,
        0x21,
        0xe0,
        0x79,
        0x76,
        0x51,
        0x5a,
        0x2a,
        0x64,
        0x74,
        0x85,
        0x3d,
        0x2a,
        0xbb,
        0xb0,
        0xe6,
        0x96,
        0xc0,
        0x04,
        0x44,
        0xd2,
        0x0f,
        0xb8,
        0xa6,
        0xea,
        0x6b,
        0xef,
        0xef,
        0x7f,
        0xc3,
        0xbf,
        0x40,
        0x8c,
        0xc1,
        0xe5,
        0x71,
        0xd7,
        0xc3,
        0x7e,
        0xdf,
        0x32,
        0x94,
        0x73,
        0x03,
        0xf9,
        0x48,
        0x55,
        0x0c,
        0xf6,
        0x70,
        0xbf,
        0xc4,
        0x4e,
        0x97,
        0xc5,
        0x20,
        0xd7,
        0x14,
        0xd0,
        0xfa,
        0xe2,
        0x4b,
        0x13,
        0x76,
        0xc3,
        0xea,
        0xec,
        0x7b,
        0x0d,
        0x98,
        0x7d,
        0xa0,
        0x77,
        0xdb,
        0xc4,
        0x1a,
        0x71,
        0xf5,
        0xd2,
        0x0c,
        0x2e,
        0x20,
        0xac,
        0xe1,
        0x1c,
        0x9a,
        0x0e,
        0x9d,
        0x2f,
        0x1b,
        0x87,
        0x5d,
        0x7c,
        0x50,
        0xc8,
        0xab,
        0x3c,
        0x3f,
        0x4e,
        0xe2,
        0x35,
        0x71,
        0x3d,
        0x56,
        0x81,
        0x89,
        0xad,
        0x3c,
        0xd5,
        0x04,
        0x18,
        0x4e,
        0x64,
        0xfe,
        0xda,
        0xd7,
        0x39,
        0xc1,
        0x8e,
        0x0c,
        0xf1,
        0xb3,
        0x44,
        0xdd,
        0xcf,
        0x3b,
        0x5b,
        0x8c,
        0x2f,
        0x87,
        0xe1,
      ]);
      final jwsSignature = new JwsSignature(signatureBytes);
      var violations = jwsSignature.validate(
          signingInput,
          JsonWebAlgorithm.RS256,
          new JwaRsaSignatureContext.withKeys(rsaPublicKey: rsaPublicKey()));
      expect(violations.length, equals(0));
    });
  });
}

Uint8List _toBytes(String keyString) =>
    new Uint8List.fromList(base64ToBytes(keyString.replaceAll('\n', '')));
