library jwt.jwt.test;

import 'package:dart_jwt/src/jwa.dart';
import 'package:dart_jwt/src/jwt.dart';
import 'package:dart_jwt/src/validation_constraint.dart';
import 'package:test/test.dart';

void main() {
  final String sharedSecret = '3ab90b11-d7bd-4097-958f-01b7ac4e985f';
  final String issuer = 'jira:ae390d29-31b2-4c12-a719-9df64e3e92b7';
  final List<String> audience = ['foobar'];
  final String subject = 'admin';
  final DateTime expiry =
      DateTime.parse('2014-03-07 15:26:07.000+11:00').toUtc();
  final DateTime issuedAt =
      DateTime.parse('2014-03-07 15:23:07.000+11:00').toUtc();
  final JwaSignatureContext signatureContext =
      new JwaSymmetricKeySignatureContext(sharedSecret);
  final claimSetValidationContext = new JwtClaimSetValidationContext(
      expiryTolerance: const Duration(days: 365 * 1000));
  final JwtValidationContext validationContext =
      new JwtValidationContext(signatureContext, claimSetValidationContext);
  final String jwtStr = r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
      'eyJleHAiOjEzOTQxNjYzNjcsInN1YiI6ImFkbWluIiwiaXNzIjoiamlyYTphZTM5MGQyOS0'
      'zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJxc2giOiJlYjRlYzVmMDk4MGQwMWRhMz'
      'A2ZGI4OWZhNTdkZDE2MzU3NDY2NzQzNmRkNzIwZDVkOWM1Mjc5YzViNDVmN2E4IiwiaWF0I'
      'joxMzk0MTY2MTg3fQ.bR8Z0MIguOg6xgHiav0quun8kTqXzNUKMKym-PFjZvc';

  group('[decode]', () {
    JsonWebToken jwt() => new JsonWebToken.decode(jwtStr);
    OpenIdJwtClaimSet claimSet() => jwt().claimSet;

    group('[claimset]', () {
      test('issuer parses', () {
        expect(claimSet().issuer, equals(issuer));
      });
      test('subject parses', () {
        expect(claimSet().subject, equals(subject));
      });
      test('expiry parses', () {
        expect(claimSet().expiry.toUtc(), equals(expiry));
      });
      test('issuedAt parses', () {
        expect(claimSet().issuedAt.toUtc(), equals(issuedAt));
      });
    });
    group('[signature]', () {
      test('validates successfully with correct shared secret', () {
        Set<ConstraintViolation> violations = jwt().validate(validationContext);
        expect(violations, isEmpty);
      });
    });
  });

  group('[encode]', () {
    final claimSet = new OpenIdJwtClaimSet.build(
        issuer: issuer,
        subject: subject,
        audience: audience,
        expiry: expiry,
        issuedAt: issuedAt);

    JsonWebToken jwt() => new JsonWebToken.jws(claimSet, signatureContext);
    String encode() => jwt().encode();
    JsonWebToken parseEncoded() =>
        new JsonWebToken.decode(encode(), validationContext: validationContext);
    OpenIdJwtClaimSet roundtripClaimSet() => parseEncoded().claimSet;

    group('[roundtrip]', () {
      test('issuer matches', () {
        expect(roundtripClaimSet().issuer, equals(issuer));
      });
      test('audience matches', () {
        expect(roundtripClaimSet().audience, equals(audience));
      });
      test('subject matches', () {
        expect(roundtripClaimSet().subject, equals(subject));
      });
      test('expiry matches', () {
        expect(roundtripClaimSet().expiry.toUtc(), equals(expiry));
      });
      test('issuedAt matches', () {
        expect(roundtripClaimSet().issuedAt.toUtc(), equals(issuedAt));
      });
    });
  });

  group('[validation]', () {
    OpenIdJwtClaimSet claimSet(
            int secondsBeforeNow) =>
        new OpenIdJwtClaimSet.build(
            issuer: issuer,
            subject: subject,
            expiry: new DateTime.now().subtract(
                new Duration(milliseconds: secondsBeforeNow * 1000 - 1)),
            issuedAt: issuedAt);

    Set<ConstraintViolation> violations(int secondsBeforeNow) =>
        claimSet(secondsBeforeNow)
            .validate(const JwtClaimSetValidationContext());

    group('[expiry]', () {
      test('fails validation if more than tolerance past expiry', () {
        expect(violations(31), isNot(isEmpty));
      });

      test('passes validation if no more than tolerance past expiry', () {
        expect(violations(30), isEmpty);
      });
    });
  });

  group('[map claim set]', () {
    group('[encode]', () {
      final claimSet = new MapJwtClaimSet.fromJson({'iss': issuer});

      JsonWebToken jwt() => new JsonWebToken.jws(claimSet, signatureContext);
      String encode() => jwt().encode();
      JsonWebToken parseEncoded() => new JsonWebToken.decode(encode(),
          validationContext: validationContext,
          claimSetParser: mapClaimSetParser);
      MapJwtClaimSet roundtripClaimSet() => parseEncoded().claimSet;

      group('[roundtrip]', () {
        test('issuer matches', () {
          expect(roundtripClaimSet().json['iss'], equals(issuer));
        });
      });
    });
  });
}
