// Test demonstrating an extension of JwtInJws.

import 'package:dart_jwt/dart_jwt.dart';
import 'package:test/test.dart';

DateTime testTime;

/// Custom JWT claim set representing claims in an AAF Rapid Connect token.
///
/// https://rapid.aaf.edu.au/developers (version 1.4.2)

class RapidAafClaimSet extends JwtClaimSet {
  static const String _attrId = "https://aaf.edu.au/attributes";

  final String subject;
  final String issuer;
  final String audience;
  final DateTime issuedAt;
  final DateTime notBefore;
  final DateTime expiry;
  final String type;
  final String jti;
  final String cn;
  final String displayName;
  final String mail;
  final String eduPersonScopedAffiliation;
  final String givenName;
  final String surname;
  final String eduPersonPrincipalName;
  final String auEduPersonSharedToken;
  final String eduPersonTargetdId;

  RapidAafClaimSet.fromJson(Map json)
      : subject = json["sub"],
        issuer = json["iss"],
        audience = json["aud"],
        issuedAt = new DateTime.fromMillisecondsSinceEpoch(json["iat"] * 1000),
        notBefore = new DateTime.fromMillisecondsSinceEpoch(json["nbf"] * 1000),
        expiry = new DateTime.fromMillisecondsSinceEpoch(json["exp"] * 1000),
        type = json["typ"],
        jti = json["jti"],
        cn = json[_attrId]["cn"],
        displayName = json[_attrId]["displayname"],
        mail = json[_attrId]["mail"],
        eduPersonScopedAffiliation =
            json[_attrId]["edupersonscopedaffiliation"],
        givenName = json[_attrId]["givenname"],
        surname = json[_attrId]["surname"],
        eduPersonPrincipalName = json[_attrId]["edupersonprincipalname"],
        auEduPersonSharedToken = json[_attrId]["auedupersonsharedtoken"],
        eduPersonTargetdId = json[_attrId]["edupersontargetedid"] {}

  Set<ConstraintViolation> validate(
      covariant RapidAafClaimSetValidationContext validationContext) {
    final violations = new Set<ConstraintViolation>();

    if (subject is! String || subject.isEmpty) {
      violations.add(new ConstraintViolation("Bad subject"));
    }

    if (issuer != validationContext.expectedIssuer) {
      violations.add(new ConstraintViolation("Invalid issuer: \"$issuer\""));
    }
    if (audience != validationContext.expectedAudience) {
      violations
          .add(new ConstraintViolation("Invalid audience: \"$audience\""));
    }

    final now = testTime ?? new DateTime.now(); // for testing set testTime

    if (now.isBefore(issuedAt.subtract(validationContext.maxClockSkew))) {
      var diff = issuedAt.difference(now);
      violations
          .add(new ConstraintViolation("Issued in the future: $diff h:m:s"));
    }
    if (now.isBefore(notBefore.subtract(validationContext.maxClockSkew))) {
      var diff = notBefore.difference(now);
      violations.add(new ConstraintViolation("Not yet valid: $diff h:m:s"));
    }
    if (now.isAfter(expiry.add(validationContext.maxClockSkew))) {
      var diff = now.difference(expiry);
      violations.add(new ConstraintViolation("Expired: by $diff h:m:s"));
    }

    if (type != "authnresponse") {
      violations.add(new ConstraintViolation("Bad type: $type"));
    }

    if (jti is! String || jti.isEmpty) {
      violations.add(new ConstraintViolation("Bad jti"));
    }
    // Note: jti should not have been previously seen, to prevent replay attacks

    return violations;
  }

  Map toJson() {
    return {
      'sub': subject,
      'iss': issuer,
      'aud': audience,
      'iat': (issuedAt.millisecondsSinceEpoch ?? 0) ~/ 1000,
      'nbf': (notBefore.millisecondsSinceEpoch ?? 0) ~/ 1000,
      'exp': (expiry.millisecondsSinceEpoch ?? 0) ~/ 1000,
      'typ': type,
      'jti': jti,
      _attrId: {
        'cn': cn,
        'displayname': displayName,
        'mail': mail,
        'edupersonscopedaffiliation': eduPersonScopedAffiliation,
        'givenname': givenName,
        'surname': surname,
        'edupersonprincipalname': eduPersonPrincipalName,
        'auedupersonsharedtoken': auEduPersonSharedToken,
        'edupersontargetedid': eduPersonTargetdId
      }
    };
  }

  String toString() {
    var s = new StringBuffer();

    s.write("""
                       sub: $subject
                       iss: $issuer
                       aud: $audience
                       iat: $issuedAt
                       nbf: $notBefore
                       exp: $expiry
                       typ: $type
                       jti: $jti
""");
    if (cn != null) {
      s.write("                        cn: $cn\n");
    }
    if (displayName != null) {
      s.write("               displayname: $displayName\n");
    }

    if (mail != null) {
      s.write("                      mail: $mail\n");
    }
    if (eduPersonScopedAffiliation != null) {
      s.write("edupersonscopedaffiliation: $eduPersonScopedAffiliation\n");
    }
    if (givenName != null) {
      s.write("                 givenname: $givenName\n");
    }
    if (surname != null) {
      s.write("                   surname: $surname\n");
    }
    if (eduPersonPrincipalName != null) {
      s.write("    edupersonprincipalname: $eduPersonPrincipalName\n");
    }
    if (auEduPersonSharedToken != null) {
      s.write("    auedupersonsharedtoken: $auEduPersonSharedToken\n");
    }
    if (eduPersonTargetdId != null) {
      s.write("       edupersontargetedid: $eduPersonTargetdId\n");
    }
    return s.toString();
  }
}

/// Context for validation of an AAF Rapid Connect claim set.

class RapidAafClaimSetValidationContext extends JwtClaimSetValidationContext {
  final String expectedIssuer;
  final String expectedAudience;
  final Duration maxClockSkew;

  RapidAafClaimSetValidationContext(this.expectedIssuer, this.expectedAudience,
      {Duration maxClockSkew: const Duration(seconds: 30)})
      : maxClockSkew = maxClockSkew,
        super(expiryTolerance: maxClockSkew);
}

/// Context for validation of an AAF Rapid Connect token.

class RapidAafValidationContext extends JwtValidationContext {
  RapidAafValidationContext(
      String sharedSecret, RapidAafClaimSetValidationContext csvc)
      : super(new JwaSymmetricKeySignatureContext(sharedSecret), csvc) {}
}

/// Parsing method for an AAF Rapid Connect token.

RapidAafClaimSet rapidAafClaimSetParser(Map json) {
  try {
    return new RapidAafClaimSet.fromJson(json);
  } catch (e) {
    throw new FormatException("Bad AAF Rapid Connect JWT: $e", json.toString());
  }
}

//----------------------------------------------------------------
// Main tests

void main() {
  var example =
      "eyJ0eXAiOiJKc29uV2ViVG9rZW4iLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJodHR"
      "wczovL3JhcGlkLmFhZi5lZHUuYXUhaHR0cHM6Ly9zZXJ2aWNlLmV4YW1wbGUuY29"
      "tIWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6IiwiaXNzIjoiaHR0cHM6Ly9yYXB"
      "pZC5hYWYuZWR1LmF1IiwiYXVkIjoiaHR0cHM6Ly9zZXJ2aWNlLmV4YW1wbGUuY29"
      "tIiwiaHR0cHM6Ly9hYWYuZWR1LmF1L2F0dHJpYnV0ZXMiOnsiY24iOiJHYW5kYWx"
      "mIHRoZSBHcmV5IiwiZGlzcGxheW5hbWUiOiJEciBHYW5kYWxmIHRoZSBHcmV5Iiw"
      "ibWFpbCI6ImdhbmRhbGZAZXhhbXBsZS5jb20iLCJlZHVwZXJzb25zY29wZWRhZmZ"
      "pbGlhdGlvbiI6InN0YWZmQGV4YW1wbGUuY29tIiwiZ2l2ZW5uYW1lIjoiR2FuZGF"
      "sZiIsInN1cm5hbWUiOiJHcmV5IiwiZWR1cGVyc29ucHJpbmNpcGFsbmFtZSI6ImV"
      "nZ2FuZGFsZmdyZXlAZXhhbXBsZS5jb20iLCJhdWVkdXBlcnNvbnNoYXJlZHRva2V"
      "uIjoibmhScWhDcmVmYmExX0dHYWJjZGVmZ2hpamtsIiwiZWR1cGVyc29udGFyZ2V"
      "0ZWRpZCI6Imh0dHBzOi8vcmFwaWQuYWFmLmVkdS5hdSFodHRwczovL3NlcnZpY2U"
      "uZXhhbXBsZS5jb20hYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoifSwiaWF0Ijo"
      "xNDgyNjI0MDAwLCJuYmYiOjE0ODI2MjQwMDAsImV4cCI6MTQ4MjYyNDEyMCwidHl"
      "wIjoiYXV0aG5yZXNwb25zZSIsImp0aSI6ImFQNFhIZTRJR0todGxnTUxyR002NzN"
      "KOWNFUmVYNDY1In0.R4VVEWcJx61AMoKuT7mM9IGLpREWg3UCkvcBWlE9LcU";
  var exampleCreateTime = new DateTime.utc(2016, 12, 25);

  final rapidAafValidationContext = new RapidAafValidationContext(
      "s3cr3t",
      new RapidAafClaimSetValidationContext(
          "https://rapid.aaf.edu.au", "https://service.example.com"));

  test('valid token', () {
    try {
      testTime = exampleCreateTime.add(new Duration(seconds: 5));

      var jwt = new JwtInJws<RapidAafClaimSet>.decode(
          example, rapidAafValidationContext, rapidAafClaimSetParser);

      var header = jwt.header.toJson();
      var claimSet = jwt.claimSet;

      //print(header);
      //print(claimSet);

      expect(header["alg"], equals("HS256"));
      expect(header["typ"], equals("JsonWebToken")); // TODO: check in validate?

      expect(claimSet.givenName, equals("Gandalf"));
    } on ConstraintViolations catch (e) {
      fail("Unexpected exception: ${e.summaryMessage}");
    }
  });

  test('wrong issuer', () {
    try {
      testTime = exampleCreateTime;

      final vc = new RapidAafValidationContext(
          "s3cr3t",
          new RapidAafClaimSetValidationContext(
              "https://bogus-issuer.example.net",
              "https://service.example.com"));
      new JwtInJws.decode(example, vc, rapidAafClaimSetParser);
      fail("Did not throw exception");
    } on ConstraintViolations catch (e) {
      expect(e.violations.length, equals(1));
      expect(e.violations.first.message, startsWith("Invalid issuer:"));
    }
  });

  test('wrong audience', () {
    try {
      testTime = exampleCreateTime;

      final vc = new RapidAafValidationContext(
          "s3cr3t",
          new RapidAafClaimSetValidationContext(
              "https://rapid.aaf.edu.au", "http://not-me.example.net"));
      new JwtInJws.decode(example, vc, rapidAafClaimSetParser);
      fail("Did not throw exception");
    } on ConstraintViolations catch (e) {
      expect(e.violations.length, equals(1));
      expect(e.violations.first.message, startsWith("Invalid audience:"));
    }
  });

  test("not yet valid", () {
    try {
      // Max clock skew: 30 seconds
      testTime = exampleCreateTime.subtract(new Duration(seconds: 31));
      new JwtInJws.decode(
          example, rapidAafValidationContext, rapidAafClaimSetParser);
      fail("Did not throw exception");
    } on ConstraintViolations catch (e) {
      expect(e.violations.length, equals(2));
      e.violations.forEach((v) {
        if (!(v.message.startsWith("Issued in the future:") ||
            v.message.startsWith("Not yet valid:"))) {
          fail("Unexpected violation: ${v.message}");
        }
      });
    }
  });

  test("expired", () {
    try {
      // Expiry is 2 minutes after it was created; max clock skew: 30 seconds
      testTime = exampleCreateTime.add(new Duration(minutes: 2, seconds: 31));
      new JwtInJws.decode(
          example, rapidAafValidationContext, rapidAafClaimSetParser);
      fail("Did not throw exception");
    } on ConstraintViolations catch (e) {
      expect(e.violations.length, equals(1));
      expect(e.violations.first.message, startsWith("Expired:"));
    }
  });

  test("bad token", () {
    for (var badStr in [
      "e30K",
      "e30K.e30K",
      "e30K.e30K.e30K.e30K",
      "foobar.e30K.e30K",
      "e30K.e30K.e30K"
    ]) {
      try {
        new JwtInJws.decode(
            badStr, rapidAafValidationContext, rapidAafClaimSetParser);
        fail("Did not throw exception");
      } on FormatException {
        //print("${e.runtimeType}: $e");
      } on ArgumentError {
        //print("${e.runtimeType}: $e");
      }
    }
  });
}
