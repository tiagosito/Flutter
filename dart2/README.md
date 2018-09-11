# JSON Web Token (JWT) for Dart

## Introduction

Provides an implementation of [JSON Web Token](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-19) standard.
    
## Using
### Basic Usage

####Decoding####

To decode a JWT string

```
JsonWebToken jwt = new JsonWebToken.decode(jwtStr);
```
**Validating**

To validate the decoded jwt

```
Set<ConstraintViolation> violations = jwt.validate(new JwtClaimSetValidationContext());
```

If the jwt is valid this will return an empty set. Otherwise the set will contain all the things that were invalid.

This validates the signature and the claim set.

Note you can also validate as you decode

```
JsonWebToken jwt = new JsonWebToken.decode(jwtStr, validationContext: new JwtClaimSetValidationContext());

```

This will throw a `ConstraintViolations` object if the validation fails.

**Claim Set**
The jwt object contains the set of claims being made. You can access them like so

```
JwtClaimSet claimSet = jwt.claimSet;
print('${claimSet.issuer}');
```
`JwtClaimSet` contains all the standard Jwt claims and validation also covers things like checking the expiry etc.

####Encoding####
**Claim Set**

First create a new claim set 

```
final issuedAt = DateTime.now();
final expiry = issuedAt.add(const Duration(minutes: 3));

final claimSet = new JwtClaimSet('the issuer', 'fred user', expiry, issuedAt));
```

or if you need a more complex building process you can use `MutableJwtClaimSet` in a builder style

```
final claimSet = (new MutableJwtClaimSet()
  ..issuer=issuer
  ..subject=subject
  ..expiry=expiry
  ..issuedAt=issuedAt)
  .toImmutable();
```
**Create the Jwt**

To create a JWT encoded inside a Json Web Signature (JWS)

```
final signatureContext = new JwaSignatureContext(sharedSecret);
final jwt = new JsonWebToken.jws(claimSet, signatureContext);
``` 
_Note: JWE encoded JWT is not yet implemented_

**Encoding**

Encoding is simply a matter of calling the `encode` method

```
String jwtString = jwt.encode();
```

### Extending

**Custom Claims**

The main way to extend the Jwt library is to add custom claims to the claimset. The following is an example of such a case.
Basically you need to extend JwtClaimSet, add your fields, the to / from json and validation.

```
class ProductHostClaimSet extends JwtClaimSet {
  final String queryStringHash;
  
  ProductHostClaimSet(String issuer, String subject, DateTime expiry, DateTime issuedAt,
      this.queryStringHash) 
    : super(issuer, subject, expiry, issuedAt);
  
  ProductHostClaimSet.fromJson(Map json)
      : queryStringHash = json['qsh'],
        super.fromJson(json);

  @override
  Map toJson() {
    return super.toJson()
        ..['qsh']=queryStringHash;
  }
  
  @override
  Set<ConstraintViolation> validate(ProductHostClaimSetValidationContext validationContext) {
    return super.validate(validationContext)
    	..addAll(_validateQsh(validationContext));
  }
  
  Set<ConstraintViolation> _validateQsh(ProductHostClaimSetValidationContext validationContext) {
    final String expectedQsh = validationContext.qshFactory();
    return queryStringHash == expectedQsh ? new Set.identity() 
        : (new Set()..add(new ConstraintViolation(
            "Query String Hash mismatch. Expected '$expectedQsh'. Got '$queryStringHash'")));
  }
  
}
```

You can then just create the Jwt in the normal manner

```
final jwt = new JsonWebToken.jws(claimSet, signatureContext);
``` 
Of course if you are not a fan of structure you can always add a single field which is a map containing all the extra claims.

## Limitations

Currently this supports enough of the JWT spec that was needed for a project. Specifically it only implements:

* JWS (no JWE support).
* HS256 for the JWS signature.

Whilst it is interoperating with a Java based implemention, a rigorous review of conformance to the spec has not been undertaken. Please file issues or PR's if you spot any issues with conformance or find bugs in general or need new features.

PR's with good tests will be looked apon favourably ;-)


## Issues

* Validation needs work. The intention is to piggy back off a constraint validation library (similar to Java Bean Validation) but I haven't written that yet.
