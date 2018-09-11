## 0.6.0

- JwtInJws class made public.
- Made header available in JsonWebToken.
- JwsType support for arbitrary values for 'typ' in headers.

## 0.5.2

- increase upper bound on crypto

## 0.5.1

- increase upper bound on crypto

## 0.5.0

- use new urlSafe base64 codec in core dart:convert package
- Breaking change: Now requires SDK >=1.16.0-dev.5.4

## 0.4.6

- updated crypto dependency with required code changes

## 0.4.5

* Fails parsing JWT headers without optional "typ" header parameter (2)

## 0.4.4

* restored optionality of `typ`

## 0.4.2

* changed to test package

## 0.4.1

* widen dependency ranges

## 0.4.0

* Abstracted out a base JwtClaimSet. Old JwtClaimSet is now renamed OpenIdJwtClaimSet (breaking)
* Removed MutableJwtClaimSet (breaking)
* Added MapJwtClaimSet

## 0.3.0

* Audience is now a List (breaking)
* MutableJwtClaimSet now deprecated

## 0.2.0

* Improvements for RSA. Thanks to Jonas Kello for the contribution

## 0.1.3

* Add RSA signatures. Thanks to Tais Plougmann Hansen for the contribution

## 0.1.2

* make typ header optional and default to JWT

## 0.1.1

* Add audience claim

## 0.1.0+2

* Bug fix. Had dependency on sdk 1.3 without realising it. Changed sdk version in
pubspec.yaml

