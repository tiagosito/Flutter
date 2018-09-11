library jwt.codec;

import 'dart:convert';

import 'jws.dart';
import 'jwt.dart';
import 'jwt_claimset.dart';

typedef JsonWebToken<CS> JwtTokenDecoder<CS extends JwtClaimSet>(String jwtToken, {JwsValidationContext validationContext});

typedef CS JwtClaimSetDecoder<CS extends JwtClaimSet>(Map claimSetJson,
    {JwsValidationContext validationContext});

JwtTokenDecoder<JwtClaimSet> defaultJwtTokenDecoder(
    JwtClaimSetDecoder claimSetDecoder) {
  return (String jwtToken, {JwsValidationContext validationContext}) =>
      new JsonWebToken.decode(jwtToken,
          validationContext: validationContext,
          claimSetParser: claimSetDecoder);
}

class JwtCodec<CS extends JwtClaimSet>
    extends Codec<JsonWebToken<CS>, String> {
  final Converter<JsonWebToken<CS>, String> encoder =
      new JwtEncoder<CS>();
  final Converter<String, JsonWebToken<CS>> decoder;

  JwtCodec(this.decoder);

  JwtCodec.simple(JwtTokenDecoder<CS> decoder,
      {JwsValidationContextFactory contextFactory})
      : this(new JwtDecoder(decoder, contextFactory));

  JwtCodec.def(JwtClaimSetDecoder<CS> decoder,
      {JwsValidationContextFactory contextFactory})
      : this(new JwtDecoder(defaultJwtTokenDecoder(decoder), contextFactory));
}

class JwtDecoder<CS extends JwtClaimSet>
    extends Converter<String, JsonWebToken<CS>> {
  final JwtTokenDecoder<CS> decoder;
  final JwsValidationContextFactory contextFactory;

  JwtDecoder(this.decoder, this.contextFactory);

  @override
  JsonWebToken<CS> convert(String input) => contextFactory != null
      ? decoder(input, validationContext: contextFactory())
      : decoder(input);
}

class JwtEncoder<CS extends JwtClaimSet>
    extends Converter<JsonWebToken<CS>, String> {
  @override
  String convert(JsonWebToken<CS> input) => input.encode();
}
