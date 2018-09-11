library openid;

import 'dart:async';
import 'http_util.dart' as http;
import 'dart:convert';

import 'model.dart';
import 'id_token.dart';

final Map<Uri,JsonWebKeySet> _keySetCache = {};

/// Represents an OpenId Provider
class Issuer {

  /// The OpenId Provider's metadata
  final OpenIdProviderMetadata metadata;

  final Map<String,String> claimsMap;

  /// Creates an issuer from its metadata.
  Issuer(this.metadata, {this.claimsMap: const {}});

  /// Url of the facebook issuer.
  ///
  /// Note: facebook does not support OpenID Connect, but the authentication
  /// works.
  static final Uri facebook = Uri.parse("https://www.facebook.com");

  /// Url of the google issuer.
  static final Uri google = Uri.parse("https://accounts.google.com");

  /// Url of the yahoo issuer.
  static final Uri yahoo = Uri.parse("https://api.login.yahoo.com");

  /// Url of the microsoft issuer.
  static final Uri microsoft = Uri.parse("https://login.microsoftonline.com/common");

  /// Url of the salesforce issuer.
  static final Uri salesforce = Uri.parse("https://login.salesforce.com");

  static Uri firebase(String id) => Uri.parse("https://securetoken.google.com/$id");

  static final Map<Uri,Issuer> _discoveries = {
    facebook : new Issuer(new OpenIdProviderMetadata(
        issuer: facebook,
        authorizationEndpoint: Uri.parse("https://www.facebook.com/v2.8/dialog/oauth"),
        tokenEndpoint: Uri.parse("https://graph.facebook.com/v2.8/oauth/access_token"),
        userinfoEndpoint: Uri.parse("https://graph.facebook.com/v2.8/879023912133394"),
        responseTypesSupported: ["token","code","code token"],
        tokenEndpointAuthMethodsSupported: ["client_secret_post"],
        scopesSupported: ["public_profile","user_friends","email",
        "user_about_me","user_actions.books","user_actions.fitness",
        "user_actions.music","user_actions.news","user_actions.video",
        "user_birthday","user_education_history","user_events",
        "user_games_activity","user_hometown","user_likes","user_location",
        "user_managed_groups","user_photos","user_posts","user_relationships",
        "user_relationship_details","user_religion_politics","user_tagged_places",
        "user_videos","user_website","user_work_history","read_custom_friendlists",
        "read_insights","read_audience_network_insights","read_page_mailboxes",
        "manage_pages","publish_pages","publish_actions","rsvp_event",
        "pages_show_list","pages_manage_cta","pages_manage_instant_articles",
        "ads_read","ads_management","business_management","pages_messaging",
        "pages_messaging_subscriptions", "pages_messaging_phone_number"]
    )),
    google: null,
    yahoo: null,
    microsoft: null,
    salesforce: null
  };

  static Iterable<Uri> get knownIssuers => _discoveries.keys;

  /// Discovers the OpenId Provider's metadata based on its uri.
  static Future<Issuer> discover(Uri uri) async {
    if (_discoveries[uri]!=null) return _discoveries[uri];

    var segments = uri.pathSegments.toList();
    if (segments.isNotEmpty&&segments.last.isEmpty) {
      segments.removeLast();
    }
    segments.addAll([".well-known","openid-configuration"]);
    uri = uri.replace(pathSegments: segments);

    var json = await http.get(uri);
    return _discoveries[uri] = new Issuer(new OpenIdProviderMetadata.fromJson(json));
  }

  /// Finds the [JsonWebKey] that matches the `kid` argument.
  Future<JsonWebKey> findJsonWebKey(String kid) async {
    var set = _keySetCache[metadata.jwksUri];
    if (set==null||set.findKey(kid)==null) {
      set = _keySetCache[metadata.jwksUri] =
      new JsonWebKeySet.fromJson(await http.get(metadata.jwksUri));
    }
    return set.findKey(kid);
  }
}

/// Represents the client application.
class Client {

  /// The id of the client.
  final String clientId;

  /// A secret for authenticating the client to the OP.
  final String clientSecret;

  /// The [Issuer] representing the OP.
  final Issuer issuer;

  Client(this.issuer, this.clientId, [this.clientSecret]);

  static Future<Client> forIdToken(String idToken) async {
    var token = new IdToken.decode(idToken);
    if (token.openIdClaimsSet.issuer==null)
      throw new ArgumentError("Token has no issuer.");
    var issuer = await Issuer.discover(token.openIdClaimsSet.issuer);
    var clientId = token.openIdClaimsSet.authorizedParty ?? token.openIdClaimsSet.audience.single;
    return new Client(issuer, clientId);
  }

  /// Creates a [Credential] for this client.
  TokenResponse createTokens({String accessToken, String tokenType,
    String refreshToken, String idToken}) =>
       new TokenResponse(accessToken: accessToken,
          tokenType: tokenType, refreshToken: refreshToken,
          idToken: new IdToken.decode(idToken));


}



class Flow {

  final String responseType;

  final Client client;

  final List<String> scopes = [];

  String state;

  Uri redirectUri = Uri.parse("http://localhost");

  Flow._(this.responseType, this.client) {
    var scopes = client.issuer.metadata.scopesSupported;
    for (var s in const["openid","profile","email"]) {
      if (scopes.contains(s)) {
        this.scopes.add(s);
        break;
      }
    }
  }

  Flow.authorizationCode(Client client) : this._("code",client);

  Flow.implicit(Client client) : this._(
      ["token id_token","id_token","token"]
          .firstWhere((v)=>client.issuer.metadata.responseTypesSupported.contains(v)),client);

  Uri get authenticationUri => client.issuer.metadata.authorizationEndpoint
      .replace(queryParameters: _authenticationUriParameters);

  Map<String,String> get _authenticationUriParameters => {
    "response_type": responseType,
    "scope": scopes.join(" "),
    "client_id": client.clientId,
    "redirect_uri": redirectUri.toString(),
    "state": state
  }..addAll(responseType.split(" ").contains("id_token") ? {"nonce":"xx"} : {});

  Future<TokenResponse> _getToken(String code) async {
    var methods = client.issuer.metadata.tokenEndpointAuthMethodsSupported;
    var json;
    if (client.clientSecret==null) {
      throw new StateError("Client secret not known.");
    }
    if (methods.contains("client_secret_post")) {
      json = await http.post(client.issuer.metadata.tokenEndpoint, body: {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirectUri.toString(),
        "client_id": client.clientId,
        "client_secret": client.clientSecret
      });
    } else if (methods.contains("client_secret_basic")) {
      var h = base64.encode("${client.clientId}:${client.clientSecret}".codeUnits);
      json = await http.post(client.issuer.metadata.tokenEndpoint, headers: {
        "authorization": "Basic $h"
      }, body: {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirectUri.toString()
      });
    } else {
      throw new UnsupportedError("Unknown auth methods: $methods");
    }
    return new TokenResponse.fromJson(json);
  }

  Future<TokenResponse> getTokenRefresh(String refreshToken) async {

    var methods = client.issuer.metadata.tokenEndpointAuthMethodsSupported;
    var json;
    if (client.clientSecret==null) {
      throw new StateError("Client secret not known.");
    }
    if (methods.contains("client_secret_post")) {
      json = await http.post(client.issuer.metadata.tokenEndpoint, body: {
        "grant_type": "refresh_token",
        "refresh_token": refreshToken,
        "redirect_uri": redirectUri.toString(),
        "client_id": client.clientId,
        "client_secret": client.clientSecret
      });
    } else if (methods.contains("client_secret_basic")) {
      var h = base64.encode("${client.clientId}:${client.clientSecret}".codeUnits);
      json = await http.post(client.issuer.metadata.tokenEndpoint, headers: {
        "authorization": "Basic $h"
      }, body: {
        "grant_type": "authorization_code",
        "refresh_token": refreshToken,
        "redirect_uri": redirectUri.toString()
      });
    } else {
      throw new UnsupportedError("Unknown auth methods: $methods");
    }
    return new TokenResponse.fromJson(json);
  }

  Future<TokenResponse> callback(Map<String,String> response) async {

    if (response.containsKey("code")) {
      var code = response["code"];
      print("callback -> _getToken($code)");
      var result = await _getToken(code);
      return result;
    } else if (response.containsKey("access_token")||response.containsKey("id_token")) {
      return new TokenResponse.fromJson(response);
    } else {
      throw new ArgumentError("Invalid response: $response");
    }
  }

  Future<TokenResponse> callback2(Map<String,String> response) async {
    if (response.containsKey("code")) {
      var code = response["code"];
      var result = await _getToken(code);

      if(result != null)
        return result;

      //return new Credential._(client, result);
    } else if (response.containsKey("access_token")||response.containsKey("id_token")) {
      return new TokenResponse.fromJson(response);
    } else {
      throw new ArgumentError("Invalid response: $response");
    }
    return null;
  }

  Future<TokenResponse> getTokenByCode(String code) async {
    var methods = client.issuer.metadata.tokenEndpointAuthMethodsSupported;
    var json;
    if (client.clientSecret==null) {
      throw new StateError("Client secret not known.");
    }
    if (methods.contains("client_secret_post")) {
      json = await http.post(client.issuer.metadata.tokenEndpoint, body: {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirectUri.toString(),
        "client_id": client.clientId,
        "client_secret": client.clientSecret
      });
    } else if (methods.contains("client_secret_basic")) {
      var h = base64.encode("${client.clientId}:${client.clientSecret}".codeUnits);
      json = await http.post(client.issuer.metadata.tokenEndpoint, headers: {
        "authorization": "Basic $h"
      }, body: {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirectUri.toString()
      });
    } else {
      throw new UnsupportedError("Unknown auth methods: $methods");
    }
    var tokenResult = new TokenResponse.fromJson(json);
    return tokenResult;
  }

  Future<dynamic> getTokenByUri(Uri uri) async {

    var code = uri.queryParameters;

    var methods = client.issuer.metadata.tokenEndpointAuthMethodsSupported;
    var json;
    if (client.clientSecret==null) {
      throw new StateError("Client secret not known.");
    }
    if (methods.contains("client_secret_post")) {
      json = await http.post(client.issuer.metadata.tokenEndpoint, body: {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirectUri.toString(),
        "client_id": client.clientId,
        "client_secret": client.clientSecret
      });
    } else if (methods.contains("client_secret_basic")) {
      var h = base64.encode("${client.clientId}:${client.clientSecret}".codeUnits);
      json = await http.post(client.issuer.metadata.tokenEndpoint, headers: {
        "authorization": "Basic $h"
      }, body: {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirectUri.toString()
      });
    } else {
      throw new UnsupportedError("Unknown auth methods: $methods");
    }
    //var tokenResult = new TokenResponse.fromJson(json);
    return json;
  }
}
