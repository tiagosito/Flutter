import 'dart:async';

import 'package:adventist_student/oauth/iatec_login.dart';
import 'package:adventist_student/oauth/shared_preference_constants.dart';
import 'package:adventist_student/oidc/model.dart';
import 'package:adventist_student/oidc/openid.dart';
import 'package:adventist_student/oidc/openid.dart' as oidc;
import 'package:adventist_student/src/utils/functions_utils.dart' as functionsUtils;
import 'package:adventist_student/src/utils/globals.dart' as globals;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/widgets.dart';
import 'package:shared_preferences/shared_preferences.dart';

export 'package:adventist_student/oauth/model/token.dart';
//export 'package:adventist_student/oauth/iatec.dart';

class Authentication {
  oidc.Flow flow;

  final BuildContext context;
  final String clientId;
  final String clientSecret;
  final String redirectUrl;
  final List<String> scopes;

  Authentication(this.context, this.clientId, this.clientSecret, this.redirectUrl, this.scopes);

  Future<bool> init() async {
    flow = await getFlow();
    return true;
  }

  Future<Client> getClient() async {
    final issuer = await Issuer.discover(Uri.parse(globals.authorizationValues.authorityUrl));
    final client = new Client(issuer, clientId, clientSecret);
    return client;
  }

  Future<oidc.Flow> getFlow() async {
    final client = await getClient();
    final f = new oidc.Flow.authorizationCode(client);
    f.scopes.addAll(scopes);
    f.redirectUri = Uri.parse(redirectUrl);
    return f;
  }

  //Authentication
  authenticate(VoidCallback onCancelledByUser, VoidCallback onFailure, VoidCallback onSuccess) async {
    bool success = await Navigator.of(context).push(new MaterialPageRoute<bool>(
          builder: (BuildContext context) => new IatecLoginWebViewPage(
                clientId: clientId,
                clientSecret: clientSecret,
                redirectUrl: redirectUrl,
                scopes: scopes,
                codeFlow: flow,
              ),
        ));

    // if success == null, user just closed the webview
    if (success == null) {
      onCancelledByUser();
    } else if (success == false) {
      onFailure();
    } else if (success) {
      await storeAccessTokenInDevice();
      onSuccess();
    }
  }

  //Refresh Token
  Future<TokenResponse> refreshToken(VoidCallback onCancelledByUser, VoidCallback onFailure, VoidCallback onSuccess) async {
    try {
      if (clientSecret == null && clientSecret.isEmpty) {
        throw new StateError("Client secret not known.");
      }

      String refreshTokenValue = globals.tokens.refreshToken;
      print("refreshToken -> getTokenRefresh($refreshTokenValue)");
      var result = await flow.getTokenRefresh(refreshTokenValue);

      if (result != null && result.accessToken != null && result.accessToken.isNotEmpty) {
        globals.tokens = result;
        await storeAccessTokenInDevice();
        onSuccess();
      } else {
        onFailure();
      }

      return result;
    } catch (ex) {
      return null;
    }
  }

  //Store the access token on the user's device
  Future<bool> storeAccessTokenInDevice() async {
    try {
//      Future<SharedPreferences> _prefs = SharedPreferences.getInstance();
//      final SharedPreferences prefs = await _prefs;

      var tokens = globals.tokens;
//      var claimsSet = globals.tokens.idToken.openIdClaimsSet;

      List<String> list = new List();
//      list.add(claimsSet.preferredUsername); //[0] Username
//      list.add(claimsSet.email); //[1] Email
//      list.add(claimsSet.birthdate); //[2] Birthdate
//      list.add(claimsSet.expiry.toString()); //[3] Expiry
//      list.add(tokens.expiresIn.toString()); //[4] Expires in
//      list.add(tokens.accessToken); //[5] Access Token
//      list.add(tokens.tokenType); //[6] Access Token
//      list.add(tokens.refreshToken); //[7] Refresh Token
//      list.add(tokens.idToken.idTokenValue); //[8] Id Token

      //Store Token

      list.add(tokens.expiresIn.toString()); //[0] Expires in
      list.add(tokens.accessToken); //[1] Access Token
      list.add(tokens.tokenType); //[2] Access Token
      list.add(tokens.refreshToken); //[3] Refresh Token
      list.add(tokens.idToken.idTokenValue); //[4] Id Token

      await functionsUtils.storeDataInDevice(SharedPreferenceConstants.keySharedPreferencesToken, list);
      //await prefs.setStringList(IatecConstants.keySharedPreferencesToken, list);

      //Store Time Expiration
      String expirationDate = new DateTime.now().add(new Duration(seconds: tokens.expiresIn)).toString();
      await functionsUtils.storeDataInDevice(SharedPreferenceConstants.keySharedPreferencesTokenExpirationDate, expirationDate);
      //await prefs.setString(IatecConstants.keySharedPreferencesTokenExpirationDate, expirationDate);

      return true;
    } catch (ex) {
      return false;
    }
  }

  //Retrieve the access token that was saved on the user's device
  Future<List<String>> retieveAccessToken(String key) async {
    List<String> list = new List();
    try {
      Future<SharedPreferences> _prefs = SharedPreferences.getInstance();
      await _prefs.then((SharedPreferences prefs) {
        list = prefs.getStringList(key);
      });
    } catch (ex) {
      print(ex.toString());
    }

    return list;
  }

  //Retrieve the access token expiration date that was saved on the user's device
  Future<String> retrieveAccessTokenExpirationDate(String key) async {
    String expirationDate;
    try {
      Future<SharedPreferences> _prefs = SharedPreferences.getInstance();
      await _prefs.then((SharedPreferences prefs) {
        expirationDate = prefs.getString(key);
      });
    } catch (ex) {
      print(ex.toString());
    }

    return expirationDate;
  }
}
