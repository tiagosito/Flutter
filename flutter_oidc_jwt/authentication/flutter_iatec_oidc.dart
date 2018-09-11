import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/widgets.dart';
import 'package:adventist_student/oauth/generic_iatec_button.dart';
import 'package:adventist_student/oauth/iatec_login.dart';

export 'package:adventist_student/oauth/model/token.dart';

/// A button widget matching the official "Sign in with Your_Project_Name" design
///
/// It requires a Iatec client_id and client_secret, and success/failure/cancel callbacks
class IatecButton extends StatefulWidget {
  final VoidCallback onSuccess;
  final VoidCallback onCancelledByUser;
  final VoidCallback onFailure;

  final String clientId;
  final String clientSecret;
  final String redirectUrl;
  final List<String> scopes;

  const IatecButton({@required this.clientId,
    @required this.clientSecret,
    @required this.scopes,
    @required this.onSuccess,
    @required this.onCancelledByUser,
    @required this.onFailure,
   this.redirectUrl});

  bool get enabled => onSuccess != null;

  @override
  _IatecButtonState createState() => new _IatecButtonState();
}

class _IatecButtonState extends State<IatecButton>
    with SingleTickerProviderStateMixin {
  @override
  Widget build(BuildContext context) {
    return new GenericIatecButton(
        clientId: widget.clientId,
        clientSecret: widget.clientSecret,
        scopes: widget.scopes,
        onSuccess: widget.onSuccess,
        onCancelledByUser: widget.onCancelledByUser,
        onFailure: widget.onFailure,
        onTap: onTap);
  }

  onTap() async {
    bool success = await Navigator.of(context).push(new MaterialPageRoute<bool>(
      builder: (BuildContext context) =>
      new IatecLoginWebViewPage(
        clientId: widget.clientId,
        clientSecret: widget.clientSecret,
        redirectUrl: widget.redirectUrl,
        scopes: widget.scopes,
      ),
    ));

    // if success == null, user just closed the webview
    if (success == null) {
      widget.onCancelledByUser();
    } else if (success == false) {
      widget.onFailure();
    } else if (success) {
      widget.onSuccess();
    }
  }
}
