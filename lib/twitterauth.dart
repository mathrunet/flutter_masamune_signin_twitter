part of masamune.signin.twitter;

/// Sign in to Firebase using Twitter Login.
class TwitterAuth {
  /// Set options for authentication.
  ///
  /// [twitterAPIKey]: Twitter API Key.
  /// [twitterAPISecret]: Twitter API Secret.
  static void initialize({String twitterAPIKey, String twitterAPISecret}) {
    _twitterAPIKey = twitterAPIKey;
    _twitterAPISecret = twitterAPISecret;
  }

  /// Gets the options for the provider.
  static const AuthProviderOptions options = const AuthProviderOptions(
      id: "twitter",
      provider: _provider,
      title: "Twitter SignIn",
      text: "Sign in with your Twitter account.");
  static Future<FirestoreAuth> _provider(
      BuildContext context, Duration timeout) {
    return signIn(timeout: timeout);
  }

  static String _twitterAPIKey;
  static String _twitterAPISecret;

  /// Sign in to Firebase using Twitter Login.
  ///
  /// [protorol]: Protocol specification.
  /// [timeout]: Timeout time.
  static Future<FirestoreAuth> signIn(
      {String protocol, Duration timeout = Const.timeout}) {
    return FirestoreAuth.signInWithProvider(
        providerCallback: (timeout) async {
          TwitterLogin twitter = TwitterLogin(
              consumerKey: _twitterAPIKey, consumerSecret: _twitterAPISecret);
          TwitterLoginResult result = await twitter.authorize();
          switch (result.status) {
            case TwitterLoginStatus.cancelledByUser:
              Log.error("Login canceled");
              return Future.delayed(Duration.zero);
            case TwitterLoginStatus.error:
              Log.error("Login terminated with error: ${result.errorMessage}");
              return Future.delayed(Duration.zero);
            default:
              break;
          }
          return TwitterAuthProvider.getCredential(
              authToken: result.session.token,
              authTokenSecret: result.session.secret);
        },
        providerId: TwitterAuthProvider.providerId,
        protocol: protocol,
        timeout: timeout);
  }
}
