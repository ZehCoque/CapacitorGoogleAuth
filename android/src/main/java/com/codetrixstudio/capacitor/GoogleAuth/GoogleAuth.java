package com.codetrixstudio.capacitor.GoogleAuth;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerFuture;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import androidx.activity.result.ActivityResult;

import com.codetrixstudio.capacitor.GoogleAuth.capacitorgoogleauth.R;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.google.android.gms.auth.api.signin.GoogleSignIn;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.gms.auth.api.signin.GoogleSignInClient;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.tasks.Task;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.OnFailureListener;

@CapacitorPlugin()
public class GoogleAuth extends Plugin {
  private final static String VERIFY_TOKEN_URL = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=";
  private final static String FIELD_TOKEN_EXPIRES_IN = "expires_in";
  private final static String FIELD_ACCESS_TOKEN = "accessToken";
  private final static String FIELD_TOKEN_EXPIRES = "expires";

  // see https://developers.google.com/android/reference/com/google/android/gms/auth/api/signin/GoogleSignInStatusCodes#SIGN_IN_CANCELLED
  private final static int SIGN_IN_CANCELLED = 12501;
  private final static int API_NOT_CONNECTED = 17;
  private final static int CANCELED = 16;
  private final static int CONNECTION_SUSPENDED_DURING_CALL = 20;
  private final static int DEVELOPER_ERROR = 10;
  private final static int ERROR = 13;
  private final static int INTERNAL_ERROR = 8;
  private final static int INVALID_ACCOUNT = 5;
  private final static int INTERRUPTED = 14;
  private final static int NETWORK_ERROR = 7;
  private final static int SERVICE_VERSION_UPDATE_REQUIRED = 2;

  public static final int KAssumeStaleTokenSec = 60;

  private GoogleSignInClient googleSignInClient;

  @Override
  public void load() {
    String clientId = getConfig().getString("androidClientId",
      getConfig().getString("clientId",
        this.getContext().getString(R.string.server_client_id)));

    boolean forceCodeForRefreshToken = getConfig().getBoolean("forceCodeForRefreshToken", false);

    GoogleSignInOptions.Builder googleSignInBuilder = new GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestIdToken(clientId)
            .requestEmail();

    if (forceCodeForRefreshToken) {
      googleSignInBuilder.requestServerAuthCode(clientId, true);
    }

    String[] scopeArray = getConfig().getArray("scopes", new String[] {});
    Scope[] scopes = new Scope[scopeArray.length - 1];
    Scope firstScope = new Scope(scopeArray[0]);
    for (int i = 1; i < scopeArray.length; i++) {
      scopes[i - 1] = new Scope(scopeArray[i]);
    }
    googleSignInBuilder.requestScopes(firstScope, scopes);

    GoogleSignInOptions googleSignInOptions = googleSignInBuilder.build();
    googleSignInClient = GoogleSignIn.getClient(this.getContext(), googleSignInOptions);
  }

  @PluginMethod()
  public void signIn(PluginCall call) {
    Intent signInIntent = googleSignInClient.getSignInIntent();
    startActivityForResult(call, signInIntent, "signInResult");
  }

  @ActivityCallback
  protected void signInResult(PluginCall call, ActivityResult result) {
    if (call == null) return;

    Task<GoogleSignInAccount> completedTask = GoogleSignIn.getSignedInAccountFromIntent(result.getData());

    try {
      GoogleSignInAccount account = completedTask.getResult(ApiException.class);

      // The accessToken is retrieved by executing a network request against the Google API, so it needs to run in a thread
      ExecutorService executor = Executors.newSingleThreadExecutor();
      executor.execute(() -> {
        try {
          JSONObject accessTokenObject = getAuthToken(account.getAccount(), true);

          JSObject authentication = new JSObject();
          authentication.put("idToken", account.getIdToken());
          authentication.put(FIELD_ACCESS_TOKEN, accessTokenObject.get(FIELD_ACCESS_TOKEN));
          authentication.put(FIELD_TOKEN_EXPIRES, accessTokenObject.get(FIELD_TOKEN_EXPIRES));
          authentication.put(FIELD_TOKEN_EXPIRES_IN, accessTokenObject.get(FIELD_TOKEN_EXPIRES_IN));

          JSObject user = new JSObject();
          user.put("serverAuthCode", account.getServerAuthCode());
          user.put("idToken", account.getIdToken());
          user.put("authentication", authentication);

          user.put("displayName", account.getDisplayName());
          user.put("email", account.getEmail());
          user.put("familyName", account.getFamilyName());
          user.put("givenName", account.getGivenName());
          user.put("id", account.getId());
          user.put("imageUrl", account.getPhotoUrl());

          call.resolve(user);
        } catch (Exception e) {
          e.printStackTrace();
          call.reject("Something went wrong while retrieving access token", e);
        }
      });
    } catch (ApiException e) {
      if (SIGN_IN_CANCELLED == e.getStatusCode()) {
        call.reject("The user canceled the sign-in flow.", "" + e.getStatusCode());
      } else {
        call.reject("Error code: " + e.getStatusCode(), "" + e.getStatusCode());
      }
    }
  }

  @PluginMethod()
  public void refresh(final PluginCall call) {
    Task<GoogleSignInAccount> task = googleSignInClient.silentSignIn();
    task.addOnCompleteListener(task1 -> {
      try {
        extractUserFromAccount(task1.getResult(ApiException.class), call);
      } catch (ApiException e) {
        // You can get from apiException.getStatusCode() the detailed error code
        // e.g. GoogleSignInStatusCodes.SIGN_IN_REQUIRED means user needs to take
        // explicit action to finish sign-in;
        // Please refer to GoogleSignInStatusCodes Javadoc for details
        e.printStackTrace();
        call.reject("Something went wrong with silent sign in", e);
      }
    });
  }

  @PluginMethod()
  public void signOut(final PluginCall call) {
    googleSignInClient.signOut()
      .addOnSuccessListener(getActivity(), new OnSuccessListener<Void>() {
        @Override
          public void onSuccess(Void aVoid) {
            call.resolve();
          }
      })
      .addOnFailureListener(getActivity(), new OnFailureListener() {
        @Override
          public void onFailure(Exception e) {
            call.reject("Sign out failed", e);
          }
      });
  }

  @PluginMethod()
  public void initialize(final PluginCall call) {
    call.resolve();
  }

  // Logic to retrieve accessToken, see https://github.com/EddyVerbruggen/cordova-plugin-googleplus/blob/master/src/android/GooglePlus.java
  private JSONObject getAuthToken(Account account, boolean retry) throws Exception {
    AccountManager manager = AccountManager.get(getContext());
    AccountManagerFuture<Bundle> future = manager.getAuthToken(account, "oauth2:profile email", null, false, null, null);
    Bundle bundle = future.getResult();
    String authToken = bundle.getString(AccountManager.KEY_AUTHTOKEN);
    try {
      return verifyToken(authToken);
    } catch (IOException e) {
      if (retry) {
        manager.invalidateAuthToken("com.google", authToken);
        return getAuthToken(account, false);
      } else {
        throw e;
      }
    }
  }

  private JSONObject verifyToken(String authToken) throws IOException, JSONException {
    URL url = new URL(VERIFY_TOKEN_URL + authToken);
    HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
    urlConnection.setInstanceFollowRedirects(true);
    String stringResponse = fromStream(new BufferedInputStream(urlConnection.getInputStream()));
    /* expecting:
    {
      "issued_to": "xxxxxx-xxxxxxxxxxxxxxx.apps.googleusercontent.com",
      "audience": "xxxxxx-xxxxxxxxxxxxxxxx.apps.googleusercontent.com",
      "user_id": "xxxxxxxxxxxxxxxxxxxx",
      "scope": "https://www.googleapis.com/auth/userinfo.email openid https://www.googleapis.com/auth/userinfo.profile",
      "expires_in": 3220,
      "email": "xxxxxxx@xxxxx.com",
      "verified_email": true,
      "access_type": "online"
     }
    */

    Log.d("AuthenticatedBackend", "token: " + authToken + ", verification: " + stringResponse);
    JSONObject jsonResponse = new JSONObject(stringResponse);
    int expires_in = jsonResponse.getInt(FIELD_TOKEN_EXPIRES_IN);
    if (expires_in < KAssumeStaleTokenSec) {
      throw new IOException("Auth token soon expiring.");
    }
    jsonResponse.put(FIELD_ACCESS_TOKEN, authToken);
    jsonResponse.put(FIELD_TOKEN_EXPIRES, expires_in + (System.currentTimeMillis() / 1000));
    return jsonResponse;
  }

  private static String fromStream(InputStream is) throws IOException {
    BufferedReader reader = new BufferedReader(new InputStreamReader(is));
    StringBuilder sb = new StringBuilder();
    String line;
    while ((line = reader.readLine()) != null) {
      sb.append(line).append("\n");
    }
    reader.close();
    return sb.toString();
  }

  private void extractUserFromAccount(GoogleSignInAccount account, final PluginCall call) {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    JSObject user = new JSObject();
    executor.execute(() -> {
      try {
        JSONObject accessTokenObject = getAuthToken(account.getAccount(), true);

        JSObject authentication = new JSObject();
        authentication.put("token", account.getIdToken());
        authentication.put(FIELD_ACCESS_TOKEN, accessTokenObject.get(FIELD_ACCESS_TOKEN));
        authentication.put("expires_at", accessTokenObject.get(FIELD_TOKEN_EXPIRES));
        authentication.put(FIELD_TOKEN_EXPIRES_IN, accessTokenObject.get(FIELD_TOKEN_EXPIRES_IN));
        authentication.put("idToken", account.getIdToken());

        call.resolve(authentication);
      } catch (Exception e) {
        e.printStackTrace();
        call.reject("Unable to fetch access token ");
      }
    });
  }
}
