/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.android.virgilsecurity.ethreesamplejavafirebase;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.auth.AuthResult;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.auth.GetTokenResult;
import com.virgilsecurity.android.common.model.EThreeParams;
import com.virgilsecurity.android.ethree.interaction.EThree;
import com.virgilsecurity.common.callback.OnResultListener;
import com.virgilsecurity.common.model.Data;
import com.virgilsecurity.sdk.cards.Card;

import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import kotlin.jvm.functions.Function0;

public class EThreeActivity extends AppCompatActivity {

    private static final String TAG = "EThreeActivity";

    private FirebaseAuth firebaseAuth;
    private TextView tvText;

    private String encryptedText;

    // This demo is intended to work with firebase function from this tutorial: https://github.com/VirgilSecurity/virgil-e3kit-firebase-func
    // Don't forget to setup firebase first.
    // Placing this method above fields to easily find an entry point.
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_ethree);

        tvText = findViewById(R.id.tvText);
        firebaseAuth = FirebaseAuth.getInstance();

        new Thread(new Runnable() {
            @Override
            public void run() {
                // Creating Alice user so the Bob user will be able to encrypt data for her.
                initAlice();
            }
        }).start();
    }

    private static final String EMAIL_POSTFIX = "@somemail.com"; // because we using firebase sign up via email

    private static final String identityAlice = UUID.randomUUID().toString() + EMAIL_POSTFIX;
    private static final String passwordAlice = UUID.randomUUID().toString();
    private EThree eThreeAlice;
    private String authTokenAlice;
    // It e3kit firebase function we using User UID as identity to generate Virgil Jwt instead of email for security reasons
    private String uidAlice;

    private static final String identityBob = UUID.randomUUID().toString() + EMAIL_POSTFIX;
    private static final String passwordBob = UUID.randomUUID().toString();
    private EThree eThreeBob;
    private String authTokenBob;
    // It e3kit firebase function we using User UID as identity to generate Virgil Jwt instead of email for security reasons
    private String uidBob;

    // This callback exchanges authToken for a Virgil JWT. So Alice now authenticated and is able to
    // interact with Virgil Services (through the E3Kit).
    private final Function0<String> getAuthTokenAlice = new Function0<String>() {
        @Override
        public String invoke() {
            return getVirgilJwt(authTokenAlice);
        }
    };

    // This callback will be called when Alice is successfully registered (Her public key is published to Virgil
    // Cards Service).
    private final com.virgilsecurity.common.callback.OnCompleteListener onRegisterAliceListener =
            new com.virgilsecurity.common.callback.OnCompleteListener() {
                @Override
                public void onSuccess() {
                    Log.i(TAG, "Alice registered");
                    // Alice is registered successfully. Starting work with main user - Bob (He will encrypt data
                    // for Alice).
                    firebaseAuth.signOut(); // Simulating second session
                    initBob();
                }

                @Override
                public void onError(final Throwable throwable) {
                    Log.e(TAG, "Alice registration failed", throwable);

                    // Error handling
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            Toast.makeText(EThreeActivity.this, throwable.getMessage(), Toast.LENGTH_SHORT).show();
                        }
                    });
                }
            };

    private final Function0<String> getAuthTokenBob = new Function0<String>() {
        @Override
        public String invoke() {
            return getVirgilJwt(authTokenBob);
        }
    };

    private final OnResultListener<Card> onLookupBobListener =
            new OnResultListener<Card>() {
                @Override
                public void onSuccess(Card result) {
                    // Now you have public key of Alice, so it's possible to encrypt data for her.
                    String text = "Hello " + identityAlice;
                    byte[] data = "Some Data, possibly photo".getBytes();

                    // encrypt method encrypts provided text and converts it to Base64 String format.
                    encryptedText = eThreeBob.authEncrypt(text, result);

                    // encrypts provided text and returns encrypted byte array.
                    Data encryptedData = eThreeBob.authEncrypt(new Data(data), result);

                    Log.d("EThreeTag", "encryptedText: \n" + encryptedText);
                    // You can convert byte[] to Base64 String to easily transfer it to the server, or to print, etc.
                    Log.d("EThreeTag", "encryptedData: \n" + encryptedData.toBase64String());

                    // Next you can lookup Bob's public key via findUser by the Alice and decrypt
                    // encrypted for her data. (You have to lookup public key for decrypt to verify that the data
                    // was really encrypted by Bob).

                    // Switch to Alice again
                    firebaseAuth.signOut();
                    getBackAlice();
                }

                @Override
                public void onError(final Throwable throwable) {
                    // Error handling
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            Toast.makeText(EThreeActivity.this, throwable.getMessage(), Toast.LENGTH_SHORT).show();
                        }
                    });
                }
            };

    private final com.virgilsecurity.common.callback.OnCompleteListener onRegisterBobListener =
            new com.virgilsecurity.common.callback.OnCompleteListener() {
                @Override
                public void onSuccess() {
                    Log.i(TAG, "Bob registration complete");
                    // Searching for the public key of Alice to be able to encrypt.
                    eThreeBob.findUser(uidAlice).addCallback(onLookupBobListener);
                }

                @Override
                public void onError(final Throwable throwable) {
                    Log.e(TAG, "Bob registration failed", throwable);
                    // Error handling
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            Toast.makeText(EThreeActivity.this, throwable.getMessage(), Toast.LENGTH_SHORT).show();
                        }
                    });
                }
            };

    /**
     * In real life you won't call initialize twice in your app because only one user is authenticated ot once.
     * But for the example purposes we have to have two users to show encrypt/decrypt flow. So you probably will have
     * twice less code.
     */
    public void initAlice() {
        // You start your user authentication/authorization (signUp/signIn) here.
        authenticate(identityAlice, passwordAlice, new OnResultListener<String>() {
            @Override
            public void onSuccess(String value) {
                authTokenAlice = value;

                // After you successfully authenticated your user - you have to initialize EThree SDK.
                // To do this you have to provide context and two listeners.
                // OnGetTokenCallback should exchange recently received authToken for a Virgil JWT.
                // OnResultListener<EThree> will give you initialized instance of EThree SDK in onSuccess method.
                EThreeParams params = new EThreeParams(uidAlice, getAuthTokenAlice, EThreeActivity.this);
                eThreeAlice = new EThree(params);
                eThreeAlice.register().addCallback(onRegisterAliceListener);
            }

            @Override
            public void onError(final Throwable throwable) {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        Toast.makeText(EThreeActivity.this, throwable.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                });
            }
        });
    }

    public void getBackAlice() {
        firebaseAuth.signInWithEmailAndPassword(identityAlice, passwordAlice).addOnCompleteListener(new OnCompleteListener<AuthResult>() {
            @Override
            public void onComplete(@NonNull Task<AuthResult> task) {
                if (task.isSuccessful()) {
                    Log.d(TAG, "Alice logged in back");
                    firebaseAuth.getCurrentUser().getIdToken(true).addOnCompleteListener(new OnCompleteListener<GetTokenResult>() {
                        @Override
                        public void onComplete(@NonNull Task<GetTokenResult> task) {
                            authTokenAlice = task.getResult().getToken();

                            /* Alice needs sender's Card to decrypt and verify the message */
                            eThreeAlice.findUser(uidBob).addCallback(new OnResultListener<Card>() {
                                @Override
                                public void onSuccess(Card card) {
                                    /* Now Alice is able to decrypt the message*/
                                    final String decryptedText = eThreeAlice.authDecrypt(encryptedText, card);
                                    Log.d("EThreeTag", "decryptedText: \n" + decryptedText);

                                    runOnUiThread(new Runnable() {
                                        @Override
                                        public void run() {
                                            tvText.setText("Success. Sample finished it's work.\n\n" + encryptedText + "\n\n" + decryptedText);
                                        }
                                    });
                                }

                                @Override
                                public void onError(@NotNull Throwable throwable) {
                                    Log.e(TAG, "Bob's Card not found", throwable);
                                }
                            });

                        }
                    });
                } else {
                    // Error handling
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            Toast.makeText(EThreeActivity.this, "Alice sign in failed", Toast.LENGTH_SHORT).show();
                        }
                    });
                }
            }
        });
    }

    /**
     * If you use some normal architecture like MVP, MVC, MVVM - you can get rid of the Callback hell. As well
     * you can wrap all callbacks to RxJava and make it really concise. But you can use just callbacks. It's up to you.
     */
    public void initBob() {
        // You start your user authentication/authorization (signUp/signIn) here.
        authenticate(identityBob, passwordBob, new OnResultListener<String>() {
            @Override
            public void onSuccess(String value) {
                authTokenBob = value;

                EThreeParams params = new EThreeParams(uidBob, getAuthTokenBob, EThreeActivity.this);
                eThreeBob = new EThree(params);
                eThreeBob.register().addCallback(onRegisterBobListener);
            }

            @Override
            public void onError(final Throwable throwable) {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        Toast.makeText(EThreeActivity.this, throwable.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                });
            }
        });
    }

    /**
     * It this example only sign up is used. You can use sign in in the same way (depending on what button is clicked
     * or some other action).
     *
     * @param identity         is identity of user for authentication
     * @param onResultListener is a callback where you you will receive authentication token that you can later exchange
     *                         for a Virgil JWT. Or error if something went wrong.
     */
    private void authenticate(final String identity,
                              String password,
                              final OnResultListener<String> onResultListener) {
        firebaseAuth.createUserWithEmailAndPassword(identity,
                password)
                .addOnCompleteListener(new OnCompleteListener<AuthResult>() {
                    @Override
                    public void onComplete(@NonNull Task<AuthResult> task) {
                        if (task.isSuccessful()) {
                            Log.i(TAG, "Firebase authentication complete");
                            FirebaseUser user = firebaseAuth.getCurrentUser();

                            if (identity.equals(identityAlice)) // Workaround because we have two users in one app
                                uidAlice = user.getUid();// You won't (shouldn't) have this.
                            else
                                uidBob = user.getUid();

                            user.getIdToken(true).addOnCompleteListener(new OnCompleteListener<GetTokenResult>() {
                                @Override
                                public void onComplete(@NonNull Task<GetTokenResult> task) {
                                    if (task.isSuccessful()) {
                                        Log.i(TAG, "ID Token received", task.getException());
                                        onResultListener.onSuccess(task.getResult().getToken());
                                    } else {
                                        Log.e(TAG, "ID Token not received", task.getException());
                                        onResultListener.onError(task.getException());
                                    }
                                }
                            });
                        } else {
                            Log.e(TAG, "Firebase authentication failed", task.getException());
                            onResultListener.onError(task.getException());
                        }
                    }
                });
    }

    /**
     * This method exchanges provided authToken for a Virgil JWT.
     *
     * @param authToken from your authentication system that signals that user is authenticated successfully.
     * @return Virgil JWT base64 string representation.
     */
    private String getVirgilJwt(String authToken) {
        try {
            String url = "<your-firebase-function-url>/getVirgilJwt";
            URL object = new URL(url);

            HttpURLConnection con = (HttpURLConnection) object.openConnection();
            con.setRequestProperty("Authorization", "Bearer " + authToken);
            con.setRequestProperty("Content-Type", "application/json");
            con.setRequestMethod("POST");
            try (OutputStream os = con.getOutputStream()) {
                os.write("{\"data\":{}}".getBytes(StandardCharsets.UTF_8));
            }

            StringBuilder sb = new StringBuilder();
            int HttpResult = con.getResponseCode();
            if (HttpResult == HttpURLConnection.HTTP_OK) {
                BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8));
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                br.close();
                JSONObject jsonObject = new JSONObject(sb.toString());

                return jsonObject.getJSONObject("result").getString("token");
            } else {
                Log.e(TAG, "Can't get Virgil token: " + con.getResponseMessage());
                throw new RuntimeException("Some connection error");
            }
        } catch (IOException exception) {
            Log.e(TAG, "Can't get Virgil token", exception);
            throw new RuntimeException("Some connection error");
        } catch (JSONException e) {
            throw new RuntimeException("Parsing virgil jwt json error");
        }
    }
}
