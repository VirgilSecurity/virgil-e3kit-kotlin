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

package com.android.virgilsecurity.ethreesamplejava;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import com.virgilsecurity.android.ethree.kotlin.callback.OnCompleteListener;
import com.virgilsecurity.android.ethree.kotlin.callback.OnGetTokenCallback;
import com.virgilsecurity.android.ethree.kotlin.callback.OnResultListener;
import com.virgilsecurity.android.ethree.interaction.EThree;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.UUID;

public class EThreeActivity extends AppCompatActivity {

    private TextView tvText;

    // Placing this method above fields to easily find an entry point.
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_ethree);

        tvText = findViewById(R.id.tvTextView);

        new Thread(new Runnable() {
            @Override public void run() {
                // Creating first user so the second user will be able to encrypt data for her.
                initUserOne();
            }
        }).start();
    }

    private static final String identityOne = UUID.randomUUID().toString();
    private EThree eThreeUserOne;
    private String authTokenUserOne;

    private static final String identityTwo = UUID.randomUUID().toString();
    private EThree eThreeUserTwo;
    private String authTokenUserTwo;


    // This callback exchanges authToken for a Virgil JWT. So user now authenticated and is able to
    // interact with Virgil Services (through the E3Kit).
    private final OnGetTokenCallback onGetTokenUserOneCallback = new OnGetTokenCallback() {
        @Override public String onGetToken() {
            return getVirgilJwt(authTokenUserOne);
        }
    };

    // This callback will be called when first user is successfully registered (Her public key is published to Virgil
    // Cards Service).
    private final OnCompleteListener onRegisterUserOneListener = new OnCompleteListener() {
        @Override public void onSuccess() {
            // First user is registered successfully. Starting work with main user - second (She will encrypt data
            // for the first user).
            initUserTwo();
        }

        @Override public void onError(final Throwable throwable) {
            // Error handling
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    Toast.makeText(EThreeActivity.this, throwable.getMessage(), Toast.LENGTH_SHORT).show();
                }
            });
        }
    };

    private final OnResultListener<EThree> onInitUserOneListener = new OnResultListener<EThree>() {
        @Override public void onSuccess(EThree result) {
            // So now you have fully initialized and ready to use EThree instance!
            eThreeUserOne = result;

            // First user's EThree is initialized. Let's register her so the second user will be able to encrypt
            // something for her.
            eThreeUserOne.register().addCallback(onRegisterUserOneListener);
        }

        @Override public void onError(final Throwable throwable) {
            // Error handling
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    Toast.makeText(EThreeActivity.this, throwable.getMessage(), Toast.LENGTH_SHORT).show();
                }
            });
        }
    };

    private final OnGetTokenCallback onGetTokenUserTwoCallback = new OnGetTokenCallback() {
        @Override public String onGetToken() {
            return getVirgilJwt(authTokenUserTwo);
        }
    };

    private final OnResultListener<Map<String, VirgilPublicKey>> onLookupUserTwoListener =
            new OnResultListener<Map<String, VirgilPublicKey>>() {
                @Override public void onSuccess(Map<String, VirgilPublicKey> result) {
                    // Now you have public key of first user, so it's possible to encrypt data for her.
                    String text = "Hello $username";
                    byte[] data = "Some Data, possibly photo".getBytes();

                    // encrypt method encrypts provided text and converts it to Base64 String format.
                    final String encryptedText = eThreeUserTwo.encrypt(text, result);

                    EThreeActivity.this.runOnUiThread(new Runnable() {
                        @Override public void run() {
                            tvText.setText("Success. Sample finished it's work.\n\n" + encryptedText);
                        }
                    });

                    // encrypts provided text and returns encrypted byte array.
                    byte[] encryptedData = eThreeUserTwo.encrypt(data, result);

                    Log.d("EThreeTag", "encryptedText: \n" + encryptedText);
                    // You can convert byte[] to Base64 String to easily transfer it to the server, or to print, etc.
                    Log.d("EThreeTag", "encryptedData: \n" + ConvertionUtils.toBase64String(encryptedData));

                    // Next you can lookup second user's public key via lookupPublicKeys by the first user and decrypt
                    // encrypted for her data. (You have to lookup public key for decrypt to verify that the data
                    // was really encrypted by second user).
                    // It is not implemented in this example because it will become overcomplicated because of
                    // two users in something like "one" session. In real-life app you will have only half of these
                    // callbacks - for one current user.
                }

                @Override public void onError(final Throwable throwable) {
                    // Error handling
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            Toast.makeText(EThreeActivity.this, throwable.getMessage(), Toast.LENGTH_SHORT).show();
                        }
                    });
                }
            };

    private final OnCompleteListener onRegisterUserTwoListener = new OnCompleteListener() {
        @Override public void onSuccess() {
            // Searching for the public key of first user to be able to encrypt.
            eThreeUserTwo.lookupPublicKeys(identityOne).addCallback(onLookupUserTwoListener);
        }

        @Override public void onError(final Throwable throwable) {
            // Error handling
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    Toast.makeText(EThreeActivity.this, throwable.getMessage(), Toast.LENGTH_SHORT).show();
                }
            });
        }
    };

    private final OnResultListener<EThree> onInitUserTwoListener = new OnResultListener<EThree>() {
        @Override public void onSuccess(EThree result) {
            // So now you have fully initialized and ready to use EThree instance for second user.
            eThreeUserTwo = result;

            eThreeUserTwo.register().addCallback(onRegisterUserTwoListener);
        }

        @Override public void onError(final Throwable throwable) {
            // Error handling
            runOnUiThread(new Runnable() {
                @Override public void run() {
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
    public void initUserOne() {
        // You start your user authentication/authorization (signUp/signIn) here.
        authenticate(identityOne, new OnResultListener<String>() {
            @Override public void onSuccess(String value) {
                try {
                    JSONObject object = new JSONObject(value);
                    authTokenUserOne = (String) object.get("authToken");
                } catch (final JSONException e) {
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            Toast.makeText(EThreeActivity.this, e.getMessage(), Toast.LENGTH_SHORT).show();
                        }
                    });
                }

                // After you successfully authenticated your user - you have to initialize EThree SDK.
                // To do this you have to provide context and two listeners.
                // OnGetTokenCallback should exchange recently received authToken for a Virgil JWT.
                // OnResultListener<EThree> will give you initialized instance of EThree SDK in onSuccess method.
                EThree.initialize(EThreeActivity.this,
                                  onGetTokenUserOneCallback).addCallback(onInitUserOneListener);
            }

            @Override public void onError(final Throwable throwable) {
                runOnUiThread(new Runnable() {
                    @Override public void run() {
                        Toast.makeText(EThreeActivity.this, throwable.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                });
            }
        });
    }


    /**
     * If you use some normal architecture like MVP, MVC, MVVM - you can get rid of the Callback hell. As well
     * you can wrap all callbacks to RxJava and make it really concise. But you can use just callbacks. It's up to you.
     */
    public void initUserTwo() {
        // You start your user authentication/authorization (signUp/signIn) here.
        authenticate(identityTwo, new OnResultListener<String>() {
            @Override public void onSuccess(String value) {
                try {
                    JSONObject object = new JSONObject(value);
                    authTokenUserTwo = (String) object.get("authToken");
                } catch (final JSONException e) {
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            Toast.makeText(EThreeActivity.this, e.getMessage(), Toast.LENGTH_SHORT).show();
                        }
                    });
                }

                EThree.initialize(EThreeActivity.this,
                                  onGetTokenUserTwoCallback).addCallback(onInitUserTwoListener);
            }

            @Override public void onError(final Throwable throwable) {
                runOnUiThread(new Runnable() {
                    @Override public void run() {
                        Toast.makeText(EThreeActivity.this, throwable.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                });
            }
        });
    }

    /**
     * !!! Current implementation of *authentication* is NOT SECURE and is just to show you that before accessing your
     * service that generates Virgil JWT's you have to authenticate your user.
     * <p>
     * In this method you have to use your authentication - Firebase, Google, Facebook, or any other auth (as well
     * as some kind of your custom authentication service).
     *
     * @param identity         is identityOne of user for authentication
     * @param onResultListener is a callback where you you will receive authentication token that you can later exchange
     *                         for a Virgil JWT. Or error if something went wrong.
     */
    private void authenticate(String identity,
                              OnResultListener<String> onResultListener) {
        try {
            String url = "http://10.0.2.2:3000/authenticate";
            URL object = new URL(url);

            HttpURLConnection con = (HttpURLConnection) object.openConnection();
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            con.setRequestProperty("Accept", "application/json");
            con.setRequestMethod("POST");

            JSONObject cred = new JSONObject();

            cred.put("identity", identity);

            OutputStream wr = con.getOutputStream();
            wr.write(cred.toString().getBytes("UTF-8"));
            wr.close();

            StringBuilder sb = new StringBuilder();
            int HttpResult = con.getResponseCode();
            if (HttpResult == HttpURLConnection.HTTP_OK) {
                BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(), "UTF-8"));
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                br.close();
                onResultListener.onSuccess(sb.toString());
            } else {
                onResultListener.onError(new Throwable("Some connection error"));
            }
        } catch (JSONException | IOException exception) {
            onResultListener.onError(exception);
        }
    }

    /**
     * This method exchanges provided authToken for a Virgil JWT.
     *
     * @param authToken from your authentication system that signals that user is authenticated successfully.
     *
     * @return Virgil JWT base64 string representation.
     */
    private String getVirgilJwt(String authToken) {
        try {
            String url = "http://10.0.2.2:3000/virgil-jwt";
            URL object = new URL(url);

            HttpURLConnection con = (HttpURLConnection) object.openConnection();
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setRequestProperty("Accept", "application/json");
            con.setRequestProperty("Authorization", "Bearer " + authToken);
            con.setRequestMethod("GET");

            StringBuilder sb = new StringBuilder();
            int HttpResult = con.getResponseCode();
            if (HttpResult == HttpURLConnection.HTTP_OK) {
                BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(), "UTF-8"));
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                br.close();
                JSONObject jsonObject = new JSONObject(sb.toString());

                return jsonObject.getString("virgilToken");
            } else {
                throw new RuntimeException("Some connection error");
            }
        } catch (IOException exception) {
            throw new RuntimeException("Some connection error");
        } catch (JSONException e) {
            throw new RuntimeException("Parsing virgil jwt json error");
        }
    }
}
