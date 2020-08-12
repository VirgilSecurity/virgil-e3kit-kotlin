package com.android.virgilsecurity.ethreesamplekotlin

import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.model.EThreeParams
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.common.callback.OnCompleteListener
import com.virgilsecurity.common.callback.OnResultListener
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.cards.Card
import kotlinx.android.synthetic.main.activity_ethree.*
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.*


class EThreeActivity : AppCompatActivity() {

    // Placing this method above fields to easily find an entry point.
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_ethree)

        Thread(Runnable {
            // Creating first user so the second user will be able to encrypt data for her.
            initUserOne()
        }).start()
    }

    private var eThreeUserOne: EThree? = null
    private var authTokenUserOne: String? = null
    private var eThreeUserTwo: EThree? = null
    private var authTokenUserTwo: String? = null

    // This callback exchanges authToken for a Virgil JWT. So user now authenticated and is able to
    // interact with Virgil Services (through the E3Kit).
    private val onGetTokenUserOneCallback = object : OnGetTokenCallback {
        override fun onGetToken(): String {
            return getVirgilJwt(authTokenUserOne)
        }
    }

    // This callback will be called when first user is successfully registered (Her public key is published to Virgil
    // Cards Service).
    private val onRegisterUserOneListener = object : OnCompleteListener {
        override fun onSuccess() {
            // First user is registered successfully. Starting work with main user - second (She will encrypt data
            // for the first user).
            initUserTwo()
        }

        override fun onError(throwable: Throwable) {
            // Error handling
            runOnUiThread { Toast.makeText(this@EThreeActivity, throwable.message, Toast.LENGTH_SHORT).show() }
        }
    }

    private val onInitUserOneListener = object : OnResultListener<EThree> {
        override fun onSuccess(result: EThree) {
            // So now you have fully initialized and ready to use EThree instance!
            eThreeUserOne = result

            // First user's EThree is initialized. Let's register her so the second user will be able to encrypt
            // something for her.
            eThreeUserOne!!.register().addCallback(onRegisterUserOneListener)
        }

        override fun onError(throwable: Throwable) {
            // Error handling
            runOnUiThread { Toast.makeText(this@EThreeActivity, throwable.message, Toast.LENGTH_SHORT).show() }
        }
    }

    private val onGetTokenUserTwoCallback = object : OnGetTokenCallback {
        override fun onGetToken(): String {
            return getVirgilJwt(authTokenUserTwo)
        }
    }

    private val onFindUserTwoListener = object :
            OnResultListener<Card> {
        override fun onSuccess(result: Card) {
            // Now you have public key of first user, so it's possible to encrypt data for her.
            val text = "Hello \$username"
            val data = "Some Data, possibly photo".toByteArray()

            // encrypt method encrypts provided text and converts it to Base64 String format.
            val encryptedText = eThreeUserTwo!!.authEncrypt(text, result)

            this@EThreeActivity.runOnUiThread {
                tvText.text = "Success. Sample finished it's work.\n" +
                              "\n" + encryptedText
            }

            // encrypts provided text and returns encrypted byte array.
            val encryptedData = eThreeUserTwo!!.authEncrypt(Data(data), result)

            Log.d("EThreeTag", "encryptedText: \n$encryptedText")
            // You can convert byte[] to Base64 String to easily transfer it to the server, or to print, etc.
            Log.d("EThreeTag", "encryptedData: \n" + encryptedData.toBase64String())

            // Next you can lookup second user's public key via lookupPublicKeys by the first user and decrypt
            // encrypted for her data. (You have to lookup public key for decrypt to verify that the data
            // was really encrypted by second user).
            // It is not implemented in this example because it will become overcomplicated because of
            // two users in something like "one" session. In real-life app you will have only half of these
            // callbacks - for one current user.
        }

        override fun onError(throwable: Throwable) {
            // Error handling
            runOnUiThread { Toast.makeText(this@EThreeActivity, throwable.message, Toast.LENGTH_SHORT).show() }
        }
    }

    private val onRegisterUserTwoListener = object : OnCompleteListener {
        override fun onSuccess() {
            // Searching for the card of first user to be able to encrypt.
            eThreeUserTwo!!.findUser(identityOne).addCallback(onFindUserTwoListener)
        }

        override fun onError(throwable: Throwable) {
            // Error handling
            runOnUiThread { Toast.makeText(this@EThreeActivity, throwable.message, Toast.LENGTH_SHORT).show() }
        }
    }

    private val onInitUserTwoListener = object : OnResultListener<EThree> {
        override fun onSuccess(result: EThree) {
            // So now you have fully initialized and ready to use EThree instance for second user.
            eThreeUserTwo = result

            eThreeUserTwo!!.register().addCallback(onRegisterUserTwoListener)
        }

        override fun onError(throwable: Throwable) {
            // Error handling
            runOnUiThread { Toast.makeText(this@EThreeActivity, throwable.message, Toast.LENGTH_SHORT).show() }
        }
    }

    /**
     * In real life you won't call initialize twice in your app because only one user is authenticated ot once.
     * But for the example purposes we have to have two users to show encrypt/decrypt flow. So you probably will have
     * twice less code.
     */
    private fun initUserOne() {
        // You start your user authentication/authorization (signUp/signIn) here.
        authenticate(identityOne, object : OnResultListener<String> {
            override fun onSuccess(result: String) {
                try {
                    val `object` = JSONObject(result)
                    authTokenUserOne = `object`.get("authToken") as String
                } catch (e: JSONException) {
                    runOnUiThread { Toast.makeText(this@EThreeActivity, e.message, Toast.LENGTH_SHORT).show() }
                }

                // After you successfully authenticated your user - you have to initialize EThree SDK.
                // To do this you have to provide identity name, a function and context.
                // The function should exchange recently received authToken for a Virgil JWT.
                // After you successfully authenticated your user - you have to initialize EThree SDK.
                // To do this you have to provide identity name, a function and context.
                // The function should exchange recently received authToken for a Virgil JWT.
                val params =
                    EThreeParams(identityOne, {getVirgilJwt(authTokenUserOne)}, this@EThreeActivity)
                eThreeUserOne = EThree(params)

                // Now you can register your identity
                try {
                    eThreeUserOne!!.register().addCallback(onRegisterUserOneListener)
                } catch (throwable: Throwable) {
                    Log.e(
                        TAG,
                        "User one registration failed",
                        throwable
                    )
                    runOnUiThread {
                        Toast.makeText(
                            this@EThreeActivity,
                            throwable.message,
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }

            override fun onError(throwable: Throwable) {
                runOnUiThread { Toast.makeText(this@EThreeActivity, throwable.message, Toast.LENGTH_SHORT).show() }
            }
        })
    }


    /**
     * If you use some normal architecture like MVP, MVC, MVVM - you can get rid of the Callback hell. As well
     * you can wrap all callbacks to RxJava and make it really concise. But you can use just callbacks. It's up to you.
     */
    fun initUserTwo() {
        // You start your user authentication/authorization (signUp/signIn) here.
        authenticate(identityTwo, object : OnResultListener<String> {
            override fun onSuccess(result: String) {
                try {
                    val `object` = JSONObject(result)
                    authTokenUserTwo = `object`.get("authToken") as String
                } catch (e: JSONException) {
                    runOnUiThread { Toast.makeText(this@EThreeActivity, e.message, Toast.LENGTH_SHORT).show() }
                }

                val params =
                    EThreeParams(identityTwo, {getVirgilJwt(authTokenUserTwo)}, this@EThreeActivity)
                eThreeUserTwo = EThree(params)

                try {
                    eThreeUserTwo!!.register().addCallback(onRegisterUserTwoListener)
                } catch (throwable: Throwable) {
                    Log.e(
                        TAG,
                        "User two registration failed",
                        throwable
                    )
                    runOnUiThread {
                        Toast.makeText(
                            this@EThreeActivity,
                            throwable.message,
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }

            override fun onError(throwable: Throwable) {
                runOnUiThread { Toast.makeText(this@EThreeActivity, throwable.message, Toast.LENGTH_SHORT).show() }
            }
        })
    }

    /**
     * !!! Current implementation of *authentication* is NOT SECURE and is just to show you that before accessing your
     * service that generates Virgil JWT's you have to authenticate your user.
     *
     *
     * In this method you have to use your authentication - Firebase, Google, Facebook, or any other auth (as well
     * as some kind of your custom authentication service).
     *
     * @param identity         is identityOne of user for authentication
     * @param onResultListener is a callback where you you will receive authentication token that you can later exchange
     * for a Virgil JWT. Or error if something went wrong.
     */
    private fun authenticate(
            identity: String,
            onResultListener: OnResultListener<String>
    ) {
        try {
            val baseUrl = "$SERVER_URL/authenticate"
            val fullUrl = URL(baseUrl)

            val urlConnection = fullUrl.openConnection() as HttpURLConnection
            urlConnection.doOutput = true
            urlConnection.doInput = true
            urlConnection.setRequestProperty("Content-Type", "application/json; charset=UTF-8")
            urlConnection.setRequestProperty("Accept", "application/json")
            urlConnection.requestMethod = "POST"

            val cred = JSONObject()

            cred.put("identity", identity)

            val wr = urlConnection.outputStream
            wr.write(cred.toString().toByteArray(charset("UTF-8")))
            wr.close()

            val httpResult = urlConnection.responseCode
            if (httpResult == HttpURLConnection.HTTP_OK) {
                val response = InputStreamReader(urlConnection.inputStream, "UTF-8").buffered().use {
                    it.readText()
                }
                onResultListener.onSuccess(response)
            } else {
                onResultListener.onError(Throwable("Some connection error"))
            }
        } catch (exception: JSONException) {
            onResultListener.onError(exception)
        } catch (exception: IOException) {
            onResultListener.onError(exception)
        }

    }

    /**
     * This method exchanges provided authToken for a Virgil JWT.
     *
     * @param authToken from your authentication system that signals that user is authenticated successfully.
     *
     * @return Virgil JWT base64 string representation.
     */
    private fun getVirgilJwt(authToken: String?): String {
        try {
            val baseUrl = "$SERVER_URL/virgil-jwt"
            val fullUrl = URL(baseUrl)

            val urlConnection = fullUrl.openConnection() as HttpURLConnection
            urlConnection.setRequestProperty("Accept", "application/json")
            urlConnection.setRequestProperty("Authorization", "Bearer " + authToken!!)
            urlConnection.requestMethod = "GET"

            val httpResult = urlConnection.responseCode
            if (httpResult == HttpURLConnection.HTTP_OK) {
                val response = InputStreamReader(urlConnection.inputStream, "UTF-8").buffered().use {
                    it.readText()
                }
                val jsonObject = JSONObject(response)

                return jsonObject.getString("virgilToken")
            } else {
                throw RuntimeException("Some connection error")
            }
        } catch (exception: IOException) {
            throw RuntimeException("Some connection error")
        } catch (e: JSONException) {
            throw RuntimeException("Parsing virgil jwt json error")
        }

    }

    companion object {
        private const val TAG = "EThreeActivity"
        private val identityOne = UUID.randomUUID().toString()
        private val identityTwo = UUID.randomUUID().toString()
        private val SERVER_URL = "http://10.0.2.2:3000"
    }
}
