package com.android.virgilsecurity.ethreesamplekotlin

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import android.widget.Toast
import com.virgilsecurity.android.ethree.kotlin.interaction.EThree
import com.virgilsecurity.sdk.utils.ConvertionUtils
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
    private val onGetTokenUserOneCallback = object : EThree.OnGetTokenCallback {
        override fun onGetToken(): String {
            return getVirgilJwt(authTokenUserOne)
        }
    }

    // This callback will be called when first user is successfully registered (Her public key is published to Virgil
    // Cards Service).
    private val onRegisterUserOneListener = object : EThree.OnCompleteListener {
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

    private val onInitUserOneListener = object : EThree.OnResultListener<EThree> {
        override fun onSuccess(result: EThree) {
            // So now you have fully initialized and ready to use EThree instance!
            eThreeUserOne = result

            // First user's EThree is initialized. Let's register her so the second user will be able to encrypt
            // something for her.
            eThreeUserOne!!.register(onRegisterUserOneListener)
        }

        override fun onError(throwable: Throwable) {
            // Error handling
            runOnUiThread { Toast.makeText(this@EThreeActivity, throwable.message, Toast.LENGTH_SHORT).show() }
        }
    }

    private val onGetTokenUserTwoCallback = object : EThree.OnGetTokenCallback {
        override fun onGetToken(): String {
            return getVirgilJwt(authTokenUserTwo)
        }
    }

    private val onLookupUserTwoListener = object :
        EThree.OnResultListener<Map<String, com.virgilsecurity.sdk.crypto.PublicKey>> {
        override fun onSuccess(result: Map<String, com.virgilsecurity.sdk.crypto.PublicKey>) {
            // Now you have public key of first user, so it's possible to encrypt data for her.
            val text = "Hello \$username"
            val data = "Some Data, possibly photo".toByteArray()

            // encrypt method encrypts provided text and converts it to Base64 String format.
            val encryptedText = eThreeUserTwo!!.encrypt(text, ArrayList(result.values))

            this@EThreeActivity.runOnUiThread { tvText.text = encryptedText }

            // encrypts provided text and returns encrypted byte array.
            val encryptedData = eThreeUserTwo!!.encrypt(data, ArrayList(result.values))

            println("encryptedText: \n$encryptedText")
            // You can convert byte[] to Base64 String to easily transfer it to the server, or to print, etc.
            println("encryptedData: \n" + ConvertionUtils.toBase64String(encryptedData))

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

    private val onRegisterUserTwoListener = object : EThree.OnCompleteListener {
        override fun onSuccess() {
            // Searching for the public key of first user to be able to encrypt.
            eThreeUserTwo!!.lookupPublicKeys(listOf(identityOne), onLookupUserTwoListener)
        }

        override fun onError(throwable: Throwable) {
            // Error handling
            runOnUiThread { Toast.makeText(this@EThreeActivity, throwable.message, Toast.LENGTH_SHORT).show() }
        }
    }

    private val onInitUserTwoListener = object : EThree.OnResultListener<EThree> {
        override fun onSuccess(result: EThree) {
            // So now you have fully initialized and ready to use EThree instance for second user.
            eThreeUserTwo = result

            eThreeUserTwo!!.register(onRegisterUserTwoListener)
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
            override fun onSuccess(value: String) {
                try {
                    val `object` = JSONObject(value)
                    authTokenUserOne = `object`.get("authToken") as String
                } catch (e: JSONException) {
                    e.printStackTrace()
                }

                // After you successfully authenticated your user - you have to initialize EThree SDK.
                // To do this you have to provide context and two listeners.
                // OnGetTokenCallback should exchange recently received authToken for a Virgil JWT.
                // OnResultListener<EThree> will give you initialized instance of EThree SDK in onSuccess method.
                EThree.initialize(
                    this@EThreeActivity,
                    onGetTokenUserOneCallback,
                    onInitUserOneListener
                )
            }

            override fun onError(throwable: Throwable) {
                throwable.printStackTrace()
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
            override fun onSuccess(value: String) {
                try {
                    val `object` = JSONObject(value)
                    authTokenUserTwo = `object`.get("authToken") as String
                } catch (e: JSONException) {
                    e.printStackTrace()
                }

                EThree.initialize(
                    this@EThreeActivity,
                    onGetTokenUserTwoCallback,
                    onInitUserTwoListener
                )
            }

            override fun onError(throwable: Throwable) {
                throwable.printStackTrace()
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
            val baseUrl = "http://10.0.2.2:3000/authenticate"
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
            exception.printStackTrace()
            onResultListener.onError(exception)
        } catch (exception: IOException) {
            exception.printStackTrace()
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
            val baseUrl = "http://10.0.2.2:3000/virgil-jwt"
            val fullUrl = URL(baseUrl)

            val urlConnection = fullUrl.openConnection() as HttpURLConnection
            urlConnection.doOutput = true
            urlConnection.doInput = true
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
            exception.printStackTrace()
            throw RuntimeException("Some connection error")
        } catch (e: JSONException) {
            throw RuntimeException("Parsing virgil jwt json error")
        }

    }

    private interface OnResultListener<T> {

        fun onSuccess(value: T)

        fun onError(throwable: Throwable)
    }

    companion object {

        private val identityOne = UUID.randomUUID().toString()

        private val identityTwo = UUID.randomUUID().toString()
    }
}
