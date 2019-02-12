package com.android.virgilsecurity.ethreesamplekotlincoroutines

import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import com.virgilsecurity.android.ethreecoroutines.interaction.EThree
import com.virgilsecurity.sdk.utils.ConvertionUtils
import kotlinx.android.synthetic.main.activity_ethree.*
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.*

class EThreeActivity : AppCompatActivity() {

    private lateinit var eThreeUserOne: EThree
    private lateinit var eThreeUserTwo: EThree

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_ethree)

        runBlocking {
            // Creating first user so the second user will be able to encrypt data for her.
            initUserOne()
        }
    }

    /**
     * In real life you won't call initialize twice in your app because only one user is authenticated ot once.
     * But for the example purposes we have to have two users to show encrypt/decrypt flow. So you probably will have
     * twice less code.
     */
    private suspend fun initUserOne() {
        // You start your user authentication/authorization (signUp/signIn) here.
        authenticateAsync(identityOne).await().run {
            val authTokenUserOne = JSONObject(this).get("authToken") as String

            // After you successfully authenticated your user - you have to initialize EThree SDK.
            // To do this you have to provide context and function that returns Virgil Jwt after that await for the
            // completion of async initialize.
            eThreeUserOne = EThree.initialize(this@EThreeActivity) {
                runBlocking {
                    // getVirgilJwtAsync function will exchange authToken for a Virgil JWT. So user authenticated and
                    // is able to interact with Virgil Services (through the E3Kit).
                    getVirgilJwtAsync(authTokenUserOne).await()
                }
            }.await()

            // First user's EThree is initialized. Let's register her so the second user will be able to encrypt
            // something for her.
            eThreeUserOne.register().await()

            // If there're no errors - user successfully registered (Her public key is published to Virgil
            // Cards Service). You can handle errors with standard try catch block.

            // First user is registered successfully. Starting work with main user - second (She will encrypt data
            // for the first user).
            initUserTwo()
        }
    }

    /**
     * Initializing our main user that will encrypt data for the first one.
     */
    private suspend fun initUserTwo() {
        authenticateAsync(identityTwo).await().run {
            val authTokenUserTwo = JSONObject(this).get("authToken") as String

            eThreeUserTwo = EThree.initialize(this@EThreeActivity) {
                runBlocking {
                    getVirgilJwtAsync(authTokenUserTwo).await()
                }
            }.await()
            // So now you have fully initialized and ready to use EThree instance for the second user.

            // Register seconds user (Her public key will be published on Virgil Cards service).
            eThreeUserTwo.register().await()

            // If there're no errors - user successfully registered (Her public key is published to Virgil
            // Cards Service).

            // Searching for the public key of the first user to be able to encrypt.
            val keysResult = eThreeUserTwo.lookupPublicKeys(listOf(identityOne)).await()

            // Now you have public key of first user, so it's possible to encrypt data for her.
            val text = "Hello \$username"
            val data = "Some Data, possibly photo".toByteArray()

            // encrypt method encrypts provided text and converts it to Base64 String format.
            val encryptedText = eThreeUserTwo.encrypt(text, keysResult.values.toList())

            runOnUiThread { tvText.text = "Success. Sample finished it's work.\n" +
                                          "\n" + encryptedText }

            // encrypts provided text and returns encrypted byte array.
            val encryptedData = eThreeUserTwo.encrypt(data, keysResult.values.toList())

            Log.d("EThreeTag", "encryptedText: \n$encryptedText")
            // You can convert byte[] to Base64 String to easily transfer it to the server, or to print, etc.
            Log.d("EThreeTag", "encryptedData: \n" + ConvertionUtils.toBase64String(encryptedData))

            // Next you can lookup second user's public key via lookupPublicKeys by the first user and decrypt
            // encrypted for her data. (You have to lookup public key for decrypt to verify that the data
            // was really encrypted by second user).
            // It is not implemented in this example because it will become overcomplicated because of
            // two users in something like "one" session. In real-life app you will have only half of these
            // functions - for one current user.
        }
    }

    /**
     * !!! Current implementation of *authentication* is NOT SECURE and is just to show you that before accessing your
     * service that generates Virgil JWTs you have to authenticate your user.
     *
     * In this function you have to use your authentication - Firebase, Google, Facebook, or any other auth (as well
     * as some kind of your custom authentication service).
     *
     * Provided [identity] is used for user authentication. You will receive authentication token that you can later
     * exchange for a Virgil JWT. Or error if something went wrong.
     */
    private fun authenticateAsync(
        identity: String
    ): Deferred<String> = GlobalScope.async {
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
            response
        } else {
            throw Throwable("Some connection error")
        }
    }

    /**
     * This method exchanges provided authToken for a Virgil JWT.
     *
     * Passed [authToken] from your authentication system signals that user is authenticated successfully.
     *
     * You will get Virgil JWT base64 string representation.
     */
    private fun getVirgilJwtAsync(authToken: String?): Deferred<String> = GlobalScope.async {
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

            jsonObject.getString("virgilToken")
        } else {
            throw RuntimeException("Some connection error")
        }
    }

    companion object {

        private val identityOne = UUID.randomUUID().toString()
        private val identityTwo = UUID.randomUUID().toString()
    }
}