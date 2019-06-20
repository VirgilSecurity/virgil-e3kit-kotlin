package com.android.virgilsecurity.ethreenexmodemo.data.remote.auth

import com.android.virgilsecurity.ethreenexmodemo.data.model.auth.AuthenticateResponse
import com.android.virgilsecurity.ethreenexmodemo.data.model.auth.NexmoJwtResponse
import com.android.virgilsecurity.ethreenexmodemo.data.model.auth.VirgilJwtResponse
import com.github.kittinunf.fuel.httpGet
import com.github.kittinunf.fuel.httpPost
import com.github.kittinunf.result.Result
import com.google.gson.Gson
import io.reactivex.Single
import org.json.JSONObject

/**
 * AuthRx
 */
object AuthRx {

    fun authenticate(identity: String) = Single.create<String> { emitter ->
        val jsonBody = JSONObject()
        jsonBody.put(KEY_IDENTITY, identity)

        (BASE_URL + AUTH + AUTHENTICATE).httpPost()
            .body(jsonBody.toString())
            .header("Content-Type", "application/json")
            .responseString { _, _, result ->
                when (result) {
                    is Result.Success -> {
                        with(result.get().let { Gson().fromJson(it, AuthenticateResponse::class.java) }) {
                            emitter.onSuccess(authToken)
                        }
                    }
                    is Result.Failure -> {
                        emitter.onError(result.getException())
                    }
                }
            }
    }

    /**
     * You can call it only after successful [authenticate]
     */
    fun virgilJwt(authToken: String) = Single.create<String> { emitter ->
        (BASE_URL + AUTH + VIRGIL_JWT).httpGet()
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer $authToken")
            .responseString { _, _, result ->
                when (result) {
                    is Result.Success -> {
                        with(result.get().let { Gson().fromJson(it, VirgilJwtResponse::class.java) }) {
                            emitter.onSuccess(virgilToken)
                        }
                    }
                    is Result.Failure -> {
                        emitter.onError(result.getException())
                    }
                }
            }
    }

    /**
     * You can call it only after successful [authenticate]
     */
    fun nexmoJwt(authToken: String) = Single.create<String> { emitter ->
        (BASE_URL + AUTH + NEXMO_JWT).httpGet()
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer $authToken")
            .responseString { _, _, result ->
                when (result) {
                    is Result.Success -> {
                        with(result.get().let { Gson().fromJson(it, NexmoJwtResponse::class.java) }) {
                            emitter.onSuccess(nexmoToken)
                        }
                    }
                    is Result.Failure -> {
                        emitter.onError(result.getException())
                    }
                }
            }
    }

    private const val BASE_URL = "http://10.0.2.2:3000"
    private const val AUTH = "/auth"
    private const val AUTHENTICATE = "/authenticate"
    private const val VIRGIL_JWT = "/virgil-jwt"
    private const val NEXMO_JWT = "/nexmo-jwt"

    private const val KEY_IDENTITY = "identity"
}