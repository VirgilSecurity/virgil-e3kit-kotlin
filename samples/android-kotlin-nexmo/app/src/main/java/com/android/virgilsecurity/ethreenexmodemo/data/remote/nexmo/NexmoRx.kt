package com.android.virgilsecurity.ethreenexmodemo.data.remote.nexmo

import android.content.Context
import android.util.Log
import com.android.virgilsecurity.ethreenexmodemo.data.model.auth.CreateUserResponse
import com.github.kittinunf.fuel.httpPost
import com.github.kittinunf.result.Result
import com.google.gson.Gson
import com.nexmo.client.NexmoClient
import com.nexmo.client.NexmoConnectionState
import com.nexmo.client.NexmoUser
import com.nexmo.client.request_listener.NexmoApiError
import com.nexmo.client.request_listener.NexmoLoginListener
import com.nexmo.client.request_listener.NexmoRequestListener
import io.reactivex.Single
import org.json.JSONObject

/**
 * NexmoRx
 */
class NexmoRx(val context: Context) {

    fun initNexmo(nexmoToken: String) = Single.create<NexmoUser> { emitter ->
        NexmoClient.init(NexmoClient.NexmoClientConfig(), context, object : NexmoLoginListener {
            override fun onLoginStateChange(
                state: NexmoLoginListener.ELoginState?,
                reason: NexmoLoginListener.ELoginStateReason?
            ) {
                if (state == NexmoLoginListener.ELoginState.LOGGED_IN
                    && reason == NexmoLoginListener.ELoginStateReason.SUCCESS
                ) {
                    Log.d(TAG, "State is: Logged In")
                } else if (reason == NexmoLoginListener.ELoginStateReason.GENERAL_ERROR) {
                    emitter.onError(Throwable("Nexmo init error"))
                }
            }

            override fun onAvailabilityChange(
                availability: NexmoLoginListener.EAvailability?,
                connectionState: NexmoConnectionState?
            ) {
                // Set user's availability state here
            }

        })

        NexmoClient.get().login(nexmoToken, object : NexmoRequestListener<NexmoUser> {
            override fun onSuccess(user: NexmoUser) {
                emitter.onSuccess(user)
            }

            override fun onError(error: NexmoApiError) {
                emitter.onError(Throwable(error.message))
            }
        })
    }

    fun createUser(identity: String, displayName: String) = Single.create<CreateUserResponse> { emitter ->
        val jsonBody = JSONObject()
        jsonBody.put(KEY_NAME, identity)
        jsonBody.put(KEY_DISPLAY_NAME, displayName)

        (BASE_URL + USERS + CREATE_USER).httpPost()
            .body(jsonBody.toString())
            .header("Content-Type", "application/json")
            .responseString { _, _, result ->
                when (result) {
                    is Result.Success -> {
                        with(result.get().let { Gson().fromJson(it, CreateUserResponse::class.java) }) {
                            emitter.onSuccess(this)
                        }
                    }
                    is Result.Failure -> {
                        emitter.onError(result.getException())
                    }
                }
            }
    }

    companion object {
        private const val TAG = "NexmoRx"

        private const val BASE_URL = "http://10.0.2.2:3000"
        private const val USERS = "/users"
        private const val CREATE_USER = "/create"

        private const val KEY_NAME = "name"
        private const val KEY_DISPLAY_NAME = "display_name"
    }
}