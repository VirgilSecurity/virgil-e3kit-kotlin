package com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.addThread

import android.content.Context
import com.android.virgilsecurity.ethreenexmodemo.data.local.Preferences
import com.nexmo.client.NexmoClient
import com.nexmo.client.NexmoConversation
import com.nexmo.client.NexmoMember
import com.nexmo.client.request_listener.NexmoApiError
import com.nexmo.client.request_listener.NexmoRequestListener
import java.util.*

/**
 * AddThreadPresenter
 */
class AddThreadPresenter(context: Context) {

    private val nexmoClient = NexmoClient.get()
    private val preferences = Preferences(context)

    fun requestAddThread(interlocutor: String, onSuccess: (NexmoConversation) -> Unit, onError: (Throwable) -> Unit) {
        nexmoClient.newConversation(UUID.randomUUID().toString(),
            "${preferences.username()} & $interlocutor",
            object : NexmoRequestListener<NexmoConversation> {
                override fun onSuccess(thread: NexmoConversation) {

                    thread.join(object : NexmoRequestListener<NexmoMember> {
                        override fun onSuccess(p0: NexmoMember?) {
                            thread.join(interlocutor, object : NexmoRequestListener<String?> {
                                override fun onSuccess(p0: String?) {
                                    onSuccess(thread)
                                }

                                override fun onError(error: NexmoApiError) {
                                    onError(Throwable(error.message))
                                }

                            })
                        }

                        override fun onError(error: NexmoApiError) {
                            onError(Throwable(error.message))
                        }

                    })
                }

                override fun onError(error: NexmoApiError) {
                    onError(Throwable(error.message))
                }

            })
    }
}