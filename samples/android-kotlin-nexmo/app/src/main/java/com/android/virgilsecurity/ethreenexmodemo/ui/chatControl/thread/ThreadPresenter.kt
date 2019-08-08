package com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.thread

import android.content.Context
import com.android.virgilsecurity.ethreenexmodemo.EThreeNexmoApp
import com.android.virgilsecurity.ethreenexmodemo.data.local.Preferences
import com.android.virgilsecurity.ethreenexmodemo.data.model.chat.NexmoMessage
import com.nexmo.client.*
import com.nexmo.client.request_listener.NexmoApiError
import com.nexmo.client.request_listener.NexmoRequestListener
import com.virgilsecurity.android.common.data.model.LookupResult
import com.virgilsecurity.android.ethree.kotlin.callback.OnResultListener
import com.virgilsecurity.android.ethree.kotlin.interaction.EThree
import com.virgilsecurity.sdk.crypto.PublicKey

/**
 * ThreadPresenter
 */
class ThreadPresenter(context: Context) {

    private val preferences = Preferences.instance(context)
    private lateinit var lookupResult: LookupResult
    private lateinit var messageEventListener: NexmoMessageEventListener

    fun startMessagesListener(thread: NexmoConversation, onNewMessage: (NexmoMessage) -> Unit) {
        messageEventListener = object : NexmoMessageEventListener {
            override fun onTypingEvent(p0: NexmoTypingEvent) {

            }

            override fun onAttachmentEvent(p0: NexmoAttachmentEvent) {

            }

            override fun onTextEvent(textEvent: NexmoTextEvent) {
                if (textEvent.member.user.name != preferences.username()) {
                    val sender = thread.allMembers.first { it.user.name != preferences.username() }
                            .user.name
                    onNewMessage(NexmoMessage(textEvent.text, sender))
                }
            }

            override fun onSeenReceipt(p0: NexmoSeenEvent) {

            }

            override fun onEventDeleted(p0: NexmoDeletedEvent) {

            }

            override fun onDeliveredReceipt(p0: NexmoDeliveredEvent) {

            }

        }

        thread.addMessageEventListener(messageEventListener)
    }

    fun requestSendMessage(
            thread: NexmoConversation,
            text: String,
            onSuccess: (NexmoMessage) -> Unit,
            onError: (Throwable) -> Unit
    ) {
        val encryptedText = EThreeNexmoApp.eThree.encrypt(text, lookupResult)

        thread.sendText(encryptedText, object : NexmoRequestListener<Void> {
            override fun onSuccess(p0: Void?) {
                onSuccess(NexmoMessage(encryptedText, preferences.username()!!))
            }

            override fun onError(error: NexmoApiError) {
                onError(Throwable(error.message))
            }

        })
    }

    fun requestPublicKey(thread: NexmoConversation, onSuccess: (LookupResult) -> Unit, onError: (Throwable) -> Unit) {
        val interlocutor = thread.allMembers.first { it.user.name != preferences.username() }.user.name

        EThreeNexmoApp.eThree
                .lookupPublicKeys(interlocutor)
                .addCallback(object : OnResultListener<LookupResult> {
                    override fun onSuccess(result: LookupResult) {
                        lookupResult = result
                        onSuccess(lookupResult)
                    }

                    override fun onError(throwable: Throwable) {
                        onError(throwable)
                    }
                })
    }

    fun stopMessagesListener(thread: NexmoConversation) {
        if (::messageEventListener.isInitialized)
            thread.removeMessageEventListener(messageEventListener)
    }
}
