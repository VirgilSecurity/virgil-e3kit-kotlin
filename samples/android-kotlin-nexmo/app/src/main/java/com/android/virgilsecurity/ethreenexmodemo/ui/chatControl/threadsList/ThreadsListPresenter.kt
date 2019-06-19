package com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.threadsList

import android.content.Context
import com.android.virgilsecurity.ethreenexmodemo.EThreeNexmoApp
import com.android.virgilsecurity.ethreenexmodemo.data.local.Preferences
import com.android.virgilsecurity.ethreenexmodemo.data.remote.nexmo.NexmoRx
import com.nexmo.client.NexmoClient
import com.nexmo.client.NexmoConversation
import com.nexmo.client.NexmoMember
import com.nexmo.client.request_listener.NexmoApiError
import com.nexmo.client.request_listener.NexmoRequestListener
import com.virgilsecurity.android.ethree.kotlin.interaction.EThree
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.disposables.CompositeDisposable
import io.reactivex.rxkotlin.plusAssign
import io.reactivex.rxkotlin.subscribeBy
import io.reactivex.schedulers.Schedulers
import java.util.*

/**
 * ThreadsListPresenter
 */
class ThreadsListPresenter(val context: Context) {

    private val compositeDisposable = CompositeDisposable()
    private val nexmoClient: NexmoClient by lazy { NexmoClient.get() }
    private val nexmoRx = NexmoRx(context)
    private val preferences = Preferences.instance(context)

    fun requestThreads(onSuccess: (Collection<NexmoConversation>) -> (Unit), onError: (Throwable) -> Unit) {
        var callbackWorked = false
        nexmoClient.getConversations(object : NexmoRequestListener<Collection<NexmoConversation>> {
            override fun onSuccess(conversations: Collection<NexmoConversation>) {
                callbackWorked = true
                onSuccess(conversations)
            }

            override fun onError(error: NexmoApiError) {
                callbackWorked = true
                onError(Throwable(error.message))
            }
        })

        Timer().schedule(object : TimerTask() {
            override fun run() {
                if (!callbackWorked) // If callback hasn't been called
                    onSuccess(listOf())
            }
        }, 5000) // If there're no conversations none of callbacks is being called, so call it manually after 5 sec
    }

    fun listenNewThreads(threadAddedSuccess: (NexmoConversation) -> Unit, threadAddedError: (Throwable) -> Unit) {
        nexmoClient.addNewConversationListener { conversation ->
            val membmers = conversation.allMembers
            val myself = membmers.find { it.user.name == preferences.username() }
            if (myself == null) {
                conversation.join(object : NexmoRequestListener<NexmoMember> {
                    override fun onSuccess(p0: NexmoMember?) {
                        threadAddedSuccess(conversation)
                    }

                    override fun onError(error: NexmoApiError) {
                        threadAddedError(Throwable(error.message))
                    }
                })
            } else {
                threadAddedSuccess(conversation)
            }
        }
    }

    fun initNexmo(onSuccess: () -> Unit, onError: (Throwable) -> Unit) {
        val initNexmoDisposable = nexmoRx.initNexmo(preferences.nexmoToken()!!)
            .subscribeOn(Schedulers.io())
            .observeOn(AndroidSchedulers.mainThread())
            .subscribeBy(
                onSuccess = { onSuccess() },
                onError = { onError(it) }
            )

        compositeDisposable += initNexmoDisposable
    }

    fun startEthree(onSuccess: () -> Unit, onError: (Throwable) -> Unit) {
        EThree.initialize(context,
            object : EThree.OnGetTokenCallback {
                override fun onGetToken(): String {
                    return preferences.virgilToken()!!
                }

            },
            object : EThree.OnResultListener<EThree> {
                override fun onSuccess(result: EThree) {
                    EThreeNexmoApp.eThree = result
                    onSuccess()
                }

                override fun onError(throwable: Throwable) {
                    onError(throwable)
                }
            })
    }

    fun disposeAll() {
        nexmoClient.removeNewConversationListener()
    }
}