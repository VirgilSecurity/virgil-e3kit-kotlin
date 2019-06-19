package com.android.virgilsecurity.ethreenexmodemo.ui.signUp

import android.content.Context
import com.android.virgilsecurity.ethreenexmodemo.EThreeNexmoApp
import com.android.virgilsecurity.ethreenexmodemo.data.local.Preferences
import com.android.virgilsecurity.ethreenexmodemo.data.model.auth.CreateUserResponse
import com.android.virgilsecurity.ethreenexmodemo.data.remote.auth.AuthRx
import com.android.virgilsecurity.ethreenexmodemo.data.remote.nexmo.NexmoRx
import com.virgilsecurity.android.ethree.kotlin.interaction.EThree
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.disposables.CompositeDisposable
import io.reactivex.rxkotlin.plusAssign
import io.reactivex.rxkotlin.subscribeBy
import io.reactivex.schedulers.Schedulers

/**
 * SignUpPresenter
 */
class SignUpPresenter(val context: Context) {

    private val compositeDisposable = CompositeDisposable()
    private val authRx = AuthRx
    private val nexmoRx = NexmoRx(context)
    private val preferences = Preferences.instance(context)

    fun requestAuthenticate(identity: String, onSuccess: () -> Unit, onError: (Throwable) -> Unit) {
        val authenticateDisposable = authRx.authenticate(identity)
            .subscribeOn(Schedulers.io())
            .observeOn(AndroidSchedulers.mainThread())
            .map {
                preferences.setAuthToken(it)
                it
            }
            .subscribeBy(
                onSuccess = { onSuccess() },
                onError = { onError(it) }
            )

        compositeDisposable += authenticateDisposable
    }

    fun requestTokens(onSuccess: () -> Unit, onError: (Throwable) -> Unit) {
        val getTokensDisposable = authRx.nexmoJwt(preferences.authToken()!!)
            .subscribeOn(Schedulers.io())
            .observeOn(AndroidSchedulers.mainThread())
            .map {
                preferences.setNexmoToken(it)
            }
            .flatMap {
                authRx.virgilJwt(preferences.authToken()!!)
            }.map {
                preferences.setVirgilToken(it)
            }.subscribeBy(
                onSuccess = { onSuccess() },
                onError = { onError(it) }
            )

        compositeDisposable += getTokensDisposable
    }

    fun initNexmo(onSuccess: () -> Unit, onError: (Throwable) -> Unit) {
        val initNexmoDisposable = nexmoRx.initNexmo(preferences.nexmoToken()!!)
            .subscribeOn(Schedulers.io())
            .observeOn(AndroidSchedulers.mainThread())
            .map {
                preferences.setUsername(it.name)
                it
            }
            .subscribeBy(
                onSuccess = { onSuccess() },
                onError = { onError(it) }
            )

        compositeDisposable += initNexmoDisposable
    }

    fun createUser(
        identity: String,
        displayName: String,
        onSuccess: (CreateUserResponse) -> Unit,
        onError: (Throwable) -> Unit
    ) {
        val createUserDisposable = nexmoRx.createUser(identity, displayName)
            .subscribeOn(Schedulers.io())
            .observeOn(AndroidSchedulers.mainThread())
            .subscribeBy(
                onSuccess = { onSuccess(it) },
                onError = { onError(it) }
            )

        compositeDisposable += createUserDisposable
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
                    EThreeNexmoApp.eThree.register(object : EThree.OnCompleteListener {
                        override fun onSuccess() {
                            onSuccess()
                        }

                        override fun onError(throwable: Throwable) {
                            onError(throwable)
                        }
                    })
                }

                override fun onError(throwable: Throwable) {
                    onError(throwable)
                }
            })
    }

    fun disposeAll() = compositeDisposable.clear()
}