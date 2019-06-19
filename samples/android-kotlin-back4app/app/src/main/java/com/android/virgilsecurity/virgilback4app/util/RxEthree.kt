package com.android.virgilsecurity.virgilback4app.util

import android.content.Context
import com.android.virgilsecurity.virgilback4app.AppVirgil
import com.virgilsecurity.android.common.data.model.LookupResult
import com.virgilsecurity.android.ethree.kotlin.callback.OnCompleteListener
import com.virgilsecurity.android.ethree.kotlin.callback.OnGetTokenCallback
import com.virgilsecurity.android.ethree.kotlin.callback.OnResultListener
import com.virgilsecurity.android.ethree.kotlin.interaction.EThree
import io.reactivex.Completable
import io.reactivex.Single

/**
 * RxEthree
 */
class RxEthree(val context: Context) {

    private val preferences = Preferences.instance(context)

    fun initEthree(): Single<EThree> = Single.create<EThree> { e ->
        EThree.initialize(context,
                          object : OnGetTokenCallback {
                              override fun onGetToken(): String {
                                  return preferences.virgilToken()!!
                              }
                          }).addCallback(object : OnResultListener<EThree> {
            override fun onSuccess(result: EThree) {
                e.onSuccess(result)
            }

            override fun onError(throwable: Throwable) {
                e.onError(throwable)
            }
        })
    }

    fun registerEthree(): Completable = Completable.create { e ->
        AppVirgil.eThree.register().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                e.onComplete()
            }

            override fun onError(throwable: Throwable) {
                e.onError(throwable)
            }
        })
    }

    fun findPublicKey(identity: String): Single<LookupResult> = Single.create<LookupResult> { e ->
        AppVirgil.eThree
                .lookupPublicKeys(identity)
                .addCallback(object : OnResultListener<LookupResult> {
                    override fun onSuccess(result: LookupResult) {
                        e.onSuccess(result)
                    }

                    override fun onError(throwable: Throwable) {
                        e.onError(throwable)
                    }
                })
    }
}
