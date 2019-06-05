package com.virgilsecurity.android.ethree.kotlin.model

import com.virgilsecurity.android.ethree.kotlin.callback.OnCompleteListener
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch

/**
 * Completable
 */
interface Completable {

    fun execute()

    fun addCallback(onCompleteListener: OnCompleteListener, scope: CoroutineScope = GlobalScope) {
        scope.launch {
            try {
                execute()
                onCompleteListener.onSuccess()
            } catch (throwable: Throwable) {
                onCompleteListener.onError(throwable)
            }
        }
    }

    fun addCallback(onCompleteListener: OnCompleteListener) =
            addCallback(onCompleteListener, GlobalScope)

}
