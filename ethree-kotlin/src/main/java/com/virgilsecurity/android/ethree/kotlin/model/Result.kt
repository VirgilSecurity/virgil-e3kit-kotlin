package com.virgilsecurity.android.ethree.kotlin.model

import com.virgilsecurity.android.ethree.kotlin.callback.OnResultListener
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch

/**
 * Result
 */
interface Result<T> {

    fun get(): T

    fun addCallback(onResultListener: OnResultListener<T>, scope: CoroutineScope = GlobalScope) {
        scope.launch {
            try {
                val result = get()
                onResultListener.onSuccess(result)
            } catch (throwable: Throwable) {
                onResultListener.onError(throwable)
            }
        }
    }

    fun addCallback(onResultListener: OnResultListener<T>) =
            addCallback(onResultListener, GlobalScope)

    // TODO check whether we need cancel()
}
