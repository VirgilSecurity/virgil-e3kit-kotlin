package com.virgilsecurity.android.ethree.kotlin.callback

/**
 * Interface that is intended to signal if some asynchronous process is completed successfully
 * or not.
 */
interface OnCompleteListener {

    /**
     * This method will be called if asynchronous process is completed successfully.
     */
    fun onSuccess()

    /**
     * This method will be called if asynchronous process is failed and provide [throwable]
     * cause.
     */
    fun onError(throwable: Throwable)
}
