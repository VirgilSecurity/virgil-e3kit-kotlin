package com.virgilsecurity.android.common.data.local

import android.content.Context
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.JsonKeyEntry
import com.virgilsecurity.sdk.storage.KeyEntry
import com.virgilsecurity.sdk.storage.KeyStorage

/**
 * KeyManagerLocal
 */
class KeyManagerLocal(val identity: String, context: Context) {

    private val keyStorage: KeyStorage = DefaultKeyStorage(context.filesDir.absolutePath, KEYSTORE_NAME)

    fun exists() = keyStorage.exists(identity)

    fun store(privateKey: ByteArray) = keyStorage.store(JsonKeyEntry(identity, privateKey))

    fun load(): KeyEntry = keyStorage.load(identity)

    fun delete() = keyStorage.delete(identity)

    companion object {
        private const val KEYSTORE_NAME = "virgil.keystore"
    }
}