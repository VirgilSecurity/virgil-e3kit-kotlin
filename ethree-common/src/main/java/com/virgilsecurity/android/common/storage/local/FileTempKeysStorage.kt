/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.android.common.storage.local

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.virgilsecurity.android.common.util.Const
import com.virgilsecurity.common.extension.toData
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.storage.FileSystem
import com.virgilsecurity.sdk.storage.FileSystemEncrypted
import java.io.File
import java.io.FileNotFoundException

/**
 * FileTempKeysStorage
 */
internal class FileTempKeysStorage(
        internal val identity: String,
        private val crypto: VirgilCrypto,
        private val identityKeyPair: VirgilKeyPair,
        rootPath: String
) {

    private val fileSystem: FileSystem
    private val gson: Gson by lazy { Gson() }

    init {
        val fullPath: String = rootPath +
                               File.separator +
                               identity +
                               File.separator +
                               Const.STORAGE_POSTFIX_E3KIT +
                               File.separator +
                               STORAGE_POSTFIX_TEMPORARY_KEYS

        fileSystem = FileSystemEncrypted(fullPath)
    }

    internal fun store(key: VirgilPrivateKey, identity: String) {
        val keyData = crypto.exportPrivateKey(key).toData()
        val data = encode(keyData, KeyType.PRIVATE)
        fileSystem.write(data, Const.DEFAULT_NAME, identity)
    }

    internal fun store(key: VirgilPublicKey, identity: String) {
        val keyData = crypto.exportPublicKey(key).toData()
        val data = encode(keyData, KeyType.PUBLIC)
        fileSystem.write(data, Const.DEFAULT_NAME, identity)
    }

    internal fun retrieve(identity: String): TempKey? {
        return try {
            val data = fileSystem.read(Const.DEFAULT_NAME, identity)
            decode(data)
        } catch (exception: FileNotFoundException) {
            null
        }
    }

    internal fun delete(identity: String) {
        fileSystem.delete(Const.DEFAULT_NAME, identity)
    }

    internal fun reset() {
        fileSystem.delete()
    }

    private fun encode(key: Data, type: KeyType): Data {
        val data = when (type) {
            KeyType.PRIVATE -> {
                crypto.authEncrypt(key.value,
                                   this.identityKeyPair.privateKey,
                                   this.identityKeyPair.publicKey).toData()
            }
            KeyType.PUBLIC -> {
                key
            }
        }

        val temporaryKey = TempKey(data, type)

        return gson.toJson(temporaryKey).toData()
    }

    private fun decode(data: Data): TempKey {
        val temporaryKey = gson.fromJson(data.asString(), TempKey::class.java)

        return when (temporaryKey.type) {
            KeyType.PRIVATE -> {
                val decryptedKey = crypto.authDecrypt(temporaryKey.key.value,
                                                      this.identityKeyPair.privateKey,
                                                      this.identityKeyPair.publicKey,
                                                      true).toData()
                temporaryKey.copy(key = decryptedKey)
            }
            KeyType.PUBLIC -> {
                temporaryKey
            }
        }
    }

    internal data class TempKey(
            @SerializedName("key")
            var key: Data,

            @SerializedName("type")
            val type: KeyType)

    internal enum class KeyType {
        PRIVATE,
        PUBLIC
    }

    companion object {
        private const val STORAGE_POSTFIX_TEMPORARY_KEYS = "UNSAFE-KEYS"
    }
}
