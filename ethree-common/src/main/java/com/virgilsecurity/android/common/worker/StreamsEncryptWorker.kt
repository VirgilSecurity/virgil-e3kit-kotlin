/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
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

package com.virgilsecurity.android.common.worker

import com.virgilsecurity.android.common.exception.EThreeException
import com.virgilsecurity.android.common.model.FindUsersResult
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.keyknox.utils.unwrapCompanionClass
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import java.io.InputStream
import java.io.OutputStream
import java.util.*
import java.util.logging.Logger

/**
 * AuthEncryptWorker
 */
internal class StreamsEncryptWorker internal constructor(
        private val localKeyStorage: LocalKeyStorage,
        private val crypto: VirgilCrypto
) {

    internal fun authEncrypt(inputStream: InputStream,
                             streamSize: Int,
                             outputStream: OutputStream,
                             user: Card) =
            authEncrypt(inputStream,
                        streamSize,
                        outputStream,
                        FindUsersResult(mapOf(user.identity to user)))

    @JvmOverloads internal fun authEncrypt(inputStream: InputStream,
                                           streamSize: Int,
                                           outputStream: OutputStream,
                                           users: FindUsersResult? = null) =
            encryptInternal(inputStream,
                            streamSize,
                            outputStream,
                            users?.map { it.value.publicKey })

    @JvmOverloads internal fun authDecrypt(inputStream: InputStream,
                                           outputStream: OutputStream,
                                           user: Card? = null) =
            decryptInternal(inputStream,
                            outputStream,
                            user?.publicKey)

    internal fun authDecrypt(inputStream: InputStream,
                             outputStream: OutputStream,
                             user: Card,
                             date: Date) {
        logger.fine("Auth decrypt stream with card ${user.identifier}")
        var card = user

        while (card.previousCard != null) {
            if (card.createdAt <= date) {
                break
            }

            card = card.previousCard
        }

        return decryptInternal(inputStream, outputStream, card.publicKey)
    }

    internal fun encryptShared(inputStream: InputStream,
                               inputStreamSize: Int,
                             outputStream: OutputStream): ByteArray {
        logger.fine("Encrypt shared stream")
        val selfKeyPair = localKeyStorage.retrieveKeyPair()
        val streamKeyPair = this.crypto.generateKeyPair()

        crypto.authEncrypt(inputStream, inputStreamSize, outputStream, selfKeyPair.privateKey, streamKeyPair.publicKey)

        return this.crypto.exportPrivateKey(streamKeyPair.privateKey)
    }

    internal fun decryptShared(inputStream: InputStream,
                               outputStream: OutputStream,
                               privateKeyData: ByteArray,
                               senderPublicKey: VirgilPublicKey?) {
        logger.fine("Decrypt shared stream with key ${senderPublicKey?.identifier}")
        val streamKeyPair = this.crypto.importPrivateKey(privateKeyData)
        return decryptInternal(inputStream, outputStream, senderPublicKey, streamKeyPair.privateKey)
    }

    private fun encryptInternal(inputStream: InputStream,
                                streamSize: Int,
                                outputStream: OutputStream,
                                publicKeys: List<VirgilPublicKey>?) {
        val selfKeyPair = localKeyStorage.retrieveKeyPair()
        val pubKeys = mutableListOf(selfKeyPair.publicKey)

        if (publicKeys != null) {
            if (publicKeys.isEmpty()) {
                throw EThreeException(EThreeException.Description.MISSING_PUBLIC_KEY)
            }

            pubKeys += publicKeys
        }

        crypto.authEncrypt(inputStream, streamSize, outputStream, selfKeyPair.privateKey, pubKeys)
    }

    private fun decryptInternal(inputStream: InputStream,
                                outputStream: OutputStream,
                                publicKey: VirgilPublicKey?,
                                privateKey: VirgilPrivateKey? = null) {
        var publicKeyNew = publicKey
        var privateKeyNew = privateKey
        if (publicKey == null || privateKey == null) {
            val selfKeyPair = localKeyStorage.retrieveKeyPair()

            publicKeyNew = publicKey ?: selfKeyPair.publicKey
            privateKeyNew = privateKey ?: selfKeyPair.privateKey
        }

        crypto.authDecrypt(inputStream, outputStream, privateKeyNew, publicKeyNew)
    }

    companion object {
        private val logger = Logger.getLogger(unwrapCompanionClass(this::class.java).name)
    }
}
