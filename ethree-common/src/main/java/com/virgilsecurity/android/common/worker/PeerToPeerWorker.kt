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

package com.virgilsecurity.android.common.worker

import com.virgilsecurity.android.common.exception.EThreeException
import com.virgilsecurity.android.common.model.FindUsersResult
import com.virgilsecurity.android.common.model.LookupResult
import com.virgilsecurity.android.common.model.toPublicKeys
import com.virgilsecurity.android.common.storage.local.KeyStorageLocal
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.crypto.exceptions.SignatureIsNotValidException
import com.virgilsecurity.sdk.exception.EmptyArgumentException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * PeerToPeerWorker
 */
internal class PeerToPeerWorker(
        private val keyStorageLocal: KeyStorageLocal,
        private val crypto: VirgilCrypto
) {

    @JvmOverloads internal fun encrypt(data: Data, users: FindUsersResult? = null): Data =
            encryptInternal(data, users?.map { it.value.publicKey })

    @JvmOverloads internal fun decrypt(data: Data, user: Card? = null): Data =
            decryptInternal(data, user?.publicKey)

    internal fun decrypt(data: Data, user: Card, date: Date): Data {
        var card = user

        while (card.previousCard != null) {
            if (card.createdAt <= date) {
                break
            }

            card = card.previousCard
        }

        return decryptInternal(data, card.publicKey)
    }

    @JvmOverloads internal fun encrypt(inputStream: InputStream,
                                       outputStream: OutputStream,
                                       users: FindUsersResult? = null) =
            encryptInternal(inputStream, outputStream, users?.map { it.value.publicKey })

    internal fun decrypt(inputStream: InputStream, outputStream: OutputStream) {
        if (inputStream.available() == 0) throw EmptyArgumentException("inputStream")

        val selfKeyPair = keyStorageLocal.load()

        crypto.decrypt(inputStream, outputStream, selfKeyPair.privateKey)
    }

    @JvmOverloads internal fun encrypt(text: String, users: FindUsersResult? = null): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        if (users != null) require(users.isNotEmpty()) { "Passed empty FindUsersResult" }

        val data = try {
            Data(text.toByteArray(StandardCharsets.UTF_8))
        } catch (exception: IllegalArgumentException) {
            throw EThreeException("Error while converting String to Data. ${exception.message}")
        }
        return encrypt(data, users).toBase64String()
    }

    @JvmOverloads internal fun decrypt(text: String, user: Card? = null): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        val data = try {
            Data.fromBase64String(text)
        } catch (exception: IllegalArgumentException) {
            throw EThreeException("Error while converting String to Data. ${exception.message}")
        }

        val decryptedData = decrypt(data, user)

        return String(decryptedData.data, StandardCharsets.UTF_8)
    }

    internal fun decrypt(text: String, user: Card, date: Date): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        val data = try {
            Data.fromBase64String(text)
        } catch (exception: IllegalArgumentException) {
            throw EThreeException("Error while converting String to Data. ${exception.message}")
        }

        val decryptedData = decrypt(data, user, date)

        return String(decryptedData.data, StandardCharsets.UTF_8)
    }

    internal fun encrypt(data: Data, user: Card): Data =
            encrypt(data, FindUsersResult(mutableMapOf(user.identity to user)))

    internal fun encrypt(text: String, user: Card): String =
            encrypt(text, FindUsersResult(mutableMapOf(user.identity to user)))

    internal fun encrypt(inputStream: InputStream, outputStream: OutputStream, user: Card) =
            encrypt(inputStream, outputStream, FindUsersResult(mutableMapOf(user.identity to user)))

    private fun encryptInternal(inputStream: InputStream,
                                outputStream: OutputStream,
                                publicKeys: List<VirgilPublicKey>?) {
        if (inputStream.available() == 0) throw EmptyArgumentException("inputStream")

        val selfKeyPair = keyStorageLocal.load()
        val pubKeys = mutableListOf(selfKeyPair.publicKey)

        if (publicKeys != null) {
            if (publicKeys.isEmpty()) {
                throw EThreeException("Passed empty FindUsersResult")
            }

            pubKeys += publicKeys
        }

        crypto.encrypt(inputStream, outputStream, pubKeys)
    }

    private fun encryptInternal(data: Data,
                                publicKeys: List<VirgilPublicKey>?): Data {
        require(data.data.isNotEmpty()) { "\'data\' should not be empty." }

        val selfKeyPair = keyStorageLocal.load()
        val pubKeys = mutableListOf(selfKeyPair.publicKey)

        if (publicKeys != null) {
            if (publicKeys.isEmpty())
                throw EThreeException("Passed empty FindUsersResult")

            pubKeys += publicKeys
        }

        return Data(crypto.signThenEncrypt(data.data, selfKeyPair.privateKey, pubKeys))
    }

    private fun decryptInternal(data: Data, publicKey: VirgilPublicKey?): Data {
        require(data.data.isNotEmpty()) { "\'data\' should not be empty." }

        val selfKeyPair = keyStorageLocal.load()
        val pubKey = publicKey ?: selfKeyPair.publicKey

        return try {
            Data(crypto.decryptThenVerify(data.data, selfKeyPair.privateKey, pubKey))
        } catch (exception: Throwable) {
            when (exception.cause) {
                is SignatureIsNotValidException -> {
                    throw EThreeException("Verification of message failed. This may be caused by " +
                                          "rotating sender key. Try finding new one")
                }
                else -> throw exception
            }
        }
    }

    // Backward compatibility deprecated methods --------------------------------------------------

    @Deprecated("Use encryptForUsers method instead.")
    internal fun encrypt(text: String, lookupResult: LookupResult): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        val data = try {
            Data(text.toByteArray(StandardCharsets.UTF_8))
        } catch (exception: IllegalArgumentException) {
            throw EThreeException("Error while converting String to Data. ${exception.message}")
        }

        return encryptInternal(data, lookupResult.toPublicKeys()).toBase64String()
    }

    @Deprecated("Use encryptForUsers method instead.")
    @JvmOverloads internal fun encrypt(data: ByteArray,
                                       lookupResult: LookupResult? = null): ByteArray =
            encryptInternal(Data(data), lookupResult.toPublicKeys()).data

    @Deprecated("Use encryptForUsers method instead.")
    internal fun encrypt(inputStream: InputStream,
                         outputStream: OutputStream,
                         lookupResult: LookupResult) =
            encryptInternal(inputStream, outputStream, lookupResult.toPublicKeys())

    @Deprecated("Use decryptFromUser method instead.")
    internal fun decrypt(base64String: String, sendersKey: VirgilPublicKey): String {
        require(base64String.isNotEmpty()) { "\'text\' should not be empty" }

        val data = try {
            Data.fromBase64String(base64String)
        } catch (exception: IllegalArgumentException) {
            throw EThreeException("Error while converting String to Data. ${exception.message}")
        }

        val decryptedData = decryptInternal(data, sendersKey)

        return String(decryptedData.data, StandardCharsets.UTF_8)
    }

    @Deprecated("Use decryptFromUser method instead.")
    @JvmOverloads internal fun decrypt(data: ByteArray,
                                       sendersKey: VirgilPublicKey? = null): ByteArray =
            decryptInternal(Data(data), sendersKey).data
}
