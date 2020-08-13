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
import com.virgilsecurity.android.common.model.LookupResult
import com.virgilsecurity.android.common.model.toPublicKeys
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.common.exception.EmptyArgumentException
import com.virgilsecurity.common.extension.toData
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * PeerToPeerWorker
 */
internal class PeerToPeerWorker internal constructor(
        private val localKeyStorage: LocalKeyStorage,
        private val crypto: VirgilCrypto
) {

    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    @JvmOverloads
    internal fun encrypt(data: Data, users: FindUsersResult? = null): Data =
            oldEncryptInternal(data, users?.map { it.value.publicKey })

    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    @JvmOverloads
    internal fun decrypt(data: Data, user: Card? = null): Data =
            oldDecryptInternal(data, user?.publicKey)

    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    internal fun decrypt(data: Data, user: Card, date: Date): Data {
        var card = user

        while (card.previousCard != null) {
            if (card.createdAt <= date) {
                break
            }

            card = card.previousCard
        }

        return oldDecryptInternal(data, card.publicKey)
    }

    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    @JvmOverloads
    internal fun encrypt(inputStream: InputStream,
                         outputStream: OutputStream,
                         users: FindUsersResult? = null) =
            oldEncryptInternal(inputStream, outputStream, users?.map { it.value.publicKey })

    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    internal fun decrypt(inputStream: InputStream, outputStream: OutputStream) {
        val selfKeyPair = localKeyStorage.retrieveKeyPair()

        crypto.decrypt(inputStream, outputStream, selfKeyPair.privateKey)
    }

    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    @JvmOverloads
    internal fun encrypt(text: String, users: FindUsersResult? = null): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        if (users != null) require(users.isNotEmpty()) { "Passed empty FindUsersResult" }

        val data = try {
            text.toByteArray(StandardCharsets.UTF_8).toData()
        } catch (exception: IllegalArgumentException) {
            throw EThreeException(EThreeException.Description.STR_TO_DATA_FAILED, exception)
        }
        return encrypt(data, users).toBase64String()
    }

    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    @JvmOverloads
    internal fun decrypt(text: String, user: Card? = null): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        val data = try {
            Data.fromBase64String(text)
        } catch (exception: IllegalArgumentException) {
            throw EThreeException(EThreeException.Description.STR_TO_DATA_FAILED, exception)
        }

        val decryptedData = decrypt(data, user)

        return String(decryptedData.value, StandardCharsets.UTF_8)
    }

    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    internal fun decrypt(text: String, user: Card, date: Date): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        val data = try {
            Data.fromBase64String(text)
        } catch (exception: IllegalArgumentException) {
            throw EThreeException(EThreeException.Description.STR_TO_DATA_FAILED, exception)
        }

        val decryptedData = decrypt(data, user, date)

        return String(decryptedData.value, StandardCharsets.UTF_8)
    }

    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    internal fun encrypt(data: Data, user: Card): Data =
            encrypt(data, FindUsersResult(mutableMapOf(user.identity to user)))

    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    internal fun encrypt(text: String, user: Card): String =
            encrypt(text, FindUsersResult(mutableMapOf(user.identity to user)))

    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    internal fun encrypt(inputStream: InputStream, outputStream: OutputStream, user: Card) =
            encrypt(inputStream, outputStream, FindUsersResult(mutableMapOf(user.identity to user)))

    private fun oldEncryptInternal(inputStream: InputStream,
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

        crypto.encrypt(inputStream, outputStream, pubKeys)
    }

    private fun oldEncryptInternal(data: Data,
                                publicKeys: List<VirgilPublicKey>?): Data {
        require(data.value.isNotEmpty()) { "\'data\' should not be empty." }

        val selfKeyPair = localKeyStorage.retrieveKeyPair()
        val pubKeys = mutableListOf(selfKeyPair.publicKey)

        if (publicKeys != null) {
            if (publicKeys.isEmpty())
                throw EThreeException(EThreeException.Description.MISSING_PUBLIC_KEY)

            pubKeys += publicKeys
        }

        return crypto.signThenEncrypt(data.value, selfKeyPair.privateKey, pubKeys).toData()
    }

    private fun oldDecryptInternal(data: Data, publicKey: VirgilPublicKey?): Data {
        require(data.value.isNotEmpty()) { "\'data\' should not be empty." }

        val selfKeyPair = localKeyStorage.retrieveKeyPair()
        val pubKey = publicKey ?: selfKeyPair.publicKey

        return try {
            crypto.decryptThenVerify(data.value, selfKeyPair.privateKey, pubKey).toData()
        } catch (exception: Throwable) {
            when (exception.cause) {
                is VerificationException -> {
                    throw EThreeException(EThreeException.Description.VERIFICATION_FAILED)
                }
                else -> throw exception
            }
        }
    }

    // Backward compatibility deprecated methods --------------------------------------------------

    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    internal fun encrypt(text: String, lookupResult: LookupResult): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        val data = try {
            text.toData(StandardCharsets.UTF_8)
        } catch (exception: IllegalArgumentException) {
            throw EThreeException(EThreeException.Description.STR_TO_DATA_FAILED, exception)
        }

        return oldEncryptInternal(data, lookupResult.toPublicKeys()).toBase64String()
    }

    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    @JvmOverloads internal fun encrypt(data: ByteArray,
                                       lookupResult: LookupResult? = null): ByteArray =
            oldEncryptInternal(data.toData(), lookupResult.toPublicKeys()).value

    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    internal fun encrypt(inputStream: InputStream,
                         outputStream: OutputStream,
                         lookupResult: LookupResult) =
            oldEncryptInternal(inputStream, outputStream, lookupResult.toPublicKeys())

    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    internal fun decrypt(base64String: String, sendersKey: VirgilPublicKey): String {
        require(base64String.isNotEmpty()) { "\'text\' should not be empty" }

        val data = try {
            Data.fromBase64String(base64String)
        } catch (exception: IllegalArgumentException) {
            throw EThreeException(EThreeException.Description.STR_TO_DATA_FAILED, exception)
        }

        val decryptedData = oldDecryptInternal(data, sendersKey)

        return String(decryptedData.value, StandardCharsets.UTF_8)
    }

    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    @JvmOverloads internal fun decrypt(data: ByteArray,
                                       sendersKey: VirgilPublicKey? = null): ByteArray =
            oldDecryptInternal(data.toData(), sendersKey).value
}
