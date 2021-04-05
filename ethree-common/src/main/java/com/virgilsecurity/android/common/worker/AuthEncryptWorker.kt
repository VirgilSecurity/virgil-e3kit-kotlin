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
import com.virgilsecurity.common.extension.toData
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.keyknox.utils.unwrapCompanionClass
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException
import java.nio.charset.StandardCharsets
import java.util.*
import java.util.logging.Logger

/**
 * AuthEncryptWorker
 */
internal class AuthEncryptWorker internal constructor(
        private val localKeyStorage: LocalKeyStorage,
        private val crypto: VirgilCrypto
) {

    internal fun authEncrypt(data: Data, user: Card): Data =
            authEncrypt(data, FindUsersResult(mapOf(user.identity to user)))

    internal fun authEncrypt(text: String, user: Card): String =
            authEncrypt(text, FindUsersResult(mapOf(user.identity to user)))

    @JvmOverloads internal fun authDecrypt(data: Data, user: Card? = null): Data =
            decryptInternal(data, user?.publicKey)

    internal fun authDecrypt(data: Data, user: Card, date: Date): Data {
        logger.fine("Auth decrypt data with card ${user.identifier}")
        var card = user

        while (card.previousCard != null) {
            if (card.createdAt <= date) {
                break
            }

            card = card.previousCard
        }

        return decryptInternal(data, card.publicKey)
    }

    @JvmOverloads internal fun authDecrypt(text: String, user: Card? = null): String {
        logger.fine("Auth decrypt text with card ${user?.identifier}")
        val data = try {
            Data.fromBase64String(text)
        } catch (exception: IllegalArgumentException) {
            throw EThreeException(EThreeException.Description.STR_TO_DATA_FAILED, exception)
        }

        val decryptedData = authDecrypt(data, user)

        return String(decryptedData.value, StandardCharsets.UTF_8)
    }

    internal fun authDecrypt(text: String, user: Card, date: Date): String {
        logger.fine("Auth decrypt text with card ${user.identifier}")
        val data = try {
            Data.fromBase64String(text)
        } catch (exception: IllegalArgumentException) {
            throw EThreeException(EThreeException.Description.STR_TO_DATA_FAILED, exception)
        }

        val decryptedData = authDecrypt(data, user, date)

        return String(decryptedData.value, StandardCharsets.UTF_8)
    }

    @JvmOverloads internal fun authEncrypt(text: String, users: FindUsersResult? = null): String {
        logger.fine("Auth encrypt text")
        if (users != null) require(users.isNotEmpty()) { "Passed empty FindUsersResult" }

        val data = try {
            text.toData(StandardCharsets.UTF_8)
        } catch (exception: IllegalArgumentException) {
            throw EThreeException(EThreeException.Description.STR_TO_DATA_FAILED, exception)
        }
        return authEncrypt(data, users).toBase64String()
    }

    @JvmOverloads internal fun authEncrypt(data: Data, users: FindUsersResult? = null): Data =
            encryptInternal(data, users?.map { it.value.publicKey })

    private fun encryptInternal(data: Data, publicKeys: List<VirgilPublicKey>?): Data {
        val selfKeyPair = localKeyStorage.retrieveKeyPair()
        val pubKeys = mutableListOf(selfKeyPair.publicKey)

        if (publicKeys != null) {
            if (publicKeys.isEmpty())
                throw EThreeException(EThreeException.Description.MISSING_PUBLIC_KEY)

            pubKeys += publicKeys
        }

        return crypto.authEncrypt(data.value, selfKeyPair.privateKey, pubKeys).toData()
    }

    private fun decryptInternal(data: Data, publicKey: VirgilPublicKey?): Data {
        val selfKeyPair = localKeyStorage.retrieveKeyPair()
        val pubKey = publicKey ?: selfKeyPair.publicKey

        return try {
            crypto.authDecrypt(data.value, selfKeyPair.privateKey, pubKey, true).toData()
        } catch (exception: Throwable) {
            when (exception.cause) {
                is VerificationException -> {
                    throw EThreeException(EThreeException.Description.VERIFICATION_FAILED)
                }
                else -> throw exception
            }
        }
    }

    companion object {
        private val logger = Logger.getLogger(unwrapCompanionClass(this::class.java).name)
    }
}
