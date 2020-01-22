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

package com.virgilsecurity.android.common.model.ratchet

import com.virgilsecurity.android.common.exception.EThreeException
import com.virgilsecurity.android.common.exception.EThreeRatchetException
import com.virgilsecurity.common.extension.toData
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.crypto.ratchet.RatchetMessage
import com.virgilsecurity.ratchet.securechat.SecureSession
import com.virgilsecurity.ratchet.sessionstorage.SessionStorage
import java.nio.charset.StandardCharsets

/**
 * Class representing Ratchet Chat.
 */
class RatchetChannel(
        internal val session: SecureSession,
        internal val sessionStorage: SessionStorage
) {

    val participant: String
        get() = session.participantIdentity

    /**
     * Encrypts data.
     *
     * @param data Data to encrypt.
     */
    fun encrypt(data: Data): Data {
        require(data.value.isNotEmpty()) { "\'data\' should not be empty" }

        val ratchetMessage = this.session.encrypt(data.value)
        sessionStorage.storeSession(this.session)

        return ratchetMessage.serialize().toData()
    }

    /**
     * Decrypts data.
     *
     * @param data Encrypted data.
     */
    fun decrypt(data: Data): Data {
        require(data.value.isNotEmpty()) { "\'data\' should not be empty" }

        val message = RatchetMessage.deserialize(data.value)
        val decrypted = session.decryptData(message).toData()

        sessionStorage.storeSession(this.session)

        return decrypted
    }

    /**
     * Encrypts string.
     *
     * @param text String to encrypt.
     */
    fun encrypt(text: String): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        val data = try {
            text.toByteArray(StandardCharsets.UTF_8).toData()
        } catch (exception: IllegalArgumentException) {
            throw EThreeException(EThreeException.Description.STR_TO_DATA_FAILED, exception)
        }

        return encrypt(data).toBase64String()
    }

    /**
     * Decrypts string.
     *
     * @param text Encrypted string.
     */
    fun decrypt(text: String): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        val data = try {
            Data.fromBase64String(text)
        } catch (exception: IllegalArgumentException) {
            throw EThreeException(EThreeException.Description.STR_TO_DATA_FAILED, exception)
        }

        val decryptedData = decrypt(data)

        return String(decryptedData.value, Charsets.UTF_8)
    }

    data class MultipleData(val multipleData: List<Data>)

    /**
     * Encrypts multiple of data.
     *
     * @param data Multiple data to encrypt.
     */
    fun encryptMultiple(data: MultipleData): MultipleData {
        if (data.multipleData.count() == 0)
            throw EThreeRatchetException(EThreeRatchetException.Description.ENCRYPT_EMPTY_ARRAY)

        val result = mutableListOf<Data>()

        data.multipleData.forEach {
            val ratchetMessage = session.encrypt(it.value)
            val encrypted = ratchetMessage.serialize().toData()

            result.add(encrypted)
        }

        sessionStorage.storeSession(this.session)

        return MultipleData(result)
    }

    /**
     * Decrypts multiple of data.
     *
     * - Important: data should be in strict order by encryption time.
     *
     * @param data Multiple data to decrypt.
     */
    fun decryptMultiple(data: MultipleData): MultipleData {
        if (data.multipleData.count() == 0)
            throw EThreeRatchetException(EThreeRatchetException.Description.DECRYPT_EMPTY_ARRAY)

        val result = mutableListOf<Data>()

        data.multipleData.forEach {
            val ratchetMessage = RatchetMessage.deserialize(it.value)
            val decrypted = session.decryptData(ratchetMessage).toData()

            result.add(decrypted)
        }

        sessionStorage.storeSession(this.session)

        return MultipleData(result)
    }

    data class MultipleString(val multipleText: List<String>)

    /**
     * Encrypts multiple strings.
     *
     * @param text Multiple strings to encrypt.
     */
    fun encryptMultiple(text: MultipleString): MultipleString {
        val data = text.multipleText.map {
            try {
                it.toByteArray(StandardCharsets.UTF_8).toData()
            } catch (exception: IllegalArgumentException) {
                throw EThreeException(EThreeException.Description.STR_TO_DATA_FAILED, exception)
            }
        }

        val encryptedData = encryptMultiple(MultipleData(data))
        val encryptedStrings = encryptedData.multipleData.map { it.toBase64String() }

        return MultipleString(encryptedStrings)
    }

    /**
     * Decrypts multiple strings.
     *
     * - Important: data should be in strict order by encryption time.
     *
     * @param text Multiple strings to decrypt.
     */
    fun decryptMultiple(text: MultipleString): MultipleString {
        val data = text.multipleText.map {
            try {
                Data.fromBase64String(it)
            } catch (exception: IllegalArgumentException) {
                throw EThreeException(EThreeException.Description.STR_TO_DATA_FAILED, exception)
            }
        }

        val decryptedData = decryptMultiple(MultipleData(data))
        val decryptedStrings = decryptedData.multipleData.map { String(it.value, Charsets.UTF_8) }

        return MultipleString(decryptedStrings)
    }
}
