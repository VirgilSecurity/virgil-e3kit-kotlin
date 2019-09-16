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
import com.virgilsecurity.android.common.exception.PrivateKeyNotFoundException
import com.virgilsecurity.android.common.manager.GroupManager
import com.virgilsecurity.android.common.model.FindUsersResult
import com.virgilsecurity.android.common.model.LookupResult
import com.virgilsecurity.android.common.model.toPublicKeys
import com.virgilsecurity.android.common.storage.local.KeyStorageLocal
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.crypto.exceptions.SignatureIsNotValidException
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException
import com.virgilsecurity.sdk.exception.EmptyArgumentException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * PeerToPeerWorker
 */
internal class PeerToPeerWorker(
        private val getGroupManager: () -> GroupManager,
        private val keyStorageLocal: KeyStorageLocal,
        private val crypto: VirgilCrypto
) {

    /**
     * Signs then encrypts data for group of users.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param data Data to encrypt.
     * @param users Result of findUsers call recipient Cards with Public Keys to sign and encrypt
     * with. Use null to sign and encrypt for self.
     *
     * @return Encrypted Data.
     */
    @JvmOverloads internal fun encrypt(data: Data, users: FindUsersResult? = null): Data =
            encryptInternal(data, users?.map { it.value.publicKey })

    /**
     * Decrypts and verifies data from users.
     *
     * *Important* Requires private key in local storage.
     *
     * @param data Data to decrypt.
     * @param user Sender Card with Public Key to verify with. Use null to decrypt and verify.
     * from self.
     *
     * @return Decrypted Data.
     */
    @JvmOverloads internal fun decrypt(data: Data, user: Card? = null): Data =
            decryptInternal(data, user?.publicKey)

    /**
     * Decrypts and verifies data from users.
     *
     * *Important* Requires private key in local storage.
     *
     * @param data Data to decrypt.
     * @param user Sender Card with Public Key to verify with.
     * @param date Date of encryption to use proper card version.
     *
     * @return Decrypted Data.
     */
    internal fun decrypt(data: Data, user: Card, date: Date): Data {
        var card = user

        while (card.previousCard != null) { // TODO test it with new card
            if (card.createdAt <= date) {
                break
            }

            card = card.previousCard
        }

        return decryptInternal(data, card.publicKey)
    }

    /**
     * Encrypts data stream.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param inputStream Data stream to be encrypted.
     * @param outputStream Stream with encrypted data.
     * @param users Result of findUsers call recipient Cards with Public Keys to sign and encrypt
     * with. Use null to sign and encrypt for self.
     */
    @JvmOverloads internal fun encrypt(inputStream: InputStream,
                                       outputStream: OutputStream,
                                       users: FindUsersResult? = null) =
            encryptInternal(inputStream, outputStream, users?.map { it.value.publicKey })

    /**
     * Decrypts encrypted stream.
     *
     * *Important* Requires private key in local storage.
     *
     * @param inputStream Stream with encrypted data.
     * @param outputStream Stream with decrypted data.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    internal fun decrypt(inputStream: InputStream, outputStream: OutputStream) {
        if (inputStream.available() == 0) throw EmptyArgumentException("inputStream")

        val selfKeyPair = keyStorageLocal.load()

        crypto.decrypt(inputStream, outputStream, selfKeyPair.privateKey)
    }

    /**
     * Signs then encrypts string for group of users.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param text String to encrypt. String should be *UTF-8* encoded.
     * @param users Result of findUsers call recipient Cards with Public Keys to sign and encrypt
     * with. Use null to sign and encrypt for self.
     *
     * @return Encrypted base64String.
     */
    @JvmOverloads internal fun encrypt(text: String, users: FindUsersResult? = null): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        val data = Data(text.toByteArray(StandardCharsets.UTF_8)) // TODO check exception type and wrap with "String to Data failed" message
        return encrypt(data, users).toBase64String()
    }

    /**
     * Decrypts and verifies base64 string from users.
     *
     * *Important* Requires private key in local storage.
     *
     * @param text Encrypted String.
     * @param user Sender Card with Public Key to verify with. Use null to decrypt and verify
     * from self.
     *
     * @return Decrypted String.
     */
    @JvmOverloads internal fun decrypt(text: String, user: Card? = null): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        val data = Data.fromBase64String(text) // TODO check exception type and wrap with "Data to String failed" message

        val decryptedData = decrypt(data, user)

        return String(decryptedData.data, StandardCharsets.UTF_8)
    }

    /**
     * Decrypts and verifies base64 string from users.
     *
     * *Important* Requires private key in local storage.
     *
     * @param text Encrypted String.
     * @param user Sender Card with Public Key to verify with.
     * @param date Date of encryption to use proper card version.
     *
     * @return Decrypted String.
     */
    internal fun decrypt(text: String, user: Card, date: Date): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        val data = Data.fromBase64String(text) // TODO check exception type and wrap with "Data to String failed" message

        val decryptedData = decrypt(data, user, date)

        return String(decryptedData.data, StandardCharsets.UTF_8)
    }

    /**
     * Signs and encrypts data for user.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * @param data Data to encrypt.
     * @param user User Card to encrypt for.
     *
     * @return Encrypted data.
     */
    internal fun encrypt(data: Data, user: Card): Data =
            encrypt(data, mapOf(user.identity to user))

    /**
     * Signs and encrypts string for user.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * @param text String to encrypt.
     * @param user User Card to encrypt for.
     *
     * @return Encrypted String.
     */
    internal fun encrypt(text: String, user: Card): String =
            encrypt(text, mapOf(user.identity to user))

    /**
     * Encrypts data stream.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * @param inputStream Data stream to be encrypted.
     * @param outputStream Stream with encrypted data.
     * @param user User Card to encrypt for.
     */
    internal fun encrypt(inputStream: InputStream, outputStream: OutputStream, user: Card) =
            encrypt(inputStream, outputStream, mapOf(user.identity to user))

    internal fun encryptInternal(inputStream: InputStream,
                                 outputStream: OutputStream,
                                 publicKeys: List<VirgilPublicKey>?) {
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

    internal fun encryptInternal(data: Data,
                                 publicKeys: List<VirgilPublicKey>?): Data { // TODO check for empty/null args
        val selfKeyPair = keyStorageLocal.load()
        val pubKeys = mutableListOf(selfKeyPair.publicKey)

        if (publicKeys != null) {
            if (publicKeys.isEmpty()) {
                throw EThreeException("Passed empty FindUsersResult")
            }

            pubKeys += publicKeys
        }

        return Data(crypto.signThenEncrypt(data.data, selfKeyPair.privateKey, pubKeys))
    }

    internal fun decryptInternal(data: Data, publicKey: VirgilPublicKey?): Data {
        val selfKeyPair = keyStorageLocal.load()
        val pubKey = publicKey ?: selfKeyPair.publicKey

        return try {
            Data(crypto.decryptThenVerify(data.data, selfKeyPair.privateKey, pubKey))
        } catch (exception: Throwable) {
            when (exception) {
                is SignatureIsNotValidException, is VerificationException -> { // TODO test this case
                    throw EThreeException("Verification of message failed. This may be caused by " +
                                          "rotating sender key. Try finding new one")
                }
                else -> throw exception
            }
        }
    }

    // Backward compatibility deprecated methods --------------------------------------------------

    /**
     * Signs then encrypts data for a group of users.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param text String to encrypt.
     * @param lookupResult Result of lookupPublicKeys call recipient PublicKeys to sign and
     * encrypt with.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Use encryptForUsers method instead.") // TODO change to actual fun name
    internal fun encryptOld(text: String, lookupResult: LookupResult): String {
        val data = Data(text.toByteArray(StandardCharsets.UTF_8)) // TODO check exception type

        return encryptInternal(data, lookupResult.toPublicKeys()).toBase64String()
    }

    /**
     * Signs then encrypts data for a group of users.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param data Data to encrypt
     * @param lookupResult Result of lookupPublicKeys call recipient PublicKeys to sign and
     * encrypt with.
     *
     * @return Encrypted Data.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Use encryptForUsers method instead.")
    internal fun encryptOld(data: ByteArray, lookupResult: LookupResult): ByteArray =
            encryptInternal(Data(data), lookupResult.toPublicKeys()).data

    /**
     * Encrypts data stream for a group of users.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param inputStream Data stream to be encrypted.
     * @param outputStream Stream with encrypted data.
     * @param lookupResult Result of lookupPublicKeys call recipient PublicKeys to sign and
     * encrypt with.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Use encryptForUsers method instead.") // TODO change to actual methods signature
    internal fun encryptOld(inputStream: InputStream,
                            outputStream: OutputStream,
                            lookupResult: LookupResult) =
            encryptInternal(inputStream, outputStream, lookupResult.toPublicKeys())

    /**
     * Decrypts and verifies encrypted text that is in base64 [String] format.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param base64String Encrypted String.
     * @param sendersKey Sender PublicKey to verify with.
     *
     * @return Decrypted String.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Use decryptFromUser method instead.")
    internal fun decryptOld(base64String: String, sendersKey: VirgilPublicKey): String {
        val data = Data.fromBase64String(base64String) // TODO check exception type

        val decryptedData = decryptInternal(data, sendersKey)

        return String(decryptedData.data, StandardCharsets.UTF_8)
    }

    /**
     * Decrypts and verifies encrypted data.
     *
     * *Important* Requires private key in local storage.
     *
     * @param data Data to decrypt.
     * @param sendersKey Sender PublicKey to verify with.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Use decryptFromUser method instead.")
    internal fun decryptOld(data: ByteArray, sendersKey: VirgilPublicKey): ByteArray =
            decryptInternal(Data(data), sendersKey).data
}
