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

package com.virgilsecurity.android.common

import com.virgilsecurity.android.common.util.Const.NO_CONTEXT
import com.virgilsecurity.android.common.util.Const.VIRGIL_BASE_URL
import com.virgilsecurity.android.common.util.Const.VIRGIL_CARDS_SERVICE_PATH
import com.virgilsecurity.android.common.exception.*
import com.virgilsecurity.android.common.storage.cloud.KeyManagerCloud
import com.virgilsecurity.android.common.storage.local.KeyStorageLocal
import com.virgilsecurity.android.common.model.LookupResult
import com.virgilsecurity.android.common.util.Const
import com.virgilsecurity.android.common.worker.AuthorizationWorker
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.keyknox.build.VersionVirgilAgent
import com.virgilsecurity.keyknox.exception.DecryptionFailedException
import com.virgilsecurity.keyknox.exception.EntryAlreadyExistsException
import com.virgilsecurity.pythia.brainkey.BrainKey
import com.virgilsecurity.pythia.brainkey.BrainKeyContext
import com.virgilsecurity.pythia.client.VirgilPythiaClient
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.HttpClient
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.exception.EmptyArgumentException
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.utils.ConvertionUtils
import java.io.InputStream
import java.io.OutputStream

/**
 * [EThreeCore] class simplifies work with Virgil Services to easily implement End to End Encrypted
 * communication.
 */
abstract class EThreeCore
/**
 * @constructor Initializing [CardManager] with provided in [EThreeCore.initialize] callback
 * [onGetTokenCallback] using [CachingJwtProvider] also initializing [DefaultKeyStorage] with
 * default settings.
 */
constructor(private val tokenProvider: AccessTokenProvider) {

    private val virgilCrypto = VirgilCrypto()
    private val cardManager: CardManager
    protected abstract val keyStorageLocal: KeyStorageLocal
    private val keyManagerCloud: KeyManagerCloud
    private val authorizationWorker: AuthorizationWorker

    init {
        cardManager = VirgilCardCrypto().let { cardCrypto ->
            val httpClient = HttpClient(Const.ETHREE_NAME, VersionVirgilAgent.VERSION)
            CardManager(cardCrypto,
                        tokenProvider,
                        VirgilCardVerifier(cardCrypto, false, false),
                        VirgilCardClient(VIRGIL_BASE_URL + VIRGIL_CARDS_SERVICE_PATH,
                                         httpClient))
        }

        keyManagerCloud = KeyManagerCloud(
            currentIdentity(),
            tokenProvider,
            VersionVirgilAgent.VERSION)

        authorizationWorker = AuthorizationWorker()
    }

    /**
     * Publishes the public key in Virgil's Cards Service in case no public key for current
     * identity is published yet. Otherwise [RegistrationException] will be thrown.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws RegistrationException
     * @throws CryptoException
     */
    @Synchronized fun register() = authorizationWorker.register()

    /**
     * Revokes the public key for current *identity* in Virgil's Cards Service. After this operation
     * you can call [EThreeCore.register] again.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws UnRegistrationException if there's no public key published yet, or if there's more
     * than one public key is published.
     */
    @Synchronized fun unregister() = authorizationWorker.unregister()

    /**
     * Generates new key pair, publishes new public key for current identity and deprecating old
     * public key, saves private key to the local storage. All data that was encrypted earlier
     * will become undecryptable.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws PrivateKeyExistsException
     * @throws CardNotFoundException
     * @throws CryptoException
     */
    @Synchronized fun rotatePrivateKey() = authorizationWorker.rotatePrivateKey()

    /**
     * Checks whether the private key is present in the local storage of current device.
     * Returns *true* if the key is present in the local key storage otherwise *false*.
     */
    fun hasLocalPrivateKey() = authorizationWorker.hasLocalPrivateKey()

    /**
     * ! *WARNING* ! If you call this function after [register] without using [backupPrivateKey]
     * then you loose private key permanently, as well you won't be able to use identity that
     * was used with that private key no more.
     *
     * Cleans up user's private key from a device - call this function when you want to log your
     * user out of the device.
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * @throws PrivateKeyNotFoundException
     */
    fun cleanup() = authorizationWorker.cleanup()









    /**
     * Signs then encrypts text for a group of users.
     *
     * Signs then encrypts provided [text] using [lookupResult] with recipients public keys and
     * returns encrypted message converted to *base64* [String].
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @JvmOverloads fun encrypt(text: String, lookupResult: LookupResult? = null): String {
        checkPrivateKeyOrThrow()

        if (text.isBlank()) throw EmptyArgumentException("text")
        if (lookupResult?.isEmpty() == true) throw EmptyArgumentException("publicKeys")
        if (lookupResult?.values?.contains(loadCurrentPublicKey()) == true)
            throw IllegalArgumentException("You should not include your own public key.")

        return signThenEncryptData(text.toByteArray(), lookupResult).let {
            ConvertionUtils.toBase64String(it)
        }
    }

    /**
     * Signs then encrypts text/other data for a group of users.
     *
     * Signs then encrypts provided [data] using [publicKeys] list of recipients and returns
     * encrypted data as [ByteArray].
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @JvmOverloads fun encrypt(data: ByteArray, lookupResult: LookupResult? = null): ByteArray {
        checkPrivateKeyOrThrow()

        if (data.isEmpty()) throw EmptyArgumentException("data")
        if (lookupResult?.isEmpty() == true) throw EmptyArgumentException("publicKeys")
        if (lookupResult?.values?.contains(loadCurrentPublicKey()) == true)
            throw IllegalArgumentException("You should not include your own public key.")

        return signThenEncryptData(data, lookupResult)
    }

    /**
     * Encrypts Input Stream for a group of users.
     *
     * Encrypts provided [inputStream] using [publicKeys] list of recipients and returns it
     * encrypted in the [outputStream].
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @JvmOverloads fun encrypt(inputStream: InputStream,
                              outputStream: OutputStream,
                              lookupResult: LookupResult? = null) {
        checkPrivateKeyOrThrow()

        if (inputStream.available() == 0) throw EmptyArgumentException("inputStream")
        if (lookupResult?.values?.contains(loadCurrentPublicKey()) == true)
            throw IllegalArgumentException("You should not include your own public key.")

        (lookupResult?.values?.toMutableList()?.apply { add(loadCurrentPublicKey()) }
         ?: listOf(loadCurrentPublicKey())).run {
            virgilCrypto.encrypt(inputStream, outputStream, this)
        }
    }

    /**
     * Signs then encrypts text/other data for a group of users.
     *
     * Signs then encrypts provided [data] using [publicKeys] list of recipients and returns
     * encrypted data as [ByteArray].
     *
     * @throws CryptoException
     */
    private fun signThenEncryptData(data: ByteArray,
                                    lookupResult: LookupResult? = null): ByteArray =
            (lookupResult?.values?.toMutableList()?.apply { add(loadCurrentPublicKey()) }
             ?: listOf(loadCurrentPublicKey())).run {
                virgilCrypto.signThenEncrypt(data, loadCurrentPrivateKey(), this)
            }

    /**
     * Decrypts then verifies encrypted text that is in base64 [String] format.
     *
     * Decrypts provided [base64String] (that was previously encrypted with [encrypt] function)
     * using current user's private key.
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @JvmOverloads fun decrypt(base64String: String, sendersKey: VirgilPublicKey? = null): String {
        checkPrivateKeyOrThrow()

        if (base64String.isBlank()) throw EmptyArgumentException("data")
        if (sendersKey == loadCurrentPublicKey())
            throw IllegalArgumentException("You should not provide your own public key.")

        return String(decryptAndVerifyData(ConvertionUtils.base64ToBytes(base64String), sendersKey))
    }

    /**
     * Decrypts then verifies encrypted data.
     *
     * Decrypts provided [data] using current user's private key then verifies that data was
     * encrypted by sender with her [sendersKey] and returns decrypted data in [ByteArray].
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @JvmOverloads fun decrypt(data: ByteArray, sendersKey: VirgilPublicKey? = null): ByteArray {
        checkPrivateKeyOrThrow()

        if (data.isEmpty()) throw EmptyArgumentException("data")
        if (sendersKey == loadCurrentPublicKey())
            throw IllegalArgumentException("You should not provide your own public key.")

        return decryptAndVerifyData(data, sendersKey)
    }

    /**
     * Decrypts encrypted inputStream.
     *
     * Decrypts provided [inputStream] using current user's private key and returns decrypted data
     * in the [outputStream].
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    fun decrypt(inputStream: InputStream,
                outputStream: OutputStream) {
        checkPrivateKeyOrThrow()

        if (inputStream.available() == 0) throw EmptyArgumentException("inputStream")

        return virgilCrypto.decrypt(inputStream, outputStream, loadCurrentPrivateKey())
    }

    /**
     * Decrypts then verifies encrypted data.
     *
     * Decrypts provided [data] using current user's private key then verifies that data was
     * encrypted by sender with her [sendersKey] and returns decrypted data in [ByteArray].
     *
     * @throws CryptoException
     */
    private fun decryptAndVerifyData(data: ByteArray,
                                     sendersKey: VirgilPublicKey? = null): ByteArray =
            (sendersKey == null).let { isNull ->
                (if (isNull) {
                    listOf(loadCurrentPublicKey())
                } else {
                    mutableListOf(sendersKey as VirgilPublicKey).apply {
                        add(loadCurrentPublicKey())
                    }
                })
            }.let { keys ->
                virgilCrypto.decryptThenVerify(
                    data,
                    loadCurrentPrivateKey(),
                    keys
                )
            }



    /**
     * Loads and returns current user's [PrivateKey]. Current user's identity is taken
     * from [tokenProvider].
     */
    private fun loadCurrentPrivateKey(): VirgilPrivateKey =
            keyStorageLocal.load().let {
                virgilCrypto.importPrivateKey(it.value).privateKey
            }

    /**
     * Loads and returns current user's [PublicKey] that is extracted from current
     * user's [PrivateKey]. Current user's identity is taken from [tokenProvider].
     */
    private fun loadCurrentPublicKey(): VirgilPublicKey =
            virgilCrypto.extractPublicKey(loadCurrentPrivateKey())

    /**
     * Extracts current user's *Identity* from Json Web Token received from [tokenProvider].
     */
    private fun currentIdentity() = tokenProvider.getToken(NO_CONTEXT).identity

    /**
     * Checks if private key for current identity is present in local key storage or throws an
     * [PrivateKeyNotFoundException] exception.
     */
    private fun checkPrivateKeyOrThrow() {
        if (!keyStorageLocal.exists()) throw PrivateKeyNotFoundException(
            "You have to get private key first. Use \'register\' " +
            "or \'restorePrivateKey\' functions.")
    }

    companion object {
        private const val THROTTLE_TIMEOUT = 2 * 1000L // 2 seconds
    }
}
