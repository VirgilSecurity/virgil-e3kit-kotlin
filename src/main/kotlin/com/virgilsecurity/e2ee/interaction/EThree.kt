/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
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

package com.virgilsecurity.e2ee.interaction

import com.virgilsecurity.e2ee.data.exception.BackupKeyException
import com.virgilsecurity.e2ee.data.exception.InitException
import com.virgilsecurity.e2ee.data.exception.RestoreKeyException
import com.virgilsecurity.e2ee.data.exception.WrongPasswordException
import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.cloud.CloudKeyStorage
import com.virgilsecurity.keyknox.crypto.KeyknoxCrypto
import com.virgilsecurity.keyknox.exception.DecryptionFailedException
import com.virgilsecurity.keyknox.exception.KeychainEntryAlreadyExistsWhileStoringException
import com.virgilsecurity.keyknox.storage.SyncKeyStorage
import com.virgilsecurity.pythia.brainkey.BrainKey
import com.virgilsecurity.pythia.brainkey.BrainKeyContext
import com.virgilsecurity.pythia.client.VirgilPythiaClient
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.CardClient
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.exception.EmptyArgumentException
import com.virgilsecurity.sdk.jwt.Jwt
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.JsonKeyEntry
import com.virgilsecurity.sdk.storage.KeyStorage
import com.virgilsecurity.sdk.utils.ConvertionUtils
import java.lang.IllegalArgumentException
import java.net.URL
import java.util.concurrent.Callable

/**
 * Created by:
 * Danylo Oliinyk
 * on
 * 10/8/18
 * at Virgil Security
 */

/**
 * [EThree] class simplifies work with Virgil Services to easily implement End to End Encrypted communication.
 * In the @constructor you should provide [getTokenCallback] which must return Json Web Token with identity inside of the user,
 * which is currently active.
 */
class EThree
/**
 * @constructor Initializing [CardManager] with provided [getTokenCallback] using [CachingJwtProvider] as well initializing
 * [DefaultKeyStorage] with default settings.
 */ private constructor(private val tokenProvider: AccessTokenProvider) { // TODO add android version of sdk (key storage path ...)

    private val virgilCrypto = VirgilCrypto()
    private val cardManager: CardManager
    private val keyStorage: KeyStorage

    init {
        cardManager = VirgilCardCrypto().let { cardCrypto ->
            CardManager(cardCrypto,
                        tokenProvider,
                        VirgilCardVerifier(cardCrypto, false, false),
                        CardClient(VIRGIL_BASE_URL + VIRGIL_CARDS_SERVICE_PATH)) // FIXME remove dev url
        }
        keyStorage = DefaultKeyStorage()
    }

    /**
     * If called without [passwordBrainKey] - loads existing private key
     * from device if the user already has it OR creates a new private key for the user,
     * then publishes the public key in Virgil's cloud.
     *
     * If called with [passwordBrainKey] - loads existing private key from the device if the user already has it.
     * If the private key was not found locally - attempts to load user's private key from the cloud.
     * If the user doesn't have neither the Card nor a private key yet, it creates a new private key for the user,
     * then publishes the public key in Virgil's cloud and backup private key to the cloud,
     * using the password specified. Is equivalent to [bootstrap] without password -> [backupPrivateKey]
     */
    @JvmOverloads fun bootstrap(onCompleteListener: OnCompleteListener, passwordBrainKey: String? = null) {
        if (keyStorage.exists(currentIdentity())) {
            if (keyStorage.load(currentIdentity()).meta[LOCAL_KEY_IS_PUBLISHED]!!.toBoolean()) {
                onCompleteListener.onSuccess()
            } else {
                try {
                    publishCardThenUpdateLocalKey(loadCurrentPrivateKey(), loadCurrentPublicKey())
                    onCompleteListener.onSuccess()
                } catch (throwable: Throwable) {
                    onCompleteListener.onError(throwable)
                }
            }
        } else {
            try {
                searchCardsAsync(currentIdentity()).call()
                        .run {
                            if (this.isNotEmpty())
                                signIn(passwordBrainKey)
                            else
                                signUp(passwordBrainKey)

                            onCompleteListener.onSuccess()
                        }
            } catch (throwable: Throwable) {
                if (throwable is DecryptionFailedException)
                    onCompleteListener.onError(WrongPasswordException("Specified password is not valid."))
                else
                    onCompleteListener.onError(throwable)
            }
        }
    }

    private fun signIn(passwordBrainKey: String?) {
        if (passwordBrainKey != null)
            restoreKeyFromKeyknox(passwordBrainKey).call()
        else
            throw InitException("Private key is not found while Card exists. " +
                                        "Try to restore your private key using bootstrap with password.")
    }

    private fun signUp(passwordBrainKey: String?) {
        if (passwordBrainKey != null) {
            initSyncKeyStorage(passwordBrainKey).call()
                    .run {
                        if (this.exists(currentIdentity() + KEYKNOX_KEY_POSTFIX)) {
                            this.retrieve(currentIdentity() + KEYKNOX_KEY_POSTFIX)
                                    .run {
                                        keyStorage.store(JsonKeyEntry(currentIdentity(), this.value).apply {
                                            meta = mapOf(LOCAL_KEY_IS_PUBLISHED to false.toString())
                                        })
                                        virgilCrypto.importPrivateKey(this.value).run {
                                            publishCardThenUpdateLocalKey(this,
                                                                          virgilCrypto.extractPublicKey(this as VirgilPrivateKey))
                                        }
                                    }
                        } else {
                            (this to virgilCrypto.generateKeys()).run {
                                JsonKeyEntry(currentIdentity() + KEYKNOX_KEY_POSTFIX,
                                             this.second.privateKey.rawKey).also {
                                    Callable { this@run.first.store(listOf(it)) }.call()
                                    keyStorage.store(it.apply {
                                        name = currentIdentity()
                                    }.apply {
                                        meta = mapOf(LOCAL_KEY_IS_PUBLISHED to false.toString())
                                    })
                                    publishCardThenUpdateLocalKey(this.second.privateKey, this.second.publicKey)
                                }
                            }
                        }
                    }
        } else {
            virgilCrypto.generateKeys().run {
                publishCardAsync(this.privateKey, this.publicKey).call()
                keyStorage.store(JsonKeyEntry(currentIdentity(), this.privateKey.rawKey).apply {
                    meta = mapOf(LOCAL_KEY_IS_PUBLISHED to true.toString())
                })
            }
        }
    }

    private fun loadCurrentPrivateKey(): PrivateKey =
            keyStorage.load(currentIdentity()).let {
                virgilCrypto.importPrivateKey(it.value)
            }

    private fun loadCurrentPublicKey(): PublicKey =
            virgilCrypto.extractPublicKey(loadCurrentPrivateKey() as VirgilPrivateKey)

    private fun publishCardThenUpdateLocalKey(privateKey: PrivateKey, publicKey: PublicKey) {
        publishCardAsync(privateKey, publicKey).call()
        keyStorage.load(currentIdentity())
                .apply {
                    meta[LOCAL_KEY_IS_PUBLISHED] = true.toString()
                }.run {
                    keyStorage.update(this)
                }
    }

    private fun searchCardsAsync(identity: String): Callable<List<Card>> =
            Callable {
                cardManager.searchCards(identity)
            }

    private fun publishCardAsync(privateKey: PrivateKey, publicKey: PublicKey): Callable<Card> =
            Callable {
                cardManager.publishCard(privateKey, publicKey, currentIdentity())
            }

    /**
     * Pulls user's private key from the Keyknox cloud storage, decrypts it with *Private key* that is generated based
     * on provided [oldPassword] after that encrypts user's *Private key* using *Public key* that is generated based
     * on provided [newPassword] and pushes encrypted user's *Private key* to the Keyknox cloud storage.
     */
    fun changePassword(oldPassword: String,
                       newPassword: String,
                       onCompleteListener: OnCompleteListener) { // TODO check if old password is right
        Callable {
            try {
                val syncKeyStorageOld = initSyncKeyStorage(oldPassword).call()
                val brainKeyContext = BrainKeyContext.Builder()
                        .setAccessTokenProvider(tokenProvider)
                        .setPythiaClient(VirgilPythiaClient(VIRGIL_BASE_URL)) // FIXME remove dev url
                        .setPythiaCrypto(VirgilPythiaCrypto())
                        .build()

                Thread.sleep(THROTTLE_TIMEOUT) // To avoid next request been throttled

                val keyPair = BrainKey(brainKeyContext).generateKeyPair(newPassword)
                syncKeyStorageOld.updateRecipients(listOf(keyPair.publicKey), keyPair.privateKey)
                onCompleteListener.onSuccess()
            } catch (throwable: Throwable) {
                onCompleteListener.onError(throwable)
            }
        }.call()
    }

    /**
     * Encrypts loaded from private keys local storage user's *Private key* using *Public key* that is generated based
     * on provided [passwordBrainKey] after that pushes encrypted user's *Private key* to the Keyknox cloud storage.
     */
    fun backupPrivateKey(passwordBrainKey: String, onCompleteListener: OnCompleteListener) { // TODO add check for bootstrap everywhere
        Callable {
            try {
                initSyncKeyStorage(passwordBrainKey).call()
                        .run {
                            (this to keyStorage.load(currentIdentity())).run {
                                this.first.store(currentIdentity() + KEYKNOX_KEY_POSTFIX,
                                                 this.second.value,
                                                 this.second.meta)
                                onCompleteListener.onSuccess()
                            }
                        }
            } catch (throwable: Throwable) {
                if (throwable is KeychainEntryAlreadyExistsWhileStoringException)
                    onCompleteListener.onError(BackupKeyException("Key with identity ${currentIdentity()} " +
                                                                          "already backuped."))
                    else
                onCompleteListener.onError(throwable)
            }
        }.call()
    }

    fun lookupPublicKeys(identities: List<String>,
                         onResultListener: OnResultListener<List<PublicKey>>) {
        if (identities.isEmpty()) {
            onResultListener.onError(EmptyArgumentException("identities"))
            return
        }

        Callable {
            try {
                identities.map {
                    searchCardsAsync(it)
                }.map {
                    it.call()
                }.map {
                    it.last().publicKey
                }.run {
                    onResultListener.onSuccess(this)
                }
            } catch (throwable: Throwable) {
                onResultListener.onError(throwable)
            }
        }.call()
    }

    /**
     * Pulls user's private key from the Keyknox cloud storage, decrypts it with *Private key* that is generated based
     * on provided [passwordBrainKey] and saves it to the current private keys local storage.
     */
    private fun restoreKeyFromKeyknox(passwordBrainKey: String): Callable<Unit> =
            Callable {
                initSyncKeyStorage(passwordBrainKey).call().run {
                    if (this.exists(currentIdentity() + KEYKNOX_KEY_POSTFIX)) {
                        val keyEntry = this.retrieve(currentIdentity() + KEYKNOX_KEY_POSTFIX)

                        keyStorage.store(JsonKeyEntry(currentIdentity(), keyEntry.value).apply {
                            meta = mapOf(LOCAL_KEY_IS_PUBLISHED to true.toString())
                        })
                    } else {
                        throw RestoreKeyException("There is no key backup with identity: ${currentIdentity()}")
                    }
                }
            }

    // FIXME rework description
    /**
     * Encrypts provided [data] using [sessionPublicKeys] list with public keys to encrypt for.
     * [encrypt] function can only be used within the session. So you have to call [startSession] first.
     */
    @JvmOverloads fun encrypt(text: String, publicKeys: List<PublicKey>? = null): String {
        if (publicKeys?.isEmpty() == true)
            throw EmptyArgumentException("publicKeys")

        if (publicKeys?.contains(loadCurrentPublicKey()) == true)
            throw IllegalArgumentException("You should not include your own public key.")

        return (publicKeys == null).let { isNull ->
            (if (isNull) {
                listOf(loadCurrentPublicKey() as VirgilPublicKey)
            } else {
                publicKeys?.asSequence()?.filterIsInstance<VirgilPublicKey>()?.toMutableList()?.apply {
                    add(loadCurrentPublicKey() as VirgilPublicKey)
                }
            })
        }.let { keys ->
            virgilCrypto.signThenEncrypt(text.toByteArray(), loadCurrentPrivateKey() as VirgilPrivateKey, keys)
                    .let { ConvertionUtils.toBase64String(it) }
        }
    }

// FIXME rework description
    /**
     * Encrypts provided [data] using [sessionPublicKeys] list with public keys to encrypt for.
     * [encrypt] function can only be used within the session. So you have to call [startSession] first.
     */
    fun encrypt(data: ByteArray, publicKeys: List<PublicKey>? = null): ByteArray {
        if (publicKeys?.isEmpty() == true)
            throw EmptyArgumentException("publicKeys")

        if (publicKeys?.contains(loadCurrentPublicKey()) == true)
            throw IllegalArgumentException("You should not include your own public key.")

        return (publicKeys == null).let { isNull ->
            (if (isNull) {
                listOf(loadCurrentPublicKey() as VirgilPublicKey)
            } else {
                publicKeys?.asSequence()?.filterIsInstance<VirgilPublicKey>()?.toMutableList()?.apply {
                    add(loadCurrentPublicKey() as VirgilPublicKey)
                }
            })
        }.let { keys ->
            virgilCrypto.signThenEncrypt(data, loadCurrentPrivateKey() as VirgilPrivateKey, keys)
        }
    }

// FIXME rework description
    /**
     * Decrypts provided [data] (that was previously encrypted with [encrypt] function) using current user's private key.
     * [decrypt] function can only be used within the session. So you have to call [startSession] first.
     */
    fun decrypt(base64String: String, publicKeys: List<PublicKey>? = null): String {
        if (publicKeys?.isEmpty() == true)
            throw EmptyArgumentException("publicKeys")

        if (publicKeys?.contains(loadCurrentPublicKey()) == true)
            throw IllegalArgumentException("You should not include your own public key.")

        return String((publicKeys == null).let { isNull ->
            (if (isNull) {
                listOf(loadCurrentPublicKey() as VirgilPublicKey)
            } else {
                publicKeys?.asSequence()?.filterIsInstance<VirgilPublicKey>()?.toMutableList()?.apply {
                    add(loadCurrentPublicKey() as VirgilPublicKey)
                }
            })
        }.let { keys ->
            virgilCrypto.decryptThenVerify(ConvertionUtils.base64ToBytes(base64String),
                                           loadCurrentPrivateKey() as VirgilPrivateKey,
                                           keys)
        })
    }

    fun cleanup() {
        keyStorage.delete(currentIdentity())
    }

    fun rollbackPrivateKey(passwordBrainKey: String, onCompleteListener: OnCompleteListener) {
        try {
            initSyncKeyStorage(passwordBrainKey).call().delete(currentIdentity() + KEYKNOX_KEY_POSTFIX)
            onCompleteListener.onSuccess()
        } catch (throwable: Throwable) {
            onCompleteListener.onError(throwable)
        }
    }

// FIXME rework description
    /**
     * Decrypts provided [data] (that was previously encrypted with [encrypt] function) using current user's private key.
     * [decrypt] function can only be used within the session. So you have to call [startSession] first.
     */
    fun decrypt(data: ByteArray, publicKeys: List<PublicKey>? = null): ByteArray {
        if (publicKeys?.isEmpty() == true)
            throw EmptyArgumentException("publicKeys")

        if (publicKeys?.contains(loadCurrentPublicKey()) == true)
            throw IllegalArgumentException("You should not include your own public key.")

        return (publicKeys == null).let { isNull ->
            (if (isNull) {
                listOf(loadCurrentPublicKey() as VirgilPublicKey)
            } else {
                publicKeys?.asSequence()?.filterIsInstance<VirgilPublicKey>()?.toMutableList()?.apply {
                    add(loadCurrentPublicKey() as VirgilPublicKey)
                }
            })
        }.let { keys ->
            virgilCrypto.decryptThenVerify(data,
                                           loadCurrentPrivateKey() as VirgilPrivateKey,
                                           keys)
        }
    }

    /**
     * Initializes [SyncKeyStorage] with default settings and provided [getTokenCallback] after that returns
     * initialized [SyncKeyStorage] object.
     */
    private fun initSyncKeyStorage(passwordBrainKey: String): Callable<SyncKeyStorage> =
            Callable {
                val brainKeyContext = BrainKeyContext.Builder()
                        .setAccessTokenProvider(tokenProvider)
                        .setPythiaClient(VirgilPythiaClient(VIRGIL_BASE_URL)) // FIXME remove dev url
                        .setPythiaCrypto(VirgilPythiaCrypto())
                        .build()
                val keyPair = BrainKey(brainKeyContext).generateKeyPair(passwordBrainKey)

                val syncKeyStorage = SyncKeyStorage(currentIdentity(), CloudKeyStorage(
                        KeyknoxManager(tokenProvider,
                                       KeyknoxClient(URL(VIRGIL_BASE_URL)), // FIXME remove dev url
                                       listOf(keyPair.publicKey),
                                       keyPair.privateKey,
                                       KeyknoxCrypto())))

                syncKeyStorage.sync()

                syncKeyStorage
            }

    /**
     * Extracts current user's *Identity* from Json Web Token that is parsed from provided [getTokenCallback].
     */
    private fun currentIdentity() = tokenProvider.getToken(null).identity

    interface OnGetTokenCallback {

        fun onGetToken(): String
    }

    interface OnCompleteListener {

        fun onSuccess()

        fun onError(throwable: Throwable)
    }

    interface OnResultListener<T> {

        fun onSuccess(result: T)

        fun onError(throwable: Throwable)
    }

    companion object {
        @JvmStatic fun initialize(onGetTokenCallback: OnGetTokenCallback, onResultListener: OnResultListener<EThree>) {
            try {
                val tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback { _ ->
                    Jwt(onGetTokenCallback.onGetToken())
                })
                if (tokenProvider.getToken(null) != null) // TODO test if getToken returns null or empty string etc
                    onResultListener.onSuccess(EThree(tokenProvider))
            } catch (throwable: Throwable) {
                onResultListener.onError(throwable)
            }
        }

        private const val VIRGIL_BASE_URL = "https://api.virgilsecurity.com"
        private const val VIRGIL_CARDS_SERVICE_PATH = "/card/v5/"

        private const val KEYKNOX_KEY_POSTFIX = "_keyknox"
        private const val LOCAL_KEY_IS_PUBLISHED = "LOCAL_KEY_IS_PUBLISHED"
        const val THROTTLE_TIMEOUT = 2 * 1000L // 2 seconds
    }
}