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

import com.virgilsecurity.e2ee.data.exception.InitException
import com.virgilsecurity.e2ee.data.exception.RestoreKeyException
import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.cloud.CloudKeyStorage
import com.virgilsecurity.keyknox.crypto.KeyknoxCrypto
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
import com.virgilsecurity.sdk.jwt.Jwt
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.JsonKeyEntry
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
class EThree(private val onGetTokenCallback: OnGetTokenCallback) { // TODO add android version of sdk (key storage path ...)

    private val virgilCrypto = VirgilCrypto()
    private val cardManager: CardManager
    private val keyStorage: DefaultKeyStorage
    private val tokenProvider: AccessTokenProvider

    /**
     * Initializing [CardManager] with provided [getTokenCallback] using [CachingJwtProvider] as well initializing
     * [DefaultKeyStorage] with default settings.
     */
    init {
        tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback { _ ->
            Jwt(onGetTokenCallback.onGetToken())
        })
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
     * using the password specified. Is equivalent to [bootstrap] without password -> [backupUserKey]
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
                            this.retrieve(currentIdentity())
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
                                JsonKeyEntry(currentIdentity(), this.second.privateKey.rawKey).apply {
                                    meta = mapOf(LOCAL_KEY_IS_PUBLISHED to false.toString())
                                }.also {
                                    Callable { this@run.first.store(listOf(it)) }.call()
                                    publishCardAsync(this.second.privateKey, this.second.publicKey).call()
                                    keyStorage.store(it)
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
    fun changeKeyknoxPassword(oldPassword: String,
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
                val keyPair = BrainKey(brainKeyContext).generateKeyPair(newPassword)
                syncKeyStorageOld.updateRecipients(listOf(keyPair.publicKey), keyPair.privateKey)
                onCompleteListener.onSuccess()
            } catch (throwable: Throwable) {
                onCompleteListener.onError(throwable)
            }
        }
    }

    /**
     * Encrypts loaded from private keys local storage user's *Private key* using *Public key* that is generated based
     * on provided [passwordBrainKey] after that pushes encrypted user's *Private key* to the Keyknox cloud storage.
     */
    fun backupUserKey(passwordBrainKey: String, onCompleteListener: OnCompleteListener) {
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
                onCompleteListener.onError(throwable)
            }
        }
    }

    fun lookupPublicKeys(identities: List<String>,
                         onResultListener: OnResultListener<List<PublicKey>>) {
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
        }
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
    fun encrypt(data: ByteArray, publicKeys: List<PublicKey>): ByteArray {
        return virgilCrypto.signThenEncrypt(data,
                                            loadCurrentPrivateKey() as VirgilPrivateKey,
                                            publicKeys.asSequence()
                                                    .filterIsInstance<VirgilPublicKey>()
                                                    .toMutableList()
                                                    .apply {
                                                        add(loadCurrentPublicKey() as VirgilPublicKey)
                                                    })
    }

    // FIXME rework description
    /**
     * Decrypts provided [data] (that was previously encrypted with [encrypt] function) using current user's private key.
     * [decrypt] function can only be used within the session. So you have to call [startSession] first.
     */
    fun decrypt(data: ByteArray, publicKeys: List<PublicKey>): ByteArray {
        return virgilCrypto.decryptThenVerify(data,
                                              loadCurrentPrivateKey() as VirgilPrivateKey,
                                              publicKeys.asSequence()
                                                      .filterIsInstance<VirgilPublicKey>()
                                                      .toMutableList()
                                                      .apply {
                                                          add(loadCurrentPublicKey() as VirgilPublicKey)
                                                      })
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

                val syncKeyStorage =
                        SyncKeyStorage(currentIdentity(), CloudKeyStorage(
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
    private fun currentIdentity() = Jwt(onGetTokenCallback.onGetToken()).identity

    interface OnGetTokenCallback {

        fun onGetToken(): String
    }

    interface OnCompleteListener {

        fun onError(throwable: Throwable)

        fun onSuccess()
    }

    interface OnResultListener<T> {

        fun onError(throwable: Throwable)

        fun onSuccess(result: T)
    }

    companion object {
        const val VIRGIL_BASE_URL = "https://api-dev.virgilsecurity.com"
        const val VIRGIL_CARDS_SERVICE_PATH = "/card/v5/"

        const val KEYKNOX_KEY_POSTFIX = "_keyknox"
        const val LOCAL_KEY_IS_PUBLISHED = "LOCAL_KEY_IS_PUBLISHED"
    }
}