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

package com.android.virgilsecurity.ethreecoroutines.interaction

import android.content.Context
import com.android.virgilsecurity.common.exceptions.*
import com.android.virgilsecurity.ethreecoroutines.extensions.asyncWithCatch
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
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException
import com.virgilsecurity.sdk.exception.EmptyArgumentException
import com.virgilsecurity.sdk.jwt.Jwt
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.JsonKeyEntry
import com.virgilsecurity.sdk.storage.KeyStorage
import com.virgilsecurity.sdk.utils.ConvertionUtils
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import java.net.URL

/**
 * Created by:
 * Danylo Oliinyk
 * on
 * 10/8/18
 * at Virgil Security
 */

/**
 * [EThree] class simplifies work with Virgil Services to easily implement End to End Encrypted communication.
 */
class EThree
/**
 * @constructor Initializing [CardManager] with provided in [EThree.initialize] callback [getTokenCallback] using
 * [CachingJwtProvider] also initializing [DefaultKeyStorage] with default settings.
 */ private constructor(context: Context,
                        private val tokenProvider: AccessTokenProvider) {

    private val virgilCrypto = VirgilCrypto()
    private val cardManager: CardManager
    private val keyStorage: KeyStorage

    init {
        cardManager = VirgilCardCrypto().let { cardCrypto ->
            CardManager(cardCrypto,
                        tokenProvider,
                        VirgilCardVerifier(cardCrypto, false, false),
                        CardClient(VIRGIL_BASE_URL + VIRGIL_CARDS_SERVICE_PATH))
        }
        keyStorage = DefaultKeyStorage(context.filesDir.absolutePath, KEYSTORE_NAME)
    }

    /**
     * If called without [password] - loads existing private key from device if the user already has it
     * OR creates a new private key for the user, then publishes the public key in Virgil's Cards Service in case
     * no public key for current identity is published yet.
     *
     * If called with [password] - loads existing private key from the device if the user already has it.
     * If the private key was not found locally - attempts to load user's private key from Virgil's cloud storage.
     * If the user doesn't have neither the Card nor a private key yet, it creates a new key pair for the user,
     * stores private key, then publishes the public key in Virgil's Cards Service and backs up private key, to the
     * Virgil's cloud storage using the password specified. It is equivalent to [bootstrap] without password
     * following with [backupPrivateKey].
     */
    @JvmOverloads fun bootstrap(password: String? = null): Deferred<Unit> =
            GlobalScope.asyncWithCatch(
                    {
                        if (keyStorage.exists(currentIdentity())) {
                            if (!keyStorage.load(currentIdentity())
                                            .meta[LOCAL_KEY_IS_PUBLISHED]!!
                                            .toBoolean())
                                publishCardThenUpdateLocalKey(loadCurrentPrivateKey(),
                                                              loadCurrentPublicKey())
                        } else {
                            cardManager.searchCards(currentIdentity())
                                    .run {
                                        if (this.isNotEmpty())
                                            signIn(password)
                                        else
                                            signUp(password)
                                    }
                        }
                    },
                    {
                        if (it is DecryptionFailedException)
                            throw WrongPasswordException(
                                "Specified password is not valid.")
                        else
                            throw it
                    })

    /**
     * ! *WARNING* ! If you call this function after [bootstrap] and not use [backupPrivateKey]
     * then you loose private key permanently, as well you won't be able to use identity that was used
     * with that private key no more.
     *
     * Cleans up user's private key from a device - call this function when you want to log your user out of the device.
     *
     * Can be called only after [bootstrap] otherwise [NotBootstrappedException] exception will be thrown
     *
     * @throws [KeyEntryNotFoundException], [NotBootstrappedException]
     */
    fun cleanup() {
        checkIfBootstrappedOrThrow()

        keyStorage.delete(currentIdentity())
    }

    /**
     * Encrypts the user's private key using the user's [password] and backs up the encrypted private key to
     * Virgil's cloud. This enables users to log in from other devices and have access to their private key
     * to decrypt data.
     *
     * Encrypts loaded from private keys local storage user's *Private key* using *Public key* that is generated based
     * on provided [password] after that backs up encrypted user's *Private key* to the Virgil's cloud storage.
     *
     * Can be called only after [bootstrap] otherwise [NotBootstrappedException] exception will be returned
     */
    fun backupPrivateKey(password: String): Deferred<Unit> = GlobalScope.asyncWithCatch(
            {
                checkIfBootstrappedOrThrow()

                if (password.isBlank())
                    throw IllegalArgumentException("\'password\' should not be empty")

                initSyncKeyStorage(password)
                        .run {
                            (this to keyStorage.load(currentIdentity())).run {
                                this.first.store(currentIdentity() + KEYKNOX_KEY_POSTFIX,
                                                 this.second.value,
                                                 this.second.meta).let { Unit }
                            }
                        }
            },
            {
                if (it is KeychainEntryAlreadyExistsWhileStoringException)
                    throw BackupKeyException("Key with identity ${currentIdentity()} " +
                                                                                          "already backed up.")
                else
                    throw it
            })
// TODO check all docs
    /**
     * Deletes the user's private key from Virgil's cloud.
     *
     * Deletes private key backup using specified [password] and provides [onCompleteListener] callback that
     * will notify you with successful completion or with a [Throwable] if something went wrong.
     *
     * Can be called only after [bootstrap] otherwise [NotBootstrappedException] exception will be returned
     *
     * @throws [WrongPasswordException]
     */
    fun resetPrivateKeyBackup(password: String): Deferred<Unit> = GlobalScope.asyncWithCatch(
            {
                checkIfBootstrappedOrThrow()

                if (password.isBlank())
                    throw IllegalArgumentException("\'password\' should not be empty")

                initSyncKeyStorage(password).delete(currentIdentity() + KEYKNOX_KEY_POSTFIX)
            },
            {
                if (it is DecryptionFailedException)
                    throw WrongPasswordException("Specified password is not valid.")
                else
                    throw it
            })

    /**
     * Changes the password on a backed-up private key.
     *
     * Pulls user's private key from the Keyknox cloud storage, decrypts it with *Private key* that is generated based
     * on provided [oldPassword] after that encrypts user's *Private key* using *Public key* that is generated based
     * on provided [newPassword] and pushes encrypted user's *Private key* to the Keyknox cloud storage.
     *
     * Can be called only after [bootstrap] otherwise [NotBootstrappedException] exception will be returned
     */
    fun changePassword(oldPassword: String,
                       newPassword: String): Deferred<Unit> = GlobalScope.async {
        checkIfBootstrappedOrThrow()

        if (oldPassword.isBlank())
            throw IllegalArgumentException("\'oldPassword\' should not be empty")
        if (newPassword.isBlank())
            throw IllegalArgumentException("\'newPassword\' should not be empty")
        if (newPassword == oldPassword)
            throw IllegalArgumentException("\'newPassword\' can't be the same as the old one")

        val syncKeyStorageOld = initSyncKeyStorage(oldPassword)
        val brainKeyContext = BrainKeyContext.Builder()
                .setAccessTokenProvider(tokenProvider)
                .setPythiaClient(VirgilPythiaClient(VIRGIL_BASE_URL))
                .setPythiaCrypto(VirgilPythiaCrypto())
                .build()

        Thread.sleep(THROTTLE_TIMEOUT) // To avoid next request been throttled

        val keyPair = BrainKey(brainKeyContext).generateKeyPair(newPassword)
        syncKeyStorageOld.updateRecipients(listOf(keyPair.publicKey), keyPair.privateKey)
    }

    /**
     * Encrypts text messages for a group of users.
     *
     * Encrypts provided [text] using [publicKeys] list of recipients and returns encrypted message converted to
     * *base64* [String].
     *
     * Can be called only after [bootstrap] otherwise [NotBootstrappedException] exception will be thrown
     */
    @JvmOverloads fun encrypt(text: String, publicKeys: List<PublicKey>? = null): String {
        checkIfBootstrappedOrThrow()

        if (text.isBlank()) throw EmptyArgumentException("data")
        if (publicKeys?.isEmpty() == true) throw EmptyArgumentException("publicKeys")
        if (publicKeys?.contains(loadCurrentPublicKey()) == true)
            throw IllegalArgumentException("You should not include your own public key.")

        return encrypt(text.toByteArray(), publicKeys).let { ConvertionUtils.toBase64String(it) }
    }

    /**
     * Encrypts messages/other data for a group of users.
     *
     * Encrypts provided [data] using [publicKeys] list of recipients and returns encrypted data as [ByteArray].
     *
     * Can be called only after [bootstrap] otherwise [NotBootstrappedException] exception will be thrown
     */
    @JvmOverloads fun encrypt(data: ByteArray, publicKeys: List<PublicKey>? = null): ByteArray {
        checkIfBootstrappedOrThrow()

        if (data.isEmpty()) throw EmptyArgumentException("data")
        if (publicKeys?.isEmpty() == true) throw EmptyArgumentException("publicKeys")
        if (publicKeys?.contains(loadCurrentPublicKey()) == true)
            throw IllegalArgumentException("You should not include your own public key.")

        return (publicKeys == null).let { isNull ->
            (if (isNull) {
                listOf(loadCurrentPublicKey() as VirgilPublicKey)
            } else {
                publicKeys?.asSequence()?.filterIsInstance<VirgilPublicKey>()?.toMutableList()
                        ?.apply {
                            add(loadCurrentPublicKey() as VirgilPublicKey)
                        }
            })
        }.let { keys ->
            virgilCrypto.signThenEncrypt(data, loadCurrentPrivateKey() as VirgilPrivateKey, keys)
        }
    }

    /**
     * Decrypts encrypted text that is in base64 [String] format.
     *
     * Decrypts provided [base64String] (that was previously encrypted with [encrypt] function) using current user's
     * private key.
     *
     * Can be called only after [bootstrap] otherwise [NotBootstrappedException] exception will be thrown
     */
    @JvmOverloads fun decrypt(base64String: String, publicKeys: List<PublicKey>? = null): String {
        checkIfBootstrappedOrThrow()

        if (base64String.isBlank()) throw EmptyArgumentException("data")
        if (publicKeys?.isEmpty() == true) throw EmptyArgumentException("publicKeys")
        if (publicKeys?.contains(loadCurrentPublicKey()) == true)
            throw IllegalArgumentException("You should not include your own public key.")

        return String(decrypt(ConvertionUtils.base64ToBytes(base64String), publicKeys))
    }

    /**
     * Decrypts encrypted data.
     *
     * Decrypts provided [data] using current user's private key and returns decrypted data in [ByteArray].
     *
     * Can be called only after [bootstrap] otherwise [NotBootstrappedException] exception will be thrown
     */
    @JvmOverloads fun decrypt(data: ByteArray, publicKeys: List<PublicKey>? = null): ByteArray {
        checkIfBootstrappedOrThrow()

        if (data.isEmpty()) throw EmptyArgumentException("data")
        if (publicKeys?.isEmpty() == true) throw EmptyArgumentException("publicKeys")
        if (publicKeys?.contains(loadCurrentPublicKey()) == true)
            throw IllegalArgumentException("You should not include your own public key.")

        return (publicKeys == null).let { isNull ->
            (if (isNull) {
                listOf(loadCurrentPublicKey() as VirgilPublicKey)
            } else {
                publicKeys?.asSequence()?.filterIsInstance<VirgilPublicKey>()?.toMutableList()
                        ?.apply {
                            add(loadCurrentPublicKey() as VirgilPublicKey)
                        }
            })
        }.let { keys ->
            virgilCrypto.decryptThenVerify(
                    data,
                    loadCurrentPrivateKey() as VirgilPrivateKey,
                    keys
            )
        }
    }

    /**
     * Retrieves user public keys from the cloud for encryption/verification operations.
     *
     * Searches for public keys with specified [identities] and returns list of [PublicKey] in [onResultListener]
     * callback or [Throwable] if something went wrong. [PublicKeyNotFoundException] will be thrown for the first
     * not found public key.
     *
     * Can be called only after [bootstrap] otherwise [NotBootstrappedException] exception will be returned
     */
    fun lookupPublicKeys(identities: List<String>): Deferred<List<PublicKey>> = GlobalScope.async {
        checkIfBootstrappedOrThrow()

        if (identities.isEmpty()) throw EmptyArgumentException("identities")
        identities.groupingBy { it }.eachCount().filter { it.value > 1 }.run {
            if (this.isNotEmpty())
                throw PublicKeyDuplicateException("Duplicates are not allowed. " +
                                                                                               "Duplicated identities:\n${this}")
        }

        identities.map {
            cardManager.searchCards(it) to it
        }.map {
            it.first to it.second
        }.map {
            if (it.first.isNotEmpty())
                it.first.last().publicKey
            else
                throw PublicKeyNotFoundException(it.second)
        }
    }

    /**
     * If [password] provided - tries to restore private key from Virgil's cloud. Otherwise [InitException] is thrown.
     */
    private fun signIn(password: String?) {
        if (password != null)
            restoreKeyFromKeyknox(password)
        else
            throw InitException(
                "Private key is not found while Card exists. " +
                "Try to restore your private key using bootstrap with password."
            )
    }

    /**
     * If [password] is provided - tries to restore private key from Virgil's cloud otherwise publishes new key pair,
     * public key to Virgil Cards Service, private key encrypted with [password] to Virgil's cloud.
     *
     * If [password] is not provided - generates new key pair, public key is published to Virgil Cards Service,
     * private key is stored locally.
     */
    private fun signUp(password: String?) {
        if (password != null) {
            initSyncKeyStorage(password)
                    .run {
                        if (this.exists(currentIdentity() + KEYKNOX_KEY_POSTFIX)) {
                            this.retrieve(currentIdentity() + KEYKNOX_KEY_POSTFIX)
                                    .run {
                                        keyStorage.store(JsonKeyEntry(currentIdentity(),
                                                                      this.value).apply {
                                            meta = mapOf(LOCAL_KEY_IS_PUBLISHED to false.toString())
                                        })
                                        virgilCrypto.importPrivateKey(this.value).run {
                                            publishCardThenUpdateLocalKey(this,
                                                                          virgilCrypto.extractPublicKey(
                                                                                  this as VirgilPrivateKey))
                                        }
                                    }
                        } else {
                            (this to virgilCrypto.generateKeys()).run {
                                JsonKeyEntry(currentIdentity() + KEYKNOX_KEY_POSTFIX,
                                             this.second.privateKey.rawKey).also {
                                    this.first.store(listOf(it))
                                    keyStorage.store(it.apply {
                                        name = currentIdentity()
                                    }.apply {
                                        meta = mapOf(LOCAL_KEY_IS_PUBLISHED to false.toString())
                                    })
                                    publishCardThenUpdateLocalKey(this.second.privateKey,
                                                                  this.second.publicKey)
                                }
                            }
                        }
                    }
        } else {
            virgilCrypto.generateKeys().run {
                publishCard(this.privateKey, this.publicKey)
                keyStorage.store(JsonKeyEntry(currentIdentity(), this.privateKey.rawKey).apply {
                    meta = mapOf(LOCAL_KEY_IS_PUBLISHED to true.toString())
                })
            }
        }
    }

    /**
     * Loads and returns current user's [PrivateKey]. Current user's identity is taken from [tokenProvider].
     */
    private fun loadCurrentPrivateKey(): PrivateKey =
            keyStorage.load(currentIdentity()).let {
                virgilCrypto.importPrivateKey(it.value)
            }

    /**
     * Loads and returns current user's [PublicKey] that is extracted from current user's [PrivateKey].
     * Current user's identity is taken from [tokenProvider].
     */
    private fun loadCurrentPublicKey(): PublicKey =
            virgilCrypto.extractPublicKey(loadCurrentPrivateKey() as VirgilPrivateKey)

    /**
     * Publishes provided [publicKey] to the Virgil Cards Service and updates local current user's [PrivateKey]
     * with *LOCAL_KEY_IS_PUBLISHED = true*.
     */
    private fun publishCardThenUpdateLocalKey(privateKey: PrivateKey, publicKey: PublicKey) {
        publishCard(privateKey, publicKey)
        keyStorage.load(currentIdentity())
                .apply {
                    meta[LOCAL_KEY_IS_PUBLISHED] = true.toString()
                }.run {
                    keyStorage.update(this)
                }
    }

    /**
     * Asynchronously publishes [Card] that is generated with provided [privateKey], [publicKey]
     * and current user's identity that is taken from [tokenProvider].
     */
    private fun publishCard(privateKey: PrivateKey, publicKey: PublicKey): Card =
            cardManager.publishCard(privateKey, publicKey, currentIdentity())

    /**
     * Pulls user's private key from the Virgil's cloud, decrypts it with *Private key* that is generated based
     * on provided [password] and saves it to the current private keys local storage.
     */
    private fun restoreKeyFromKeyknox(password: String) =
            initSyncKeyStorage(password).run {
                if (this.exists(currentIdentity() + KEYKNOX_KEY_POSTFIX)) {
                    val keyEntry = this.retrieve(currentIdentity() + KEYKNOX_KEY_POSTFIX)

                    keyStorage.store(JsonKeyEntry(currentIdentity(), keyEntry.value).apply {
                        meta = mapOf(LOCAL_KEY_IS_PUBLISHED to true.toString())
                    })
                } else {
                    throw RestoreKeyException("There is no key backup with identity: ${currentIdentity()}")
                }
            }

    /**
     * Initializes [SyncKeyStorage] with default settings, [tokenProvider] and provided [password] after that returns
     * initialized [SyncKeyStorage] object.
     */
    private fun initSyncKeyStorage(password: String): SyncKeyStorage =
            BrainKeyContext.Builder()
                    .setAccessTokenProvider(tokenProvider)
                    .setPythiaClient(VirgilPythiaClient(VIRGIL_BASE_URL))
                    .setPythiaCrypto(VirgilPythiaCrypto())
                    .build().let {
                        BrainKey(it).generateKeyPair(password).let { keyPair ->
                            SyncKeyStorage(currentIdentity(),
                                           keyStorage,
                                           CloudKeyStorage(KeyknoxManager(
                                                   tokenProvider,
                                                   KeyknoxClient(URL(VIRGIL_BASE_URL)),
                                                   listOf(keyPair.publicKey),
                                                   keyPair.privateKey,
                                                   KeyknoxCrypto()))).also { syncKeyStorage ->
                                syncKeyStorage.sync()
                            }
                        }
                    }

    /**
     * Extracts current user's *Identity* from Json Web Token received from [tokenProvider].
     */
    private fun currentIdentity() = tokenProvider.getToken(NO_CONTEXT).identity

    private fun checkIfBootstrappedOrThrow() {
        if (!keyStorage.exists(currentIdentity())) throw NotBootstrappedException(
            "You have to call bootstrap() first.")
    }

    companion object {
        /**
         * Current method allows you to initialize EThree helper class. To do this you should provide
         * [onGetTokenCallback] that must return Json Web Token string representation with identity of the user which
         * will use this class. In [onResultListener] you will receive instance of [EThree] class or an [Throwable]
         * if something went wrong.
         */
        @JvmStatic fun initialize(context: Context,
                                  onGetToken: () -> String): Deferred<EThree> {
            val tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback {
                Jwt(onGetToken())
            })

            return GlobalScope.async {
                if (tokenProvider.getToken(NO_CONTEXT) != null)
                    EThree(context, tokenProvider)
                else
                    throw IllegalStateException("Token is null after successful parsing")
            }
        }


        private const val VIRGIL_BASE_URL = "https://api.virgilsecurity.com"
        private const val VIRGIL_CARDS_SERVICE_PATH = "/card/v5/"

        private const val KEYKNOX_KEY_POSTFIX = "_keyknox"
        private const val LOCAL_KEY_IS_PUBLISHED = "LOCAL_KEY_IS_PUBLISHED"
        private const val THROTTLE_TIMEOUT = 2 * 1000L // 2 seconds
        private const val KEYSTORE_NAME = "virgil.keystore"
        private val NO_CONTEXT = null
    }
}