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
import com.virgilsecurity.e2ee.data.exception.SessionException
import com.virgilsecurity.keyknox.storage.SyncKeyStorage
import com.virgilsecurity.pythia.brainkey.BrainKey
import com.virgilsecurity.pythia.brainkey.BrainKeyContext
import com.virgilsecurity.pythia.client.VirgilPythiaClient
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.jwt.Jwt
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.storage.JsonFileKeyStorage
import com.virgilsecurity.sdk.storage.PrivateKeyStorage

/**
 * Created by:
 * Danylo Oliinyk
 * on
 * 10/8/18
 * at Virgil Security
 */

/**
 * [EndToEndEncryption] class simplifies work with Virgil Services to easily implement End to End Encrypted communication.
 * In the @constructor you should provide [getTokenCallback] which must return Json Web Token with identity inside of the user,
 * which is currently active.
 */
class EndToEndEncryption(private val getTokenCallback: () -> String) { // TODO add android version of sdk (key storage path ...)

    private val virgilCrypto = VirgilCrypto()
    private val cardManager: CardManager
    private val keyStorage: PrivateKeyStorage

    private var sessionPublicKeys: MutableList<VirgilPublicKey> = mutableListOf()

    /**
     * Initializing [CardManager] with provided [getTokenCallback] using [CachingJwtProvider] and
     * [PrivateKeyStorage] with default settings.
     */
    init {
        cardManager = VirgilCardCrypto().let { cardCrypto ->
            CardManager(cardCrypto, CachingJwtProvider(CachingJwtProvider.RenewJwtCallback { _ ->
                Jwt(getTokenCallback())
            }), VirgilCardVerifier(cardCrypto))
        }
        keyStorage = PrivateKeyStorage(VirgilPrivateKeyExporter(), JsonFileKeyStorage())
    }

    /**
     * Creates a new private key for the user, then publishes the public key in Virgil's cloud OR
     * Loads existing private key from device if the user already has it.
     */
    fun initUser() {
        cardManager.searchCards(currentIdentity()).run {
            if (this.isNotEmpty()) {
                if (keyStorage.exists(currentIdentity()))
                    addToSessionCurrentUserPublicKey()
                else
                    throw InitException("Private key in not found while Card exists. " +
                                                "Probably you have to restore your private key.")
            } else {
                val keyPair = virgilCrypto.generateKeys()
                cardManager.publishCard(keyPair.privateKey, keyPair.publicKey, currentIdentity())
                keyStorage.store(keyPair.privateKey, currentIdentity(), null)
                sessionPublicKeys.add(keyPair.publicKey)
            }
        }
    }

    /**
     * Attempts to load user's private key from the cloud. If the user doesn't have a private key yet, it creates one
     * and backs it up to the cloud, using the password specified. Is equivalent to [initUser] -> [backupUserKey]
     */
    fun initAndSyncUser(passwordBrainKey: String) {
        cardManager.searchCards(currentIdentity()).run {
            if (this.isNotEmpty()) {
                if (keyStorage.exists(currentIdentity())) {
                    addToSessionCurrentUserPublicKey()
                } else {
                    try {
                        restoreUserKey(passwordBrainKey)
                    } catch (e: RestoreKeyException) {
                        throw InitException("Private key is neither present in local storage nor the cloud storage.")
                    }
                }
            } else {
                val keyPair = virgilCrypto.generateKeys()
                cardManager.publishCard(keyPair.privateKey, keyPair.publicKey, currentIdentity())
                keyStorage.store(keyPair.privateKey, currentIdentity(), null)
                backupUserKey(passwordBrainKey)
                sessionPublicKeys.add(keyPair.publicKey)
            }
        }
    }

    /**
     * Deletes user's *Private key* from the private keys local storage and from the Keyknox cloud storage.
     */
    fun resetUser(passwordBrainKey: String) {
        keyStorage.delete(currentIdentity())
        initSyncKeyStorage(passwordBrainKey).run {
            this.delete(currentIdentity())
        }
    }

    /**
     * Pulls user's private key from the Keyknox cloud storage, decrypts it with *Private key* that is generated based
     * on provided [oldPassword] after that encrypts user's *Private key* using *Public key* that is generated based
     * on provided [newPassword] and pushes encrypted user's *Private key* to the Keyknox cloud storage.
     */
    fun changeKeyknoxPassword(oldPassword: String, newPassword: String) { // TODO check if old password is right
        val syncKeyStorageOld = initSyncKeyStorage(oldPassword)
        val keyEntry = syncKeyStorageOld.retrieve(currentIdentity() + KEYKNOX_KEY_POSTFIX)
        syncKeyStorageOld.delete(currentIdentity() + KEYKNOX_KEY_POSTFIX)

        val syncKeyStorageNew = initSyncKeyStorage(newPassword)
        syncKeyStorageNew.store(listOf(keyEntry))
    }

    /**
     * Encrypts loaded from private keys local storage user's *Private key* using *Public key* that is generated based
     * on provided [passwordBrainKey] after that pushes encrypted user's *Private key* to the Keyknox cloud storage.
     */
    fun backupUserKey(passwordBrainKey: String) {
        initSyncKeyStorage(passwordBrainKey).run {
            this.store(currentIdentity() + KEYKNOX_KEY_POSTFIX,
                       (keyStorage.load(currentIdentity()).left as VirgilPrivateKey).rawKey,
                       keyStorage.load(currentIdentity()).right)
        }
    }

    /**
     * Pulls user's private key from the Keyknox cloud storage, decrypts it with *Private key* that is generated based
     * on provided [passwordBrainKey] and saves it to the current private keys local storage.
     */
    fun restoreUserKey(passwordBrainKey: String) {
        initSyncKeyStorage(passwordBrainKey).run {
            if (this.exists(currentIdentity())) {
                val keyEntry = this.retrieve(currentIdentity() + KEYKNOX_KEY_POSTFIX)
                val restoredPrivateKey = virgilCrypto.importPrivateKey(keyEntry.value)
                keyStorage.store(restoredPrivateKey, currentIdentity(), keyEntry.meta)
            } else {
                throw RestoreKeyException()
            }
        }
    }

    /**
     * Encrypts provided [data] using [sessionPublicKeys] list with public keys to encrypt for.
     * [encrypt] function can only be used within the session. So you have to call [startSession] first.
     */
    fun encrypt(data: ByteArray): ByteArray {
        if (sessionPublicKeys.size > 1) {
            return virgilCrypto.encrypt(data, sessionPublicKeys)
        } else {
            throw SessionException("Please, start session first with " +
                                           "\"startSession(identities: List<String>)\" function.")
        }
    }

    /**
     * Decrypts provided [data] (that was previously encrypted with [encrypt] function) using current user's private key.
     * [decrypt] function can only be used within the session. So you have to call [startSession] first.
     */
    fun decrypt(data: ByteArray): ByteArray {
        if (sessionPublicKeys.size > 1) {
            return virgilCrypto.decrypt(data, keyStorage.load(currentIdentity()).left as VirgilPrivateKey)
        } else {
            throw SessionException("Please, start session first with " +
                                           "\"startSession(interlocutors: List<String>)\" function.")
        }
    }

    /**
     * Starts session within which you can encrypt and decrypt data from/to interlocutors specified in [interlocutors]
     * argument. List of [interlocutors] can't be empty. Session can run in only one instance, so you have to
     * call [stopSession] function in the end of the session to start another session.
     */
    fun startSession(interlocutors: List<String>) {
        if (interlocutors.isEmpty())
            throw SessionException("Please, pass at least one interlocutor to \'startSession\' function")

        if (sessionPublicKeys.size > 1)
            throw SessionException("Please, stop session first with \"stopSession()\" function.")

        interlocutors.forEach { identity ->
            cardManager.searchCards(identity).run {
                if (this.isEmpty())
                    throw SessionException("No cards was found for the $identity.")

                sessionPublicKeys.add(this.last().publicKey as VirgilPublicKey)
            }
        }
    }

    /**
     * Stops session. After the session is stopped you can't encrypt or decrypt data - you have to start another one
     * session with [startSession] function.
     */
    fun stopSession() {
        keyStorage.load(currentIdentity()).run {
            sessionPublicKeys = sessionPublicKeys.asSequence().filter {
                it == this
            }.toMutableList()
        }
    }

    /**
     * Initializes [SyncKeyStorage] with default settings and provided [getTokenCallback] after that returns
     * initialized [SyncKeyStorage] object.
     */
    private fun initSyncKeyStorage(passwordBrainKey: String): SyncKeyStorage =
            CachingJwtProvider(CachingJwtProvider.RenewJwtCallback { _ ->
                Jwt(getTokenCallback())
            }).let {
                val brainKeyContext = BrainKeyContext.Builder()
                        .setAccessTokenProvider(it)
                        .setPythiaClient(VirgilPythiaClient())
                        .setPythiaCrypto(VirgilPythiaCrypto())
                        .build()
                val keyPair = BrainKey(brainKeyContext).generateKeyPair(passwordBrainKey)
                val syncKeyStorage = SyncKeyStorage(currentIdentity(),
                                                    it,
                                                    listOf(keyPair.publicKey),
                                                    keyPair.privateKey)
                syncKeyStorage.sync()

                syncKeyStorage
            }

    /**
     * Extracts current user's *Identity* from Json Web Token that is parsed from provided [getTokenCallback].
     */
    private fun currentIdentity() = Jwt(getTokenCallback()).identity

    /**
     * Add current user's *Public key* to the session keys list, because it will be used in any session.
     */
    private fun addToSessionCurrentUserPublicKey() =
            sessionPublicKeys.add(
                    virgilCrypto.extractPublicKey((keyStorage.load(currentIdentity()).left as VirgilPrivateKey))
            )

    companion object {
        const val KEYKNOX_KEY_POSTFIX = "_keyknox"
    }
}