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

import com.virgilsecurity.android.common.EThreeCore
import com.virgilsecurity.android.common.exception.*
import com.virgilsecurity.android.common.storage.local.KeyStorageLocal
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.crypto.pythia.Pythia.cleanup
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.crypto.VirgilCrypto

/**
 * AuthorizationWorker
 */
internal class AuthorizationWorker(
        private val cardManager: CardManager,
        private val virgilCrypto: VirgilCrypto,
        private val keyStorageLocal: KeyStorageLocal
) {

    /**
     * Publishes the public key in Virgil's Cards Service in case no public key for current
     * identity is published yet. Otherwise [RegistrationException] will be thrown.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws RegistrationException
     * @throws CryptoException
     */
    @Synchronized internal fun register() = object : Completable {
        override fun execute() {
            if (cardManager.searchCards(currentIdentity()).isNotEmpty())
                throw RegistrationException("Card with identity " +
                                            "${currentIdentity()} already exists")

            if (keyStorageLocal.exists())
                throw PrivateKeyExistsException("You already have a Private Key on this device" +
                                                "for identity: ${currentIdentity()}. Please, use" +
                                                "\'cleanup()\' function first.")

            virgilCrypto.generateKeyPair().run {
                cardManager.publishCard(this.privateKey, this.publicKey, currentIdentity())
                keyStorageLocal.store(virgilCrypto.exportPrivateKey(this.privateKey))
            }
        }
    }

    /**
     * Revokes the public key for current *identity* in Virgil's Cards Service. After this operation
     * you can call [EThreeCore.register] again.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws UnRegistrationException if there's no public key published yet, or if there's more
     * than one public key is published.
     */
    @Synchronized internal fun unregister() = object : Completable {
        override fun execute() {
            val foundCards = cardManager.searchCards(currentIdentity())
            if (foundCards.isEmpty())
                throw UnRegistrationException("Card with identity " +
                                              "${currentIdentity()} does not exist.")

            if (foundCards.size > 1)
                throw UnRegistrationException("Too many cards with identity: " +
                                              "${currentIdentity()}.")

            cardManager.revokeCard(foundCards.first().identifier).run {
                if (hasLocalPrivateKey()) cleanup()
            }
        }
    }

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
    @Synchronized internal fun rotatePrivateKey() = object : Completable {
        override fun execute() {
            if (keyStorageLocal.exists())
                throw PrivateKeyExistsException("You already have a Private Key on this device" +
                                                "for identity: ${currentIdentity()}. Please, use" +
                                                "\'cleanup()\' function first.")

            val cards = cardManager.searchCards(currentIdentity())
            if (cards.isEmpty())
                throw CardNotFoundException("No cards was found " +
                                            "with identity: ${currentIdentity()}")
            if (cards.size > 1)
                throw IllegalStateException("${cards.size} cards was found " +
                                            "with identity: ${currentIdentity()}. How? (: " +
                                            "Should be <= 1. Please, contact developers if " +
                                            "it was not an intended behaviour.")

            (cards.first() to virgilCrypto.generateKeyPair()).run {
                val rawCard = cardManager.generateRawCard(this.second.privateKey,
                                                          this.second.publicKey,
                                                          currentIdentity(),
                                                          this.first.identifier)
                cardManager.publishCard(rawCard)

                keyStorageLocal.store(virgilCrypto.exportPrivateKey(this.second.privateKey))
            }
        }
    }

    /**
     * Checks whether the private key is present in the local storage of current device.
     * Returns *true* if the key is present in the local key storage otherwise *false*.
     */
    internal fun hasLocalPrivateKey() = keyStorageLocal.exists()

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
    internal fun cleanup() {
        checkPrivateKeyOrThrow()

        keyStorageLocal.delete()
    }
}
