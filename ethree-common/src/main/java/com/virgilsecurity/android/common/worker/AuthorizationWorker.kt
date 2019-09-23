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
import com.virgilsecurity.android.common.storage.local.KeyStorageLocal
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.crypto.VirgilKeyPair

/**
 * AuthorizationWorker
 */
internal class AuthorizationWorker(
        private val cardManager: CardManager,
        private val keyStorageLocal: KeyStorageLocal,
        private val identity: String,
        private val publishCardThenSaveLocal: (VirgilKeyPair?, String?) -> Unit,
        private val privateKeyDeleted: () -> Unit
) {

    /** // TODO check throws for all functions
     * Publishes Card on Virgil Cards Service and saves Private Key in local storage.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @param keyPair `VirgilKeyPair` to publish Card with. Will generate if not specified.
     */
    @Synchronized
    @JvmOverloads
    internal fun register(keyPair: VirgilKeyPair? = null) = object : Completable {
        override fun execute() {
            if (keyStorageLocal.exists())
                throw EThreeException("Private key already exists in local key storage")

            val cards = cardManager.searchCards(this@AuthorizationWorker.identity)
            if (cards.isNotEmpty()) throw EThreeException("User is already registered")

            publishCardThenSaveLocal(keyPair, null)
        }
    }

    /**
     * Revokes Card from Virgil Cards Service, deletes Private Key from local storage
     *
     * To start execution of the current function, please see [Completable] description.
     */
    @Synchronized internal fun unregister() = object : Completable {
        override fun execute() {
            val cards = cardManager.searchCards(this@AuthorizationWorker.identity)
            val card = cards.firstOrNull() ?: throw EThreeException("User is not registered")

            cardManager.revokeCard(card.identifier)
            keyStorageLocal.delete()
            privateKeyDeleted()
        }
    }

    /**
     * Generates new Private Key, publishes new Card to replace the current one on Virgil Cards
     * Service and saves new Private Key in local storage
     *
     * To start execution of the current function, please see [Completable] description.
     */
    @Synchronized internal fun rotatePrivateKey() = object : Completable {
        override fun execute() {
            if (keyStorageLocal.exists())
                throw EThreeException("Private key already exists in local key storage.")

            val cards = cardManager.searchCards(this@AuthorizationWorker.identity)
            val card = cards.firstOrNull() ?: throw EThreeException("User is not registered")

            publishCardThenSaveLocal(null, card.identifier)
        }
    }

    /**
     * Checks existence of private key in local key storage.
     * Returns *true* if the key is present in the local key storage otherwise *false*.
     */
    internal fun hasLocalPrivateKey() = keyStorageLocal.exists()

    /**
     * ! *WARNING* ! If you call this function after [register] without using [backupPrivateKey]
     * then you will loose private key permanently, as well you won't be able to use identity that
     * was used with that private key no more.
     *
     * Deletes Private Key from local storage, cleans local cards storage.
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException] // TODO check exception type
     * exception will be thrown.
     */
    internal fun cleanup() {
        keyStorageLocal.delete()
        privateKeyDeleted()
    }
}
