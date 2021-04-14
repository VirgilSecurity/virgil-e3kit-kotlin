/*
 * Copyright (c) 2015-2021, Virgil Security, Inc.
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
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.keyknox.utils.unwrapCompanionClass
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import java.util.logging.Logger

/**
 * AuthorizationWorker
 */
internal class AuthorizationWorker internal constructor(
        private val cardManager: CardManager,
        private val localKeyStorage: LocalKeyStorage,
        private val identity: String,
        private val publishCardThenSaveLocal: (VirgilKeyPair?, String?) -> Unit,
        private val privateKeyDeleted: () -> Unit
) {

    @Synchronized
    @JvmOverloads
    internal fun register(keyPair: VirgilKeyPair? = null) = object : Completable {
        override fun execute() {
            logger.fine("Register new key pair")
            if (localKeyStorage.exists())
                throw EThreeException(EThreeException.Description.PRIVATE_KEY_EXISTS)

            val cards = cardManager.searchCards(this@AuthorizationWorker.identity)
            if (cards.isNotEmpty()) {
                throw EThreeException(
                    EThreeException.Description.USER_IS_ALREADY_REGISTERED
                )
            }

            publishCardThenSaveLocal(keyPair, null)
        }
    }

    @Synchronized internal fun unregister() = object : Completable {
        override fun execute() {
            logger.fine("Unregister key pair")
            val cards = cardManager.searchCards(this@AuthorizationWorker.identity)
            if (cards.isEmpty()) {
                throw EThreeException(EThreeException.Description.USER_IS_NOT_REGISTERED)
            }
            cards.forEach { card ->
                cardManager.revokeCard(card.identifier)
            }

            localKeyStorage.delete()
            privateKeyDeleted()
        }
    }

    @Synchronized internal fun rotatePrivateKey() = object : Completable {
        override fun execute() {
            logger.fine("Rotate private key")
            if (localKeyStorage.exists())
                throw EThreeException(EThreeException.Description.PRIVATE_KEY_EXISTS)

            val cards = cardManager.searchCards(this@AuthorizationWorker.identity)
            val card = cards.firstOrNull()
                       ?: throw EThreeException(EThreeException.Description.USER_IS_NOT_REGISTERED)

            publishCardThenSaveLocal(null, card.identifier)
        }
    }

    internal fun hasLocalPrivateKey() = localKeyStorage.exists()

    internal fun cleanup() {
        logger.fine("Cleanup")
        localKeyStorage.delete()
        privateKeyDeleted()
    }

    companion object {
        private val logger = Logger.getLogger(unwrapCompanionClass(this::class.java).name)
    }
}
