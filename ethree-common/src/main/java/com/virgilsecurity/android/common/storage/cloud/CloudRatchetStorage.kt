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

package com.virgilsecurity.android.common.storage.cloud

import com.virgilsecurity.android.common.exception.EThreeRatchetException
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.crypto.ratchet.RatchetMessage
import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.client.KeyknoxPullParams
import com.virgilsecurity.keyknox.client.KeyknoxPushParams
import com.virgilsecurity.keyknox.client.KeyknoxResetParams
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider

/**
 * CloudRatchetStorage
 */
internal class CloudRatchetStorage(
        private val accessTokenProvider: AccessTokenProvider,
        private val localKeyStorage: LocalKeyStorage
) {

    private val keyknoxManager: KeyknoxManager
    private val identity: String
        get() = localKeyStorage.identity

    init {
        val keyknoxClient = KeyknoxClient(this.accessTokenProvider)

        this.keyknoxManager = KeyknoxManager(keyknoxClient)
    }

    internal fun store(ticket: RatchetMessage, card: Card, name: String?) {
        val selfKeyPair = localKeyStorage.retrieveKeyPair()

        val pushParams = KeyknoxPushParams(listOf(card.identity, this.identity),
                                           ROOT,
                                           card.identity,
                                           name ?: DEFAULT_KEY)

        keyknoxManager.pushValue(pushParams,
                                 ticket.serialize(),
                                 null,
                                 listOf(card.publicKey, selfKeyPair.publicKey),
                                 selfKeyPair.privateKey)
    }

    internal fun retrieve(card: Card, name: String?): RatchetMessage {
        val selfKeyPair = localKeyStorage.retrieveKeyPair()

        val params = KeyknoxPullParams(card.identity,
                                       ROOT,
                                       this.identity,
                                       name ?: DEFAULT_KEY)

        val response = keyknoxManager.pullValue(params,
                                                listOf(card.publicKey),
                                                selfKeyPair.privateKey)

        if (response.value.isEmpty()) {
            throw EThreeRatchetException(EThreeRatchetException.Description.NO_INVITE)
        }

        return RatchetMessage.deserialize(response.value)
    }

    internal fun delete(card: Card, name: String?) {
        val params = KeyknoxResetParams(ROOT,
                                        card.identity,
                                        name ?: DEFAULT_KEY)

        keyknoxManager.resetValue(params)
    }

    internal fun reset() {
        val params = KeyknoxResetParams(ROOT, null, null)

        keyknoxManager.resetValue(params)
    }

    companion object {
        private const val ROOT = "ratchet-peer-to-peer"
        private const val DEFAULT_KEY = "default"
    }
}
