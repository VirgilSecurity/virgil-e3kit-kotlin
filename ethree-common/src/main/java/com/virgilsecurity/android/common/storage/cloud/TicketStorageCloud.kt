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

import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.android.common.model.Ticket
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.common.util.toHexString
import com.virgilsecurity.crypto.foundation.GroupSessionMessage
import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.client.*
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider

/**
 * TicketStorageCloud
 */
internal class TicketStorageCloud(
        accessTokenProvider: AccessTokenProvider,
        private val localKeyStorage: LocalKeyStorage
) {

    private val keyknoxManager: KeyknoxManager = KeyknoxManager(KeyknoxClient(accessTokenProvider))
    private var identity: String = localKeyStorage.identity

    internal fun store(ticket: Ticket, cards: List<Card>) {
        val selfKeyPair = localKeyStorage.load()

        val groupMessage = ticket.groupMessage

        val sessionId = groupMessage.sessionId.toHexString()
        val epoch = groupMessage.epoch
        val ticketData = groupMessage.serialize()

        val identities = cards.map { it.identity }
        val publicKeys = cards.map { it.publicKey }

        val params = KeyknoxPushParams(identities + this.identity,
                                       GROUP_SESSION_ROOT,
                                       sessionId,
                                       epoch.toString())

        keyknoxManager.pushValue(params,
                                 ticketData,
                                 null,
                                 publicKeys,
                                 selfKeyPair.privateKey)
    }

    internal fun retrieve(sessionId: Data,
                          identity: String,
                          identityPublicKey: VirgilPublicKey): List<Ticket> {
        val selfKeyPair = localKeyStorage.load()

        val sessionIdHex = sessionId.toHexString()

        val getParams = KeyknoxGetKeysParams(identity,
                                          GROUP_SESSION_ROOT,
                                          sessionIdHex)

        val epochs = keyknoxManager.getKeys(getParams)

        val tickets = mutableListOf<Ticket>()
        for (epoch in epochs) {
            val pullParams = KeyknoxPullParams(identity,
                                           GROUP_SESSION_ROOT,
                                           sessionIdHex,
                                           epoch)
            val response = keyknoxManager.pullValue(pullParams,
                                                    listOf(identityPublicKey),
                                                    selfKeyPair.privateKey)

            val groupMessage = GroupSessionMessage.deserialize(response.value)
            val participants = response.identities.toSet()
            val ticket = Ticket(groupMessage, participants)

            tickets.add(ticket)
        }

        return tickets
    }

    internal fun addRecipients(cards: List<Card>, sessionId: Data) {
        val selfKeyPair = localKeyStorage.load()

        val sessionIdHex = sessionId.toHexString()

        val identities = cards.map { it.identity }
        val publicKeys = cards.map { it.publicKey }

        val getParams = KeyknoxGetKeysParams(this.identity,
                                             GROUP_SESSION_ROOT,
                                             sessionIdHex)

        val epochs = keyknoxManager.getKeys(getParams)

        for (epoch in epochs) {
            val pullParams = KeyknoxPullParams(this.identity,
                                               GROUP_SESSION_ROOT,
                                               sessionIdHex,
                                               epoch)
            val response = keyknoxManager.pullValue(pullParams,
                                                    listOf(selfKeyPair.publicKey),
                                                    selfKeyPair.privateKey)

            val pushParams = KeyknoxPushParams(identities,
                                               GROUP_SESSION_ROOT,
                                               sessionIdHex,
                                               epoch)

            keyknoxManager.pushValue(pushParams,
                                     response.value,
                                     response.keyknoxHash,
                                     publicKeys + selfKeyPair.publicKey,
                                     selfKeyPair.privateKey)
        }
    }

    internal fun reAddRecipient(card: Card, sessionId: Data) {
        val selfKeyPair = localKeyStorage.load()

        val path = sessionId.toHexString()

        val getParams = KeyknoxGetKeysParams(this.identity,
                                             GROUP_SESSION_ROOT,
                                             path)

        val epochs = keyknoxManager.getKeys(getParams)

        for (epoch in epochs) {
            val pullParams = KeyknoxPullParams(this.identity,
                                               GROUP_SESSION_ROOT,
                                               path,
                                               epoch)

            val response = keyknoxManager.pullValue(pullParams,
                                                    listOf(selfKeyPair.publicKey),
                                                    selfKeyPair.privateKey)

            removeRecipient(card.identity, sessionId, epoch)

            val pushParams = KeyknoxPushParams(listOf(card.identity),
                                               GROUP_SESSION_ROOT,
                                               path,
                                               epoch)

            keyknoxManager.pushValue(pushParams,
                                     response.value,
                                     response.keyknoxHash,
                                     listOf(card.publicKey, selfKeyPair.publicKey),
                                     selfKeyPair.privateKey)
        }
    }

    internal fun removeRecipient(identity: String, sessionId: Data, epoch: String? = null) {
        val sessionIdHex = sessionId.toHexString()

        val params = KeyknoxDeleteRecipientParams(identity,
                                                  GROUP_SESSION_ROOT,
                                                  sessionIdHex,
                                                  epoch)

        keyknoxManager.deleteRecipient(params)
    }

    internal fun delete(sessionId: Data) {
        val sessionIdHex = sessionId.toHexString()

        val params = KeyknoxResetParams(GROUP_SESSION_ROOT, sessionIdHex, null)

        keyknoxManager.resetValue(params)
    }

    companion object {
        private const val GROUP_SESSION_ROOT = "group-session"
    }
}
