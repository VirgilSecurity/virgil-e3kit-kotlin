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

package com.virgilsecurity.android.common.manager

import com.virgilsecurity.android.common.exception.GroupException
import com.virgilsecurity.android.common.model.Group
import com.virgilsecurity.android.common.model.GroupInfo
import com.virgilsecurity.android.common.model.RawGroup
import com.virgilsecurity.android.common.model.Ticket
import com.virgilsecurity.android.common.storage.cloud.TicketStorageCloud
import com.virgilsecurity.android.common.storage.local.GroupStorageFile
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.VirgilCrypto

/**
 * GroupManager
 */
internal class GroupManager(
        internal val localGroupStorage: GroupStorageFile,
        private val ticketStorageCloud: TicketStorageCloud,
        private val localKeyStorage: LocalKeyStorage,
        private val lookupManager: LookupManager,
        private val crypto: VirgilCrypto
) {

    private val identity: String = localGroupStorage.identity

    private fun parse(rawGroup: RawGroup): Group = Group(rawGroup,
                                                         crypto,
                                                         localKeyStorage,
                                                         this,
                                                         lookupManager)

    internal fun store(ticket: Ticket, cards: List<Card>): Group {
        val rawGroup = RawGroup(GroupInfo(this.identity), listOf(ticket))

        ticketStorageCloud.store(ticket, cards)
        localGroupStorage.store(rawGroup)

        return parse(rawGroup)
    }

    internal fun pull(sessionId: Data, card: Card): Group {
        val tickets = ticketStorageCloud.retrieve(sessionId,
                                                  card.identity,
                                                  card.publicKey)

        if (tickets.isEmpty()) {
            localGroupStorage.delete(sessionId)

            throw GroupException("Group with provided id was not found")
        }

        val rawGroup = RawGroup(GroupInfo(card.identity), tickets)

        localGroupStorage.store(rawGroup)

        return parse(rawGroup)
    }

    internal fun addAccess(cards: List<Card>, sessionId: Data) =
        ticketStorageCloud.addRecipients(cards, sessionId)

    internal fun reAddAccess(card: Card, sessionId: Data) =
            ticketStorageCloud.reAddRecipient(card, sessionId)

    internal fun retrieve(sessionId: Data): Group? {
        val rawGroup = localGroupStorage.retrieve(sessionId, MAX_TICKETS_IN_GROUP)

        return if (rawGroup == null) rawGroup else parse(rawGroup)
    }

    internal fun retrieve(sessionId: Data, epoch: UInt): Group? {
        val rawGroup = localGroupStorage.retrieve(sessionId, epoch)

        return if (rawGroup == null) rawGroup else parse(rawGroup)
    }

    internal fun removeAccess(identities: Set<String>, sessionId: Data) {
        identities.forEach {
            ticketStorageCloud.removeRecipient(it, sessionId)
        }
    }

    internal fun delete(sessionId: Data) {
        ticketStorageCloud.delete(sessionId)
        localGroupStorage.delete(sessionId)
    }

    companion object {
        private const val MAX_TICKETS_IN_GROUP = 50
    }
}
