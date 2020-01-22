/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
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
import com.virgilsecurity.android.common.storage.cloud.CloudTicketStorage
import com.virgilsecurity.android.common.storage.local.FileGroupStorage
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.keyknox.utils.unwrapCompanionClass
import com.virgilsecurity.sdk.cards.Card
import java.util.logging.Logger

/**
 * GroupManager
 */
internal class GroupManager internal constructor(
        internal val localGroupStorage: FileGroupStorage,
        internal val cloudTicketStorage: CloudTicketStorage,
        private val localKeyStorage: LocalKeyStorage,
        private val lookupManager: LookupManager
) {

    internal val identity: String = localGroupStorage.identity

    private fun parse(rawGroup: RawGroup): Group = Group(rawGroup,
                                                         localKeyStorage,
                                                         this,
                                                         lookupManager)

    internal fun store(ticket: Ticket, cards: List<Card>): Group {
        val info = GroupInfo(this.identity)
        val rawGroup = RawGroup(info, listOf(ticket))

        cloudTicketStorage.store(ticket, cards)
        localGroupStorage.store(rawGroup)

        return parse(rawGroup)
    }

    internal fun pull(sessionId: Data, card: Card): Group {
        val cloudEpochs = cloudTicketStorage.getEpochs(sessionId, card.identity)
        val localEpochs = localGroupStorage.getEpochs(sessionId)

        val anyEpoch = cloudEpochs.firstOrNull()
        if (anyEpoch == null) {
            localGroupStorage.delete(sessionId)

            throw GroupException(GroupException.Description.GROUP_WAS_NOT_FOUND)
        }

        val epochs = cloudEpochs.subtract(localEpochs).toMutableSet()
        epochs.add(anyEpoch)

        val tickets = cloudTicketStorage.retrieve(sessionId, card.identity, card.publicKey, epochs)
        val info = GroupInfo(card.identity)
        val rawGroup = RawGroup(info, tickets)

        localGroupStorage.store(rawGroup)

        return retrieve(sessionId)
               ?: throw GroupException(GroupException.Description.INCONSISTENT_STATE)
    }

    internal fun addAccess(cards: List<Card>, sessionId: Data) =
            cloudTicketStorage.addRecipients(cards, sessionId)

    internal fun reAddAccess(card: Card, sessionId: Data) =
            cloudTicketStorage.reAddRecipient(card, sessionId)

    internal fun retrieve(sessionId: Data): Group? {
        val ticketsCount = MAX_TICKETS_IN_GROUP

        val rawGroup = try {
            localGroupStorage.retrieve(sessionId, ticketsCount)
        } catch (throwable: Throwable) {
            logger.info(throwable.message)
            return null
        }

        return parse(rawGroup)
    }

    internal fun retrieve(sessionId: Data, epoch: Long): Group? {
        val rawGroup = try {
            localGroupStorage.retrieve(sessionId, epoch)
        } catch (throwable: Throwable) {
            logger.info(throwable.message)
            return null
        }

        return parse(rawGroup)
    }

    internal fun removeAccess(identities: Set<String>, sessionId: Data) {
        identities.forEach {
            cloudTicketStorage.removeRecipient(it, sessionId)
        }
    }

    internal fun delete(sessionId: Data) {
        cloudTicketStorage.delete(sessionId)
        localGroupStorage.delete(sessionId)
    }

    companion object {
        internal const val MAX_TICKETS_IN_GROUP = 50

        private val logger = Logger.getLogger(unwrapCompanionClass(this.javaClass).name)
    }
}
