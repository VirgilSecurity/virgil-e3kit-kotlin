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

package com.virgilsecurity.android.common.model

import com.virgilsecurity.android.common.exception.GroupException
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.android.common.manager.GroupManager
import com.virgilsecurity.android.common.manager.LookupManager
import com.virgilsecurity.crypto.foundation.GroupSession
import com.virgilsecurity.sdk.crypto.VirgilCrypto

/**
 * Group
 */
internal class Group(
        rawGroup: RawGroup,
        private val crypto: VirgilCrypto,
        localKeyStorage: LocalKeyStorage,
        groupManager: GroupManager,
        lookupManager: LookupManager
) {

    val initiator: String = rawGroup.info.initiator
    val participants: Set<String>

    internal val session: GroupSession

    private val selfIdentity: String = localKeyStorage.identity

    init {
        val tickets = rawGroup.tickets.sortedBy { it.groupMessage.epoch } // TODO check sort order matches $0.groupMessage.getEpoch() < $1.groupMessage.getEpoch()
        val lastTicket = tickets.lastOrNull() ?: throw GroupException("Group is invalid")

        validateParticipantsCount(lastTicket.participants.size)

        this.participants = lastTicket.participants
        this.session = generateSession(tickets)
    }

    internal fun checkPermissions() {
        if (selfIdentity != initiator) {
            throw GroupException("Only group initiator can do changed on group")
        }
    }

    internal fun generateSession(tickets: List<Ticket>): GroupSession {
        val session = GroupSession()
        session.setRng(crypto.rng)

        tickets.forEach {
            session.addEpoch(it.groupMessage)
        }

        return session
    }

    companion object {
        internal fun validateParticipantsCount(count: Int) {
            if (count !in VALID_PARTICIPANTS_COUNT_RANGE) {
                throw GroupException("Please check valid participants count range in " +
                                     "Group.VALID_PARTICIPANTS_COUNT_RANGE")
            }
        }

        val VALID_PARTICIPANTS_COUNT_RANGE = 2..100
    }
}
