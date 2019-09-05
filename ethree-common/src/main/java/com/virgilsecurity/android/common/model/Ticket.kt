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

import com.virgilsecurity.common.model.Data
import com.virgilsecurity.common.util.SerializeUtils
import com.virgilsecurity.crypto.foundation.GroupSessionMessage
import com.virgilsecurity.crypto.foundation.GroupSessionTicket
import com.virgilsecurity.sdk.crypto.VirgilCrypto

/**
 * Ticket
 */
internal class Ticket {

    internal val groupMessage: GroupSessionMessage
    internal val participants: Set<String>

    internal constructor(groupMessage: GroupSessionMessage, participants: Set<String>) {
        this.groupMessage = groupMessage
        this.participants = participants
    }

    internal constructor(crypto: VirgilCrypto, sessionId: Data, participants: Set<String>) {
        val ticket = GroupSessionTicket()
        ticket.setRng(crypto.rng)

        ticket.setupTicketAsNew(sessionId.data)

        this.groupMessage = ticket.ticketMessage
        this.participants = participants
    }

    internal fun serialize(): Data = SerializeUtils.serialize(this)

    companion object {
        @JvmStatic internal fun deserialize(data: Data): Ticket =
                SerializeUtils.deserialize(data, Ticket::class.java)
    }

    // TODO add Parcelable
}
