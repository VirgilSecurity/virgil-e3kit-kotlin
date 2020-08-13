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

package com.virgilsecurity.android.common.model

import android.os.Parcel
import android.os.Parcelable
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.common.util.SerializeUtils
import com.virgilsecurity.crypto.foundation.GroupSessionMessage
import com.virgilsecurity.crypto.foundation.GroupSessionTicket
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import java.io.Serializable


/**
 * Ticket
 */
internal class Ticket : Parcelable {

    internal val groupMessage: GroupSessionMessage
    internal val participants: Set<String>

    private constructor(parcel: Parcel) {
        val groupMessageDataLength = parcel.readInt()
        val serializedGroupMessage = ByteArray(groupMessageDataLength)
        parcel.readByteArray(serializedGroupMessage)
        this.groupMessage = GroupSessionMessage.deserialize(serializedGroupMessage)

        this.participants = parcel.readSerializable() as Set<String>
    }

    internal constructor(groupMessage: GroupSessionMessage, participants: Set<String>) {
        this.groupMessage = groupMessage
        this.participants = participants
    }

    internal constructor(crypto: VirgilCrypto,
                         sessionId: Data,
                         participants: Set<String>) {
        require(participants is Serializable) { "Please, use serializable Set for participants." }

        val ticket = GroupSessionTicket()
        ticket.setRng(crypto.rng)

        ticket.setupTicketAsNew(sessionId.value)

        this.groupMessage = ticket.ticketMessage
        this.participants = participants
    }

    internal fun serialize(): Data {
        val dto = TicketDto(this.groupMessage.serialize(), this.participants)
        return SerializeUtils.serialize(dto)
    }

    override fun writeToParcel(parcel: Parcel, flags: Int) {
        val groupMessageData = this.groupMessage.serialize()
        parcel.writeInt(groupMessageData.size)
        parcel.writeByteArray(groupMessageData)

        parcel.writeSerializable(participants as Serializable)
    }

    override fun describeContents(): Int {
        return hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Ticket

        if (!groupMessage.serialize().contentEquals(other.groupMessage.serialize())) return false
        if (participants != other.participants) return false

        return true
    }

    override fun hashCode(): Int {
        var result = groupMessage.hashCode()
        result = 31 * result + participants.hashCode()
        return result
    }

    private data class TicketDto(val groupMessage: ByteArray, val participants: Set<String>)

    companion object {
        @JvmStatic internal fun deserialize(data: Data): Ticket {
            val dto = SerializeUtils.deserialize(data, TicketDto::class.java)
            return Ticket(GroupSessionMessage.deserialize(dto.groupMessage), dto.participants)
        }

        @JvmField
        val CREATOR = object : Parcelable.Creator<Ticket> {
            override fun createFromParcel(parcel: Parcel): Ticket {
                return Ticket(parcel)
            }

            override fun newArray(size: Int): Array<Ticket?> {
                return arrayOfNulls(size)
            }
        }
    }
}
