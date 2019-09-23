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

package com.virgilsecurity.android.ethree.common.model

import android.os.Parcel
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.virgilsecurity.android.common.exception.GroupIdTooShortException
import com.virgilsecurity.android.common.model.Ticket
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.crypto.HashAlgorithm
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.util.*
import kotlin.collections.HashMap


/**
 * TicketTest
 */
@RunWith(AndroidJUnit4::class)
class TicketTest {

    @Test fun ticket_parcelable_with_serializable_participants() {
        val crypto = VirgilCrypto()
        val identifierData = Data(UUID.randomUUID().toString().toByteArray())
        val sessionId = computeSessionId(identifierData, crypto)
        val participantsSet = setOf("Bob", "Alice", "Jane")
        val ticket = Ticket(crypto, sessionId, participantsSet)

        val groupMessage = ticket.groupMessage
        val participants = ticket.participants

        val parcel = Parcel.obtain()
        ticket.writeToParcel(parcel, ticket.describeContents())
        parcel.setDataPosition(0)

        val createdFromParcel = Ticket.CREATOR.createFromParcel(parcel)
        assertArrayEquals(createdFromParcel.groupMessage.serialize(), groupMessage.serialize())
        assertEquals(createdFromParcel.participants, participants)
    }

    @Test(expected = IllegalArgumentException::class)
    fun ticket_parcelable_with_not_serializable_participants() {
        val crypto = VirgilCrypto()
        val identifierData = Data(UUID.randomUUID().toString().toByteArray())
        val sessionId = computeSessionId(identifierData, crypto)

        val participantsSet = NotSerializableSet("Bob", "Alice", "Jane")

        // Only Serializable Set's are supported
        Ticket(crypto, sessionId, participantsSet)
    }

    private fun computeSessionId(identifier: Data, crypto: VirgilCrypto): Data {
        if (identifier.data.size <= 10) {
            throw GroupIdTooShortException("Group Id length should be > 10")
        }

        val hash = crypto.computeHash(identifier.data, HashAlgorithm.SHA512)
                .sliceArray(IntRange(0, 31))

        return Data(hash)
    }

    private class NotSerializableSet(vararg values: String) : Set<String> {

        @Transient
        private var map: HashMap<String, Any>

        init {
            val valuesToObjects = values.map { it to PRESENT }.toMap()
            map = HashMap(valuesToObjects)
        }


        override val size: Int
            get() = map.size

        override fun contains(element: String): Boolean = map.contains(element)

        override fun containsAll(elements: Collection<String>): Boolean = containsAll(elements)

        override fun isEmpty(): Boolean = map.isEmpty()

        override fun iterator(): Iterator<String> = map.keys.iterator()

        companion object {
            private val PRESENT = Any()
        }
    }
}
