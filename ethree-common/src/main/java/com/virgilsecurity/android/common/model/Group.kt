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

import com.virgilsecurity.android.common.exception.*
import com.virgilsecurity.android.common.manager.GroupManager
import com.virgilsecurity.android.common.manager.LookupManager
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.common.extension.toData
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.crypto.foundation.FoundationException
import com.virgilsecurity.crypto.foundation.GroupSession
import com.virgilsecurity.crypto.foundation.GroupSessionMessage
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.utils.ConvertionUtils
import java.util.*
import kotlin.collections.HashSet

/**
 * Group
 */
class Group internal constructor(
        rawGroup: RawGroup,
        private val localKeyStorage: LocalKeyStorage,
        private val groupManager: GroupManager,
        private val lookupManager: LookupManager
) {

    private val crypto: VirgilCrypto

    val initiator: String = rawGroup.info.initiator
    var participants: MutableSet<String>
        private set

    internal var session: GroupSession

    private val selfIdentity: String = localKeyStorage.identity

    init {
        val tickets = rawGroup.tickets.sortedBy { it.groupMessage.epoch }
        val lastTicket = tickets.lastOrNull()
                         ?: throw GroupException(GroupException.Description.INVALID_GROUP)

        validateParticipantsCount(lastTicket.participants.size)

        this.crypto = localKeyStorage.crypto
        this.participants = lastTicket.participants.toMutableSet()
        this.session = generateSession(tickets)
    }

    private fun generateSession(tickets: List<Ticket>, crypto: VirgilCrypto): GroupSession {
        val session = GroupSession()
        session.setRng(crypto.rng)

        tickets.forEach {
            session.addEpoch(it.groupMessage)
        }

        return session
    }

    private fun shareTickets(cards: List<Card>, newSet: Set<String>) {
        val sessionId = this.session.sessionId.toData()
        groupManager.addAccess(cards, newSet, sessionId)
        this.participants = newSet.toMutableSet()
    }

    private fun addNewTicket(participants: FindUsersResult) {
        val newSet = HashSet(participants.keys)

        val ticketMessage = this.session.createGroupTicket().ticketMessage
        val ticket = Ticket(ticketMessage, newSet)

        groupManager.store(ticket, participants.values.toList())
        this.session.addEpoch(ticket.groupMessage)

        newSet.add(this.initiator)

        this.participants = newSet
    }

    internal fun checkPermissions() {
        if (selfIdentity != initiator)
            throw GroupException(GroupException.Description.GROUP_PERMISSION_DENIED)
    }

    internal fun generateSession(tickets: List<Ticket>): GroupSession =
            generateSession(tickets, this.crypto)

    /**
     * Signs and encrypts data for group.
     *
     * @param string string to encrypt.
     *
     * @return encrypted base64String.
     *
     * @notice Requires private key in local storage.
     */
    fun encrypt(string: String): String {
        require(string.isNotEmpty()) { "\'string\' should not be empty" }

        return ConvertionUtils.toBase64String(encrypt(string.toByteArray()))
    }

    /**
     * Signs and encrypts data for group.
     *
     * @param data byte array to encrypt.
     *
     * @return encrypted byte array.
     *
     * @notice Requires private key in local storage.
     */
    fun encrypt(data: ByteArray): ByteArray {
        require(data.isNotEmpty()) { "\'data\' should not be empty" }

        val selfKeyPair = this.localKeyStorage.retrieveKeyPair()
        val encrypted = this.session.encrypt(data, selfKeyPair.privateKey.privateKey)
        return encrypted.serialize()
    }

    /**
     * Decrypts and verifies data from group participant.
     *
     * @param data encrypted byte array.
     * @param senderCard sender Card to verify with.
     * @param date date of message. Use it to prevent verifying new messages with old card.
     *
     * @return decrypted byte array.
     */
    @JvmOverloads fun decrypt(data: ByteArray, senderCard: Card, date: Date? = null): ByteArray {
        require(data.isNotEmpty()) { "\'data\' should not be empty" }

        val encrypted = GroupSessionMessage.deserialize(data)
        var card = senderCard

        if (date != null) {
            // Find a card which is actual for the date
            var previousCard = card.previousCard
            while (previousCard != null) {
                if (!date.before(card.createdAt)) {
                    break
                }
                previousCard = card.previousCard
                card = previousCard
            }
        }

        if (!Arrays.equals(this.session.sessionId, encrypted.sessionId))
            throw GroupException(GroupException.Description.MESSAGE_NOT_FROM_THIS_GROUP)

        val messageEpoch = encrypted.epoch
        val currentEpoch = this.session.currentEpoch

        if (currentEpoch < messageEpoch) {
            throw GroupException(GroupException.Description.GROUP_IS_OUTDATED)
        }

        try {
            return if (currentEpoch - messageEpoch < GroupManager.MAX_TICKETS_IN_GROUP) {
                this.session.decrypt(encrypted, card.publicKey.publicKey)
            } else {
                val sessionId = encrypted.sessionId.toData()

                val tempGroup = this.groupManager.retrieve(sessionId, messageEpoch)
                                ?: throw GroupException(
                                    GroupException.Description.MISSING_CACHED_GROUP
                                )

                tempGroup.decrypt(data, senderCard)
            }
        } catch (e: FoundationException) {
            throw GroupException(GroupException.Description.VERIFICATION_FAILED)
        }
    }

    /**
     * Decrypts and verifies base64 string from group participant.
     *
     * @param text encrypted String.
     * @param senderCard sender Card to verify with.
     * @param date date of message. Use it to prevent verifying new messages with old card.
     *
     * @return decrypted String.
     */
    @JvmOverloads fun decrypt(text: String, senderCard: Card, date: Date? = null): String {
        require(text.isNotEmpty()) { "\'text\' should not be empty" }

        val data: Data
        try {
            data = Data.fromBase64String(text)
        } catch (exception: Exception) {
            throw EThreeException(EThreeException.Description.STR_TO_DATA_FAILED, exception)
        }

        val decryptedData = this.decrypt(data.value, senderCard, date)
        return ConvertionUtils.toString(decryptedData)
    }

    /**
     * Updates group.
     */
    fun update(): Completable = object : Completable {
        override fun execute() {
            val sessionId = this@Group.session.sessionId.toData()
            val card = lookupManager.lookupCard(this@Group.initiator)
            val group = groupManager.pull(sessionId, card)
            this@Group.session = group.session
            this@Group.participants = group.participants
        }
    }

    /**
     * Adds new participants to group.
     *
     * @param participants Cards of users to add. Result of findUsers call.
     *
     * @notice New participant will be able to decrypt all history
     */
    fun add(participants: FindUsersResult): Completable = object : Completable {
        override fun execute() {
            checkPermissions()

            val oldSet = this@Group.participants
            val newSet = oldSet.union(participants.keys)

            validateParticipantsCount(newSet.size)

            if (newSet == oldSet) {
                throw GroupException(
                    GroupException.Description.INVALID_CHANGE_PARTICIPANTS
                )
            }

            val addSet = newSet.subtract(oldSet)

            val addedCards = mutableListOf<Card>()
            addSet.forEach {
                val card = participants[it]
                           ?: throw GroupException(GroupException.Description.INCONSISTENT_STATE)

                addedCards.add(card)
            }

            this@Group.shareTickets(addedCards, newSet)
        }
    }

    /**
     * Share group access and history on new Card of existing participant.
     *
     * @param Participant Card.
     */
    fun reAdd(participant: Card): Completable = object : Completable {
        override fun execute() {
            checkPermissions()

            groupManager.reAddAccess(participant, this@Group.session.sessionId.toData())
        }
    }

    /**
     * Removes participants from group.
     *
     * *Note* Removed participant will not be able to decrypt previous history again after group
     * update.
     *
     * @param Cards of users to remove. Result of findUsers call.
     */
    fun remove(participants: FindUsersResult): Completable = object : Completable {
        override fun execute() {
            checkPermissions()

            val oldSet = this@Group.participants
            val newSet = oldSet.subtract(participants.keys)

            validateParticipantsCount(newSet.size)

            // Group initiator should not be able to remove himself from a group
            if (participants.containsKey(this@Group.initiator)) {
                throw GroupException(GroupException.Description.INITIATOR_REMOVAL_FAILED)
            }

            if (newSet == oldSet) {
                throw GroupException(
                    GroupException.Description.INVALID_CHANGE_PARTICIPANTS
                )
            }

            val newSetLookup = lookupManager.lookupCards(newSet.toList(),
                                                         forceReload = false,
                                                         checkResult = true)
            addNewTicket(newSetLookup)

            val removedSet = oldSet.subtract(newSet)
            groupManager.removeAccess(removedSet, this@Group.session.sessionId.toData())
        }
    }

    fun add(participant: Card): Completable =
            add(FindUsersResult(mapOf(participant.identity to participant)))

    fun remove(participant: Card): Completable =
            remove(FindUsersResult(mapOf(participant.identity to participant)))

    companion object {
        internal fun validateParticipantsCount(count: Int) {
            if (count !in VALID_PARTICIPANTS_COUNT_RANGE)
                throw GroupException(GroupException.Description.INVALID_PARTICIPANTS_COUNT)
        }

        val VALID_PARTICIPANTS_COUNT_RANGE = 1..100
    }
}
