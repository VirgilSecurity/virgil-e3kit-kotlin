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

package com.virgilsecurity.android.common.worker

import com.virgilsecurity.android.common.manager.GroupManager
import com.virgilsecurity.android.common.model.FindUsersResult
import com.virgilsecurity.android.common.model.Group
import com.virgilsecurity.android.common.model.Ticket
import com.virgilsecurity.common.extension.toData
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.common.model.Result
import com.virgilsecurity.keyknox.utils.unwrapCompanionClass
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import java.nio.charset.StandardCharsets
import java.util.logging.Logger

/**
 * GroupWorker
 */
internal class GroupWorker internal constructor(
        private val identity: String,
        private val crypto: VirgilCrypto,
        private val getGroupManager: () -> GroupManager,
        private val computeSessionId: (Data) -> Data
) {

    internal fun createGroup(identifier: Data, users: FindUsersResult? = null): Result<Group> =
            object : Result<Group> {
                override fun get(): Group {
                    require(identifier.value.isNotEmpty()) { "\'identifier\' should not be empty" }
                    logger.fine("Create group ${identifier.toBase64String()}")

                    val sessionId = computeSessionId(identifier)
                    val usersNew = users ?: FindUsersResult()
                    val participants = usersNew.keys + identity

                    Group.validateParticipantsCount(participants.size)

                    val ticket = Ticket(crypto, sessionId, participants)

                    return getGroupManager().store(ticket, usersNew.values.toList())
                }
            }

    internal fun getGroup(identifier: Data): Group? {
        require(identifier.value.isNotEmpty()) { "\'identifier\' should not be empty" }
        logger.fine("Get group ${identifier.toBase64String()}")

        val sessionId = computeSessionId(identifier)
        return getGroupManager().retrieve(sessionId)
    }

    internal fun loadGroup(identifier: Data, card: Card): Result<Group> =
            object : Result<Group> {
                override fun get(): Group {
                    require(identifier.value.isNotEmpty()) { "\'identifier\' should not be empty" }
                    logger.fine("Load group ${identifier.toBase64String()}")

                    val sessionId = computeSessionId(identifier)
                    return getGroupManager().pull(sessionId, card)
                }
            }

    internal fun deleteGroup(identifier: Data): Completable =
            object : Completable {
                override fun execute() {
                    require(identifier.value.isNotEmpty()) { "\'identifier\' should not be empty" }
                    logger.fine("Delete group ${identifier.toBase64String()}")

                    val sessionId = computeSessionId(identifier)
                    getGroupManager().delete(sessionId)
                }
            }

    internal fun createGroup(identifier: String, users: FindUsersResult? = null): Result<Group> {
        require(identifier.isNotEmpty()) { "\'identifier\' should not be empty" }

        val identifierData = identifier.toData(StandardCharsets.UTF_8)

        return createGroup(identifierData, users)
    }

    internal fun getGroup(identifier: String): Group? {
        require(identifier.isNotEmpty()) { "\'identifier\' should not be empty" }

        val identifierData = identifier.toData(StandardCharsets.UTF_8)

        return getGroup(identifierData)
    }

    internal fun loadGroup(identifier: String, card: Card): Result<Group> {
        require(identifier.isNotEmpty()) { "\'identifier\' should not be empty" }

        val identifierData = identifier.toData(StandardCharsets.UTF_8)

        return loadGroup(identifierData, card)
    }

    internal fun deleteGroup(identifier: String): Completable {
        require(identifier.isNotEmpty()) { "\'identifier\' should not be empty" }

        val identifierData = identifier.toData(StandardCharsets.UTF_8)

        return deleteGroup(identifierData)
    }

    companion object {
        private val logger = Logger.getLogger(unwrapCompanionClass(this::class.java).name)
    }
}
