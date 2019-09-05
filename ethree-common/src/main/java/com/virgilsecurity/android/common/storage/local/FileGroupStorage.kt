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

package com.virgilsecurity.android.common.storage.local

import com.virgilsecurity.android.common.exception.FileGroupStorageException
import com.virgilsecurity.android.common.model.GroupInfo
import com.virgilsecurity.android.common.model.RawGroup
import com.virgilsecurity.android.common.model.Ticket
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.common.util.toHexString
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.storage.FileSystemEncrypted
import com.virgilsecurity.sdk.storage.FileSystemEncryptedCredentials
import java.io.File

/**
 * FileGroupStorage
 */
@ExperimentalUnsignedTypes
class FileGroupStorage internal constructor(
        private val identity: String,
        crypto: VirgilCrypto,
        identityKeyPair: VirgilKeyPair,
        rootPath: String
) { // TODO use internal everywhere possible

    private val fileSystemEncrypted: FileSystemEncrypted

    init {
        val credentials = FileSystemEncryptedCredentials(crypto, identityKeyPair)
        val fullPath: String = rootPath +
                               File.separator +
                               identityKeyPair +
                               File.separator +
                               STORAGE_POSTFIX_E3KIT +
                               File.separator +
                               STORAGE_POSTFIX_GROUPS

        fileSystemEncrypted = FileSystemEncrypted(fullPath, credentials)
    }

    internal fun store(group: RawGroup) {
        val ticket = group.tickets.last()

        val subdir = ticket.groupMessage.sessionId.toHexString()

        val name = ticket.groupMessage.epoch.toString() // TODO was it meant like that?
        val data = ticket.serialize()

        fileSystemEncrypted.write(data, name, subdir)
    }

    internal fun retrieveInfo(sessionId: Data): GroupInfo = retrieveGroupInfo(sessionId)

    internal fun retrieve(sessionId: Data, count: Int): RawGroup {
        val tickets = retrieveLastTickets(count, sessionId)
        val groupInfo = retrieveGroupInfo(sessionId)

        return RawGroup(groupInfo, tickets)
    }

    internal fun retrieve(sessionId: Data, epoch: UInt): RawGroup {
        val ticket = retrieveTicket(sessionId, epoch)
        val groupInfo = retrieveGroupInfo(sessionId)

        return RawGroup(groupInfo, listOf(ticket))
    }

    internal fun delete(sessionId: Data) = fileSystemEncrypted.delete(sessionId.toHexString())

    internal fun reset() = fileSystemEncrypted.delete()

    private fun retrieveTicket(sessionId: Data, epoch: UInt): Ticket {
        val subdir = sessionId.toHexString() + File.separator + TICKETS_SUBDIR
        val name = epoch.toString()

        val data = fileSystemEncrypted.read(name, subdir)

        return Ticket.deserialize(data)
    }

    private fun retrieveLastTickets(count: Int, sessionId: Data): List<Ticket> {
        val result = mutableListOf<Ticket>()

        val subdir = sessionId.toHexString() + File.separator + TICKETS_SUBDIR

        val epochs = fileSystemEncrypted
                .listFileNames(subdir).map { name ->
                    try {
                        name.toUInt()
                    } catch (exception: NumberFormatException) {
                        throw FileGroupStorageException("Invalid file name")
                    }
                }
                .sorted()
                .takeLast(count)

        epochs.forEach { epoch ->
            try {
                retrieveTicket(sessionId, epoch)
            } catch (throwable: Throwable) {
                throw FileGroupStorageException("File is empty")
            }.also { ticket ->
                result.add(ticket)
            }
        }

        return result
    }

    private fun retrieveGroupInfo(sessionId: Data): GroupInfo {
        val subdir = sessionId.toHexString()

        val data = fileSystemEncrypted.read(GROUP_INFO_NAME, subdir)

        return GroupInfo.deserialize(data)
    }

    companion object {
        private const val GROUP_INFO_NAME = "GROUP_INFO"
        private const val TICKETS_SUBDIR = "TICKETS"
        private const val STORAGE_POSTFIX_E3KIT = "VIRGIL-E3KIT"
        private const val STORAGE_POSTFIX_GROUPS = "GROUPS"
    }
}
