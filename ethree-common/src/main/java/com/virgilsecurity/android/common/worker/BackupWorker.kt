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

package com.virgilsecurity.android.common.worker

import com.virgilsecurity.android.common.exception.BackupKeyException
import com.virgilsecurity.android.common.exception.EThreeException
import com.virgilsecurity.android.common.exception.PrivateKeyNotFoundException
import com.virgilsecurity.android.common.exception.RestoreKeyException
import com.virgilsecurity.android.common.storage.cloud.CloudKeyManager
import com.virgilsecurity.android.common.storage.local.KeyStorageLocal
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.keyknox.exception.EntryAlreadyExistsException
import com.virgilsecurity.keyknox.exception.EntryNotFoundException
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException

/**
 * BackupWorker
 */
internal class BackupWorker(
        private val keyStorageLocal: KeyStorageLocal,
        private val keyManagerCloud: CloudKeyManager,
        private val privateKeyChanged: (Card?) -> Unit
) {

    internal fun backupPrivateKey(password: String): Completable = object : Completable {
        override fun execute() {
            try {
                require(password.isNotEmpty()) { "\'password\' should not be empty" }

                val identityKeyPair = keyStorageLocal.load()
                keyManagerCloud.store(identityKeyPair.privateKey, password)
            } catch (e: EntryAlreadyExistsException) {
                throw BackupKeyException("Can't backup private key", e)
            }
        }
    }

    internal fun restorePrivateKey(password: String): Completable = object : Completable {
        override fun execute() {
            try {
                require(password.isNotEmpty()) { "\'password\' should not be empty" }

                val entry = keyManagerCloud.retrieve(password)
                keyStorageLocal.store(Data(entry.data))
                privateKeyChanged(null)
            } catch (e: KeyEntryAlreadyExistsException) {
                throw RestoreKeyException("Can't restore private key", e)
            }
        }
    }

    internal fun changePassword(oldPassword: String,
                                newPassword: String): Completable = object : Completable {
        override fun execute() {
            require(oldPassword.isNotEmpty()) { "\'oldPassword\' should not be empty" }
            require(newPassword.isNotEmpty()) { "\'newPassword\' should not be empty" }
            if (oldPassword == newPassword) throw EThreeException("To change password, please" +
                                                                  "provide new password that " +
                                                                  "differs from the old one.")

            keyManagerCloud.changePassword(oldPassword, newPassword)
        }
    }

    @JvmOverloads
    internal fun resetPrivateKeyBackup(password: String? = null): Completable = object : Completable {
        override fun execute() {
            if (password != null)
                try {
                    keyManagerCloud.delete(password)
                } catch (exception: EntryNotFoundException) {
                    throw PrivateKeyNotFoundException("Can't reset private key: private key not " +
                                                      "found", exception)
                }
            else
                keyManagerCloud.deleteAll()
        }

    }
}
