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

import com.virgilsecurity.android.common.EThreeCore
import com.virgilsecurity.android.common.exception.EThreeException
import com.virgilsecurity.android.common.manager.LookupManager
import com.virgilsecurity.android.common.model.DerivedPasswords
import com.virgilsecurity.android.common.storage.cloud.CloudKeyManager
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.common.extension.toData
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.keyknox.exception.EntryAlreadyExistsException
import com.virgilsecurity.keyknox.exception.EntryNotFoundException
import com.virgilsecurity.keyknox.utils.unwrapCompanionClass
import com.virgilsecurity.sdk.crypto.HashAlgorithm
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryAlreadyExistsException
import java.util.logging.Logger

/**
 * BackupWorker
 */
internal class BackupWorker internal constructor(
        private val localKeyStorage: LocalKeyStorage,
        private val keyManagerCloud: CloudKeyManager,
        private val privateKeyChanged: (EThreeCore.PrivateKeyChangedParams?) -> Unit,
        private val lookupManager: LookupManager,
        private val identity: String
) {

    internal fun backupPrivateKey(keyName: String?, password: String): Completable = object : Completable {
        override fun execute() {
            logger.fine("Backup private key $keyName")
            try {
                require(password.isNotEmpty()) { "\'password\' should not be empty" }

                val identityKeyPair = localKeyStorage.retrieveKeyPair()
                keyManagerCloud.store(identityKeyPair.privateKey, keyName, password)
            } catch (exception: EntryAlreadyExistsException) {
                throw EThreeException(EThreeException.Description.PRIVATE_KEY_BACKUP_EXISTS,
                                      exception)
            }
        }
    }

    internal fun restorePrivateKey(keyName: String?, password: String): Completable = object : Completable {
        override fun execute() {
            logger.fine("Restore private key $keyName")
            try {
                require(password.isNotEmpty()) { "\'password\' should not be empty" }

                val entry = try {
                    keyManagerCloud.retrieve(keyName, password)
                } catch (exception: EntryNotFoundException) {
                    throw EThreeException(EThreeException.Description.NO_PRIVATE_KEY_BACKUP,
                                          exception)
                }

                val card = lookupManager.lookupCard(this@BackupWorker.identity)

                localKeyStorage.store(entry.data.toData())

                val params = EThreeCore.PrivateKeyChangedParams(card, isNew = false)

                privateKeyChanged(params)
            } catch (exception: KeyEntryAlreadyExistsException) {
                throw EThreeException(EThreeException.Description.PRIVATE_KEY_EXISTS,
                                      exception) // FIXME add in swift or remove here
            }
        }
    }

    internal fun changePassword(oldPassword: String,
                                newPassword: String): Completable = object : Completable {
        override fun execute() {
            logger.fine("Change password")
            require(oldPassword.isNotEmpty()) { "\'oldPassword\' should not be empty" }
            require(newPassword.isNotEmpty()) { "\'newPassword\' should not be empty" }
            if (oldPassword == newPassword)
                throw EThreeException(EThreeException.Description.SAME_PASSWORD)

            keyManagerCloud.changePassword(oldPassword, newPassword)
        }
    }

    internal fun resetPrivateKeyBackup(): Completable = object : Completable {
        override fun execute() {
            logger.fine("Reset private key backup")
            try {
                keyManagerCloud.deleteAll()
            } catch (exception: EntryNotFoundException) {
                throw EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY, exception)
            }
        }

    }

    @Deprecated("Check 'replace with' section.",
                ReplaceWith("Please, use resetPrivateKeyBackup without password instead."))
    internal fun resetPrivateKeyBackup(password: String): Completable = object : Completable {
        override fun execute() {
            logger.fine("Reset private key backup with password")
            try {
                keyManagerCloud.delete(password)
            } catch (exception: EntryNotFoundException) {
                throw EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY, exception)
            }
        }

    }

    companion object {
        private val logger = Logger.getLogger(unwrapCompanionClass(this::class.java).name)
    }
}
