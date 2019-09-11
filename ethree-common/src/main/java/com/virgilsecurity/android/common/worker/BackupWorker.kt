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

import com.virgilsecurity.android.common.EThreeCore
import com.virgilsecurity.android.common.exception.BackupKeyException
import com.virgilsecurity.android.common.exception.PrivateKeyNotFoundException
import com.virgilsecurity.android.common.exception.RestoreKeyException
import com.virgilsecurity.android.common.exception.WrongPasswordException
import com.virgilsecurity.android.common.util.Const
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.keyknox.exception.DecryptionFailedException
import com.virgilsecurity.keyknox.exception.EntryAlreadyExistsException
import com.virgilsecurity.pythia.brainkey.BrainKey
import com.virgilsecurity.pythia.brainkey.BrainKeyContext
import com.virgilsecurity.pythia.client.VirgilPythiaClient
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto

/**
 * BackupWorker
 */
class BackupWorker {

    /**
     * Encrypts the user's private key using the user's [password] and backs up the encrypted
     * private key to Virgil's cloud. This enables users to log in from other devices and have
     * access to their private key to decrypt data.
     *
     * Encrypts loaded from private keys local storage user's *Private key* using *Public key*
     * that is generated based on provided [password] after that backs up encrypted user's
     * *Private key* to the Virgil's cloud storage.
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws PrivateKeyNotFoundException
     * @throws BackupKeyException
     */
    fun backupPrivateKey(password: String) = object : Completable {
        override fun execute() {
            try {
                checkPrivateKeyOrThrow()

                require(!password.isBlank()) { "\'password\' should not be empty" }

                with(keyStorageLocal.load()) {
                    keyManagerCloud.store(password, this.value, this.meta)
                }
            } catch (throwable: Throwable) {
                if (throwable is EntryAlreadyExistsException)
                    throw BackupKeyException("Key with identity ${currentIdentity()} " +
                                             "already backed up.")
                else
                    throw throwable
            }
        }
    }

    /**
     * Pulls user's private key from the Virgil's cloud, decrypts it with *Private key* that
     * is generated based on provided [password] and saves it to the current private keys
     * local storage.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws WrongPasswordException
     * @throws RestoreKeyException
     */
    fun restorePrivateKey(password: String) = object : Completable {
        override fun execute() {
            try {
                if (keyStorageLocal.exists())
                    throw RestoreKeyException("You already have a Private Key on this device" +
                                              "for identity: ${currentIdentity()}. Please, use" +
                                              "\'cleanup()\' function first.")

                if (keyManagerCloud.exists(password)) {
                    Thread.sleep(EThreeCore.THROTTLE_TIMEOUT) // To avoid next request been throttled

                    val keyEntry = keyManagerCloud.retrieve(password)
                    keyStorageLocal.store(keyEntry.data)
                } else {
                    throw RestoreKeyException("There is no key backup with " +
                                              "identity: ${currentIdentity()}")
                }
            } catch (throwable: Throwable) {
                if (throwable is DecryptionFailedException)
                    throw WrongPasswordException("Specified password is not valid.")
                else
                    throw throwable
            }
        }
    }

    /**
     * Changes the password of the private key backup.
     *
     * Pulls user's private key from the Virgil's cloud storage, decrypts it with *Private key*
     * that is generated based on provided [oldPassword] after that encrypts user's *Private key*
     * using *Public key* that is generated based on provided [newPassword] and pushes encrypted
     * user's *Private key* to the Virgil's cloud storage.
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws PrivateKeyNotFoundException
     */
    fun changePassword(oldPassword: String,
                       newPassword: String) = object : Completable {
        override fun execute() {
            checkPrivateKeyOrThrow()

            if (oldPassword.isBlank())
                throw IllegalArgumentException("\'oldPassword\' should not be empty")
            if (newPassword.isBlank())
                throw IllegalArgumentException("\'newPassword\' should not be empty")
            if (newPassword == oldPassword)
                throw IllegalArgumentException("\'newPassword\' can't be the same as the old one")

            val brainKeyContext = BrainKeyContext.Builder()
                    .setAccessTokenProvider(tokenProvider)
                    .setPythiaClient(VirgilPythiaClient(Const.VIRGIL_BASE_URL))
                    .setPythiaCrypto(VirgilPythiaCrypto())
                    .build()

            val keyPair = BrainKey(brainKeyContext).generateKeyPair(newPassword)

            Thread.sleep(EThreeCore.THROTTLE_TIMEOUT) // To avoid next request been throttled

            keyManagerCloud.updateRecipients(oldPassword,
                                             listOf(keyPair.publicKey),
                                             keyPair.privateKey)
        }
    }

    /**
     * Deletes the user's private key from Virgil's cloud.
     *
     * Deletes private key backup using specified [password] and provides [onCompleteListener]
     * callback that will notify you with successful completion or with a [Throwable] if
     * something went wrong.
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws PrivateKeyNotFoundException
     * @throws WrongPasswordException
     */
    @JvmOverloads fun resetPrivateKeyBackup(password: String? = null) = object : Completable {
        override fun execute() {
            try {
                checkPrivateKeyOrThrow()

                if (password == null) {
                    keyManagerCloud.deleteAll()
                } else {
                    if (password.isBlank())
                        throw IllegalArgumentException("\'password\' should not be empty")

                    keyManagerCloud.delete(password)
                }
            } catch (throwable: Throwable) {
                if (throwable is DecryptionFailedException)
                    throw WrongPasswordException("Specified password is not valid.")
                else
                    throw throwable
            }
        }

    }
}
