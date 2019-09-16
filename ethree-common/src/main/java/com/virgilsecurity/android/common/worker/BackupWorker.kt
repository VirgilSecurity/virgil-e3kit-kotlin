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

import com.virgilsecurity.android.common.KeyManagerCloudStub
import com.virgilsecurity.android.common.exception.BackupKeyException
import com.virgilsecurity.android.common.exception.PrivateKeyNotFoundException
import com.virgilsecurity.android.common.exception.RestoreKeyException
import com.virgilsecurity.android.common.exception.WrongPasswordException
import com.virgilsecurity.android.common.storage.local.KeyStorageLocal
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.cards.Card

/**
 * BackupWorker
 */
internal class BackupWorker(
        private val keyStorageLocal: KeyStorageLocal,
        private val keyManagerCloud: KeyManagerCloudStub, // FIXME to actual KeyManagerCloud
        private val privateKeyChanged: (Card?) -> Unit
) {

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
    internal fun backupPrivateKey(password: String): Completable = object : Completable {
        override fun execute() {
            val identityKeyPair = keyStorageLocal.load()
            keyManagerCloud.store(identityKeyPair.privateKey, password)
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
    internal fun restorePrivateKey(password: String): Completable = object : Completable {
        override fun execute() {
            val entry = keyManagerCloud.retrieve(password)
            keyStorageLocal.store(Data(entry.data))
            privateKeyChanged(null)
        }
    }

    /**
     * Changes the password on a backed-up private key.
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
    internal fun changePassword(oldPassword: String,
                       newPassword: String): Completable = object : Completable {
        override fun execute() {
            keyManagerCloud.changePassword(oldPassword, newPassword)
        }
    }

    /**
     * Deletes Private Key stored on Virgil's cloud. This will disable user to log in from
     * other devices.
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
    @JvmOverloads
    internal fun resetPrivateKeyBackup(password: String? = null): Completable = object : Completable {
        override fun execute() {
            if (password != null)
                keyManagerCloud.delete(password)
            else
                keyManagerCloud.deleteAll()
        }

    }
}
