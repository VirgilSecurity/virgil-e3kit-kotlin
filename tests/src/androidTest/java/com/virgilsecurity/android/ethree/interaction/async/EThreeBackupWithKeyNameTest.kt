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

package com.virgilsecurity.android.ethree.interaction.async

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.virgilsecurity.android.common.exception.EThreeException
import com.virgilsecurity.android.common.model.EThreeParams
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.android.ethree.utils.TestConfig.Companion.virgilServiceAddress
import com.virgilsecurity.android.ethree.utils.TestUtils
import com.virgilsecurity.common.callback.OnCompleteListener
import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.cloud.CloudKeyStorage
import com.virgilsecurity.keyknox.crypto.KeyknoxCrypto
import com.virgilsecurity.keyknox.storage.SyncKeyStorage
import com.virgilsecurity.pythia.brainkey.BrainKey
import com.virgilsecurity.pythia.brainkey.BrainKeyContext
import com.virgilsecurity.pythia.client.VirgilPythiaClient
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyStorage
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class EThreeBackupWithKeyNameTest {

    private lateinit var identity: String
    private lateinit var keyName: String
    private lateinit var password: String
    private lateinit var jwtGenerator: JwtGenerator
    private lateinit var keyStorage: KeyStorage

    @Before
    fun setup() {
        identity = "identity-" + UUID.randomUUID().toString()
        keyName = "key-" + UUID.randomUUID().toString()
        password = "pwd-" + UUID.randomUUID().toString()

        jwtGenerator = JwtGenerator(
            TestConfig.appId,
            TestConfig.appKey,
            TestConfig.appPublicKeyId,
            TimeSpan.fromTime(600, TimeUnit.SECONDS),
            VirgilAccessTokenSigner(TestConfig.virgilCrypto)
        )

        keyStorage = DefaultKeyStorage(TestConfig.DIRECTORY_PATH, TestConfig.KEYSTORE_NAME)
    }

    private fun initAndRegisterEThree(identity: String): EThree {
        val eThree = initEThree(identity)
        registerEThree(eThree)
        return eThree
    }

    private fun initEThree(identity: String): EThree {
        val params = EThreeParams(identity, {jwtGenerator.generateToken(identity).stringRepresentation()}, TestConfig.context)

        return EThree(params)
    }

    private fun registerEThree(eThree: EThree) {
        eThree.register().execute()
    }

    private fun initSyncKeyStorage(identity: String, passwordBrainKey: String): SyncKeyStorage {
        val tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback {
            jwtGenerator.generateToken(identity)
        })
        val brainKeyContext = BrainKeyContext.Builder()
                .setAccessTokenProvider(tokenProvider)
                .setPythiaClient(VirgilPythiaClient(virgilServiceAddress))
                .setPythiaCrypto(VirgilPythiaCrypto())
                .build()
        val keyPair = BrainKey(brainKeyContext).generateKeyPair(passwordBrainKey)

        val syncKeyStorage = SyncKeyStorage(
            identity,
            keyStorage,
            CloudKeyStorage(
                KeyknoxManager(
                    KeyknoxClient(tokenProvider, URL(virgilServiceAddress)),
                    KeyknoxCrypto()
                ),
                listOf(keyPair.publicKey),
                keyPair.privateKey
            )
        )

        syncKeyStorage.sync()

        return syncKeyStorage
    }

    // STE-15_1
    @Test fun backup_key_before_register() {
        val eThree = initEThree(identity)

        val waiter = CountDownLatch(1)
        var failedToBackup = false
        eThree.backupPrivateKey(keyName, password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Log.e(TAG, "No private key. Backup should fail")
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                if (throwable is EThreeException
                    && throwable.description == EThreeException.Description.MISSING_PRIVATE_KEY) {
                    failedToBackup = true
                }

                waiter.countDown()
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failedToBackup)
    }

    // STE-15_2-4
    @Test fun backup_key_after_register() {
        val eThree = initAndRegisterEThree(identity)

        val waiter = CountDownLatch(1)
        var successfullyBackuped = false
        eThree.backupPrivateKey(keyName, password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                successfullyBackuped = true
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.e(TAG, "Backup private key failed", throwable)
                waiter.countDown()
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(successfullyBackuped)

        val waiterTwo = CountDownLatch(1)
        var failedToBackup = false
        eThree.backupPrivateKey(keyName, password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Log.e(TAG, "Private key backup exists. Backup with the same key should fail")
                waiterTwo.countDown()
            }

            override fun onError(throwable: Throwable) {
                if (throwable is EThreeException
                    && throwable.description
                    == EThreeException.Description.PRIVATE_KEY_BACKUP_EXISTS) {

                    failedToBackup = true
                } else {
                    Log.e(TAG, "Backup failed with unpredictable exception", throwable)
                }

                waiterTwo.countDown()
            }
        })
        waiterTwo.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failedToBackup)
    }

    // STE-16
    @Test fun restore_private_key() {
        val eThreeWithPass = initAndRegisterEThree(identity)

        val waiter = CountDownLatch(1)
        var backupSuccessful = false
        eThreeWithPass.backupPrivateKey(keyName, password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                backupSuccessful = true
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.e(TAG, "Backup failed", throwable)
                waiter.countDown()
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(backupSuccessful)

        eThreeWithPass.cleanup()
        val waiterTwo = CountDownLatch(1)
        var restoreSuccessful = false
        eThreeWithPass.restorePrivateKey(keyName, password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                restoreSuccessful = true
                waiterTwo.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.e(TAG, "Restoring failed", throwable)
                waiterTwo.countDown()
            }
        })
        waiterTwo.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(restoreSuccessful)

        val waiterThree = CountDownLatch(1)
        var failedToRestore = false
        eThreeWithPass.restorePrivateKey(keyName, password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Log.e(TAG, "Private key is already exists. Restore should fail")
                waiterThree.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.d(TAG, "Exception type is: " + throwable.javaClass.canonicalName)
                if (throwable is EThreeException
                    && throwable.description == EThreeException.Description.PRIVATE_KEY_EXISTS) {
                    failedToRestore = true
                }

                waiterThree.countDown()
            }
        })
        waiterThree.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failedToRestore)
    }

    @Test fun restore_private_key_dublicate() {
        val keyPassword = UUID.randomUUID().toString()

        val eThreeWithPass = initAndRegisterEThree(identity)

        var waiter = CountDownLatch(1)
        var backupSuccessful = false
        eThreeWithPass.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Log.d(TAG, "Private key backup success")
                backupSuccessful = true
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.e(TAG, "Backup failed", throwable)
                waiter.countDown()
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(backupSuccessful)

        waiter = CountDownLatch(1)
        backupSuccessful = false
        eThreeWithPass.backupPrivateKey(keyName, keyPassword).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Log.d(TAG, "Private key '${keyName}' backup success")
                backupSuccessful = true
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.e(TAG, "Private key '${keyName}' backup failed", throwable)
                waiter.countDown()
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(backupSuccessful)

        eThreeWithPass.cleanup()
        waiter = CountDownLatch(1)
        var restoreSuccessful = false
        eThreeWithPass.restorePrivateKey(keyName, keyPassword).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Log.d(TAG, "Private key '${keyName}' restored")
                restoreSuccessful = true
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.e(TAG, "Restore privatekey failed", throwable)
                waiter.countDown()
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(restoreSuccessful)

        eThreeWithPass.cleanup()
        waiter = CountDownLatch(1)
        restoreSuccessful = false
        eThreeWithPass.restorePrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Log.d(TAG, "Private key restored")
                restoreSuccessful = true
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.e(TAG, "Restore key failed", throwable)
                waiter.countDown()
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(restoreSuccessful)
    }

    // STE-17
    @Test fun change_password() {
        Log.d(TAG, "Change password")
        val passwordNew = UUID.randomUUID().toString()

        val eThreeWithPass = initAndRegisterEThree(identity)

        var waiter = CountDownLatch(1)
        var success = false
        eThreeWithPass.backupPrivateKey(keyName, password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                success = true
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.e(TAG, "Backup failed", throwable)
                waiter.countDown()
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(success)

        waiter = CountDownLatch(1)
        var passwordNotChanged = true
        eThreeWithPass.changePassword(keyName, UUID.randomUUID().toString(), passwordNew)
                .addCallback(object : OnCompleteListener {
                    override fun onSuccess() {
                        Log.e(TAG, "Change password with wrong password should fail, but successful")
                        waiter.countDown()
                    }

                    override fun onError(throwable: Throwable) {
                        if (throwable is EThreeException
                                && throwable.description == EThreeException.Description.WRONG_PASSWORD) {
                            passwordNotChanged = true
                        } else {
                            Log.e(TAG, "Change password with wrong password failed with unpredictable exception", throwable)
                        }
                        waiter.countDown()
                    }
                })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(passwordNotChanged)

        val waiterOne = CountDownLatch(1)
        var passwordChanged = false
        eThreeWithPass.changePassword(keyName, password, passwordNew)
                .addCallback(object : OnCompleteListener {
                    override fun onSuccess() {
                        passwordChanged = true
                        waiterOne.countDown()
                    }

                    override fun onError(throwable: Throwable) {
                        Log.e(TAG, "Change password failed", throwable)
                        waiterOne.countDown()
                    }
                })
        waiterOne.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(passwordChanged)

        eThreeWithPass.cleanup()
        val waiterTwo = CountDownLatch(1)
        var failedWithOldPassword = false
        eThreeWithPass.restorePrivateKey(keyName, password).addCallback(object : OnCompleteListener {

            override fun onSuccess() {
                Log.e(TAG, "Restore key with old password should fail")
                waiterTwo.countDown()
            }

            override fun onError(throwable: Throwable) {
                if (throwable is EThreeException
                    && throwable.description == EThreeException.Description.WRONG_PASSWORD) {
                    failedWithOldPassword = true
                } else {
                    Log.e(TAG, "Restore key with old password failed with unpredictable exception", throwable)
                }

                waiterTwo.countDown()
            }
        })
        waiterTwo.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failedWithOldPassword)

        val waiterThree = CountDownLatch(1)
        var successWithNewPassword = false
        eThreeWithPass.restorePrivateKey(keyName, passwordNew).addCallback(object : OnCompleteListener {

            override fun onSuccess() {
                successWithNewPassword = true
                waiterThree.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.e(TAG, "Restore key with new password failed", throwable)
                waiterThree.countDown()
            }
        })
        waiterThree.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(successWithNewPassword)
    }

    // STE-18_2
    @Test fun reset_key_backup_after_backup() {
        val eThreeWithPass = initAndRegisterEThree(identity)

        val waiter = CountDownLatch(1)
        var success = false
        eThreeWithPass.backupPrivateKey(keyName, password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                success = true
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.e(TAG, "Backup failed", throwable)
                waiter.countDown()
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(success)

        val waiterTwo = CountDownLatch(1)
        var successfulKeyReset = false
        eThreeWithPass.resetPrivateKeyBackupWithKeyName(keyName).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                successfulKeyReset = true
                waiterTwo.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.e(TAG, "Reset private key failed", throwable)
                waiterTwo.countDown()
            }
        })
        waiterTwo.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(successfulKeyReset)

        eThreeWithPass.cleanup()
        val waiterTree = CountDownLatch(1)
        var restoreFailed = false
        eThreeWithPass.restorePrivateKey(keyName, password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Log.e(TAG, "Restoring succeful, but should fail")
                waiterTree.countDown()
            }

            override fun onError(throwable: Throwable) {
                restoreFailed = true
                waiterTree.countDown()
            }
        })
        waiterTree.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(restoreFailed)
    }

    companion object {
        const val TAG = "EThreeBackupTest"
    }
}
