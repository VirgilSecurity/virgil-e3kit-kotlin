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
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.exception.EThreeException
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.android.ethree.utils.TestConfig.Companion.virgilServiceAddress
import com.virgilsecurity.android.ethree.utils.TestUtils
import com.virgilsecurity.common.callback.OnCompleteListener
import com.virgilsecurity.common.callback.OnResultListener
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

/**
 * Created by:
 * Danylo Oliinyk
 * on
 * 10/9/18
 * at Virgil Security
 */
@RunWith(AndroidJUnit4::class)
class EThreeBackupTest {

    private lateinit var jwtGenerator: JwtGenerator
    private lateinit var keyStorage: KeyStorage

    @Before
    fun setup() {
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
        var eThree: EThree? = null
        val waiter = CountDownLatch(1)

        EThree.initialize(TestConfig.context,
                          object : OnGetTokenCallback {
                              override fun onGetToken(): String {
                                  return jwtGenerator.generateToken(
                                      identity)
                                          .stringRepresentation()
                              }
                          })
                .addCallback(object : OnResultListener<EThree> {
                    override fun onSuccess(result: EThree) {
                        eThree = result
                        waiter.countDown()
                    }

                    override fun onError(throwable: Throwable) {
                        fail(throwable.message)
                    }

                })

        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)

        return eThree!!
    }

    private fun registerEThree(eThree: EThree): EThree {
        val waiter = CountDownLatch(1)

        eThree.register().addCallback(object : OnCompleteListener {

            override fun onSuccess() {
                // Good, go on
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })

        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)

        return eThree
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
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()

        val eThree = initEThree(identity)

        val waiter = CountDownLatch(1)
        var failedToBackup = false
        eThree.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Illegal State")
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
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val eThree = initAndRegisterEThree(identity)

        val waiter = CountDownLatch(1)
        var successfullyBackuped = false
        eThree.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                successfullyBackuped = true
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(successfullyBackuped)

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        assertTrue(syncKeyStorage.exists(identity))
        val retrievedKey = syncKeyStorage.retrieve(identity)
        assertEquals(TestConfig.virgilCrypto.importPrivateKey(keyStorage.load(identity).value),
                     TestConfig.virgilCrypto.importPrivateKey(retrievedKey.value))

        val waiterTwo = CountDownLatch(1)
        var failedToBackup = false
        eThree.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Illegal State")
            }

            override fun onError(throwable: Throwable) {
                if (throwable is EThreeException
                    && throwable.description
                    == EThreeException.Description.PRIVATE_KEY_BACKUP_EXISTS) {

                    failedToBackup = true
                }

                waiterTwo.countDown()
            }
        })
        waiterTwo.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failedToBackup)
    }

    // STE-16
    @Test fun restore_private_key() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()

        val eThreeWithPass = initAndRegisterEThree(identity)

        val waiter = CountDownLatch(1)
        eThreeWithPass.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)

        eThreeWithPass.cleanup()
        val waiterTwo = CountDownLatch(1)
        var restoreSuccessful = false
        eThreeWithPass.restorePrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                restoreSuccessful = true
                waiterTwo.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiterTwo.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(restoreSuccessful)

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        assertTrue(syncKeyStorage.exists(identity))
        val retrievedKey = syncKeyStorage.retrieve(identity)
        assertEquals(TestConfig.virgilCrypto.importPrivateKey(keyStorage.load(identity).value),
                     TestConfig.virgilCrypto.importPrivateKey(retrievedKey.value))

        val waiterThree = CountDownLatch(1)
        var failedToRestore = false
        eThreeWithPass.restorePrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Illegal state")
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
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val keyName = UUID.randomUUID().toString()
        val keyPassword = UUID.randomUUID().toString()

        val eThreeWithPass = initAndRegisterEThree(identity)

        var waiter = CountDownLatch(1)
        eThreeWithPass.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Log.d(TAG, "Private key backup success")
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.e(TAG, throwable.message)
                fail(throwable.message)
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)

        waiter = CountDownLatch(1)
        eThreeWithPass.backupPrivateKey(keyName, keyPassword).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Log.d(TAG, "Private key '${keyName}' backup success")
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                Log.e(TAG, "Private key '${keyName}' backup failed", throwable)
                fail(throwable.message)
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)

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
                Log.e(TAG, throwable.message)
                fail(throwable.message)
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
                Log.e(TAG, throwable.message)
                fail(throwable.message)
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(restoreSuccessful)
    }

    @Test fun restore_private_key_with_key_name() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val keyName = UUID.randomUUID().toString()

        val eThreeWithPass = initAndRegisterEThree(identity)

        val waiter = CountDownLatch(1)
        eThreeWithPass.backupPrivateKey(keyName, password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Log.d(TAG, "Backup '${keyName}' private key success")
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)

        eThreeWithPass.cleanup()
        val waiterTwo = CountDownLatch(1)
        var restoreSuccessful = false
        eThreeWithPass.restorePrivateKey(keyName, password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                restoreSuccessful = true
                Log.d(TAG, "Private key '${keyName}' restored")
                waiterTwo.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiterTwo.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(restoreSuccessful)

        val waiterThree = CountDownLatch(1)
        var failedToRestore = false
        eThreeWithPass.restorePrivateKey(keyName, password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Illegal state")
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

    // STE-17
    @Test fun change_password() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val passwordNew = UUID.randomUUID().toString()

        val eThreeWithPass = initAndRegisterEThree(identity)

        val waiter = CountDownLatch(1)
        eThreeWithPass.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)

        val waiterOne = CountDownLatch(1)
        var passwordChanged = false
        eThreeWithPass.changePassword(password, passwordNew)
                .addCallback(object : OnCompleteListener {
                    override fun onSuccess() {
                        passwordChanged = true
                        waiterOne.countDown()
                    }

                    override fun onError(throwable: Throwable) {
                        fail(throwable.message)
                    }
                })
        waiterOne.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(passwordChanged)

        eThreeWithPass.cleanup()
        val waiterTwo = CountDownLatch(1)
        var failedWithOldPassword = false
        eThreeWithPass.restorePrivateKey(password).addCallback(object : OnCompleteListener {

            override fun onSuccess() {
                fail("Illegal State")
            }

            override fun onError(throwable: Throwable) {
                if (throwable is EThreeException
                    && throwable.description == EThreeException.Description.WRONG_PASSWORD) {
                    failedWithOldPassword = true
                }

                waiterTwo.countDown()
            }
        })
        waiterTwo.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failedWithOldPassword)

        val waiterThree = CountDownLatch(1)
        var successWithNewPassword = false
        eThreeWithPass.restorePrivateKey(passwordNew).addCallback(object : OnCompleteListener {

            override fun onSuccess() {
                successWithNewPassword = true
                waiterThree.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiterThree.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(successWithNewPassword)
    }

    // STE-18_1
    @Test fun reset_key_backup_before_backup() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val eThreeWithPass = initEThree(identity)

        val waiter = CountDownLatch(1)
        var failedToReset = false
        eThreeWithPass.resetPrivateKeyBackup(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Illegal state")
            }

            override fun onError(throwable: Throwable) {
                if (throwable is EThreeException
                    && throwable.description == EThreeException.Description.MISSING_PRIVATE_KEY) {
                    failedToReset = true
                }

                waiter.countDown()
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failedToReset)

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        assertFalse(syncKeyStorage.exists(identity))
    }

    // STE-18_2
    @Test fun reset_key_backup_after_backup() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val eThreeWithPass = initAndRegisterEThree(identity)

        val waiter = CountDownLatch(1)
        eThreeWithPass.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)

        val waiterTwo = CountDownLatch(1)
        var successfulKeyReset = false
        eThreeWithPass.resetPrivateKeyBackup(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                successfulKeyReset = true
                waiterTwo.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiterTwo.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(successfulKeyReset)

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        assertFalse(syncKeyStorage.exists(identity))
    }

    // Reset without password
    @Test fun reset_key_backup_after_backup_no_password() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val eThreeWithPass = initAndRegisterEThree(identity)

        val waiter = CountDownLatch(1)
        eThreeWithPass.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)

        val waiterTwo = CountDownLatch(1)
        var successfulKeyReset = false
        eThreeWithPass.resetPrivateKeyBackup().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                successfulKeyReset = true
                waiterTwo.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiterTwo.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(successfulKeyReset)

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        assertFalse(syncKeyStorage.exists(identity))
    }

    @Test fun reset_backed_key_wrong_pass() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val eThreeWithPass = initAndRegisterEThree(identity)

        val waiter = CountDownLatch(1)
        eThreeWithPass.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiter.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)

        val waiterTwo = CountDownLatch(1)
        var failedKeyReset = false
        eThreeWithPass.resetPrivateKeyBackup(WRONG_PASSWORD)
                .addCallback(object : OnCompleteListener {
                    override fun onSuccess() {
                        fail("Illegal state")
                    }

                    override fun onError(throwable: Throwable) {
                        if (throwable is EThreeException
                            && throwable.description
                            == EThreeException.Description.WRONG_PASSWORD) {

                            failedKeyReset = true
                        }

                        waiterTwo.countDown()
                    }
                })
        waiterTwo.await(TestUtils.REQUEST_TIMEOUT, TimeUnit.SECONDS)
        assertTrue("Key reset failed with wrong error", failedKeyReset)
    }

    companion object {
        const val TAG = "EThreeBackupTest"
        const val WRONG_PASSWORD = "WRONG_PASSWORD"
    }
}
