/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
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

package com.virgilsecurity.android.ethree.kotlin.interaction

import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.android.ethree.utils.TestConfig.Companion.virgilBaseUrl
import com.virgilsecurity.android.ethree.utils.TestUtils
import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.cloud.CloudKeyStorage
import com.virgilsecurity.keyknox.crypto.KeyknoxCrypto
import com.virgilsecurity.keyknox.storage.SyncKeyStorage
import com.virgilsecurity.pythia.brainkey.BrainKey
import com.virgilsecurity.pythia.brainkey.BrainKeyContext
import com.virgilsecurity.pythia.client.VirgilPythiaClient
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.model.RawSignedModel
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.CardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyStorage
import com.virgilsecurity.sdk.utils.Tuple
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
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
class EThreeBackupTest {

    private lateinit var jwtGenerator: JwtGenerator
    private lateinit var keyStorage: KeyStorage

    @Before
    fun setup() {
        TestUtils.pause()

        jwtGenerator = JwtGenerator(
            TestConfig.appId,
            TestConfig.apiKey,
            TestConfig.apiPublicKeyId,
            TimeSpan.fromTime(600, TimeUnit.SECONDS),
            VirgilAccessTokenSigner(TestConfig.virgilCrypto)
        )

        keyStorage = DefaultKeyStorage(TestConfig.DIRECTORY_PATH, TestConfig.KEYSTORE_NAME)
    }

    private fun initAndBootstrapEThree(identity: String): EThree {
        val eThree = initEThree(identity)
        bootstrapEThree(eThree)
        return eThree
    }

    private fun initEThree(identity: String): EThree {
        var eThree: EThree? = null
        val waiter = CountDownLatch(1)

        EThree.initialize(TestConfig.context, object : EThree.OnGetTokenCallback {
            override fun onGetToken(): String {
                return jwtGenerator.generateToken(identity).stringRepresentation()
            }
        }, object : EThree.OnResultListener<EThree> {
            override fun onSuccess(result: EThree) {
                eThree = result
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }

        })

        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

        return eThree!!
    }

    private fun bootstrapEThree(eThree: EThree): EThree {
        val waiter = CountDownLatch(1)

        eThree.register(object : EThree.OnCompleteListener {

            override fun onSuccess() {
                // Good, go on
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })

        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

        return eThree
    }

    private fun initSyncKeyStorage(identity: String, passwordBrainKey: String): SyncKeyStorage {
        val tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback {
            jwtGenerator.generateToken(identity)
        })
        val brainKeyContext = BrainKeyContext.Builder()
                .setAccessTokenProvider(tokenProvider)
                .setPythiaClient(VirgilPythiaClient(virgilBaseUrl))
                .setPythiaCrypto(VirgilPythiaCrypto())
                .build()
        val keyPair = BrainKey(brainKeyContext).generateKeyPair(passwordBrainKey)

        val syncKeyStorage =
                SyncKeyStorage(
                    identity, keyStorage, CloudKeyStorage(
                        KeyknoxManager(
                            tokenProvider,
                            KeyknoxClient(URL(virgilBaseUrl)),
                            listOf(keyPair.publicKey),
                            keyPair.privateKey,
                            KeyknoxCrypto()
                        )
                    )
                )

        syncKeyStorage.sync()

        return syncKeyStorage
    }

    private fun initCardManager(identity: String): CardManager {
        val cardCrypto = VirgilCardCrypto()
        return CardManager(
            cardCrypto,
            GeneratorJwtProvider(jwtGenerator, identity),
            VirgilCardVerifier(cardCrypto, false, false),
            CardClient(TestConfig.virgilBaseUrl + TestConfig.VIRGIL_CARDS_SERVICE_PATH)
        )
    }

    private fun generateRawCard(identity: String, cardManager: CardManager): Tuple<VirgilKeyPair, RawSignedModel> {
        return VirgilCrypto().generateKeys().let {
            Tuple(it, cardManager.generateRawCard(it.privateKey, it.publicKey, identity))
        }
    }

    // STE-KeyBackup-1
//    @Test
//    fun change_password() {
//        val identity = UUID.randomUUID().toString()
//        val password = UUID.randomUUID().toString()
//        val passwordNew = UUID.randomUUID().toString()
//        val timeTrack = System.currentTimeMillis() / 1000
//        println("One: $timeTrack")
//
//        val eThreeWithPass = initAndBootstrapEThreeWithPass(identity, password)
//
//        TestUtils.pause()
//
//        val waiter = CountDownLatch(1)
//        var passwordChanged = false
//        eThreeWithPass.changePassword(password, passwordNew, object : EThree.OnCompleteListener {
//            override fun onSuccess() {
//                println("Two: " + ((System.currentTimeMillis() / 1000) - timeTrack))
//                passwordChanged = true
//                waiter.countDown()
//            }
//
//            override fun onError(throwable: Throwable) {
//                fail(throwable.message)
//            }
//        })
//        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
//        assertTrue(passwordChanged)
//
//        TestUtils.pause()
//
//        eThreeWithPass.cleanup()
//        val waiterTwo = CountDownLatch(1)
//        var failedWithOldPassword = false
//        eThreeWithPass.register(object : EThree.OnCompleteListener {
//
//            override fun onSuccess() {
//                fail("Illegal State")
//            }
//
//            override fun onError(throwable: Throwable) {
//                if (throwable is WrongPasswordException)
//                    failedWithOldPassword = true
//
//                waiterTwo.countDown()
//            }
//        }, password)
//        waiterTwo.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
//        assertTrue(failedWithOldPassword)
//
//        TestUtils.pause()
//
//        val waiterThree = CountDownLatch(1)
//        var successWithNewPassword = false
//        eThreeWithPass.register(object : EThree.OnCompleteListener {
//
//            override fun onSuccess() {
//                successWithNewPassword = true
//                waiterThree.countDown()
//            }
//
//            override fun onError(throwable: Throwable) {
//                fail(throwable.message)
//            }
//        }, passwordNew)
//        waiterThree.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
//        assertTrue(successWithNewPassword)
//    }

    // STE-KeyBackup-2
//    @Test
//    fun backup_after_bootstrap_with_password() {
//        val identity = UUID.randomUUID().toString()
//        val password = UUID.randomUUID().toString()
//        val eThreeWithPass = initAndBootstrapEThreeWithPass(identity, password)
//
//        TestUtils.pause()
//
//        val waiter = CountDownLatch(1)
//        var failedToBackup = false
//        eThreeWithPass.backupPrivateKey(password, object : EThree.OnCompleteListener {
//            override fun onSuccess() {
//                fail("Illegal State")
//            }
//
//            override fun onError(throwable: Throwable) {
//                if (throwable is BackupKeyException)
//                    failedToBackup = true
//
//                waiter.countDown()
//            }
//        })
//        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
//        assertTrue(failedToBackup)
//    }

    // STE-KeyBackup-3
//    @Test
//    fun backup_key_after_bootstrap() {
//        val identity = UUID.randomUUID().toString()
//        val password = UUID.randomUUID().toString()
//        val eThree = initAndBootstrapEThree(identity)
//
//        TestUtils.pause()
//
//        val waiter = CountDownLatch(1)
//        var successfullyBackuped = false
//        eThree.backupPrivateKey(password, object : EThree.OnCompleteListener {
//            override fun onSuccess() {
//                successfullyBackuped = true
//                waiter.countDown()
//            }
//
//            override fun onError(throwable: Throwable) {
//                fail(throwable.message)
//            }
//        })
//        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
//        assertTrue(successfullyBackuped)
//
//        TestUtils.pause()
//
//        val syncKeyStorage = initSyncKeyStorage(identity, password)
//        assertTrue(syncKeyStorage.exists(identity + TestConfig.KEYKNOX_KEY_POSTFIX))
//        val retrievedKey = syncKeyStorage.retrieve(identity + TestConfig.KEYKNOX_KEY_POSTFIX)
//        assertEquals(TestConfig.virgilCrypto.importPrivateKey(keyStorage.load(identity).value),
//                     TestConfig.virgilCrypto.importPrivateKey(retrievedKey.value))
//
//        eThree.cleanup()
//        assertFalse(keyStorage.exists(identity))
//
//        TestUtils.pause()
//
//        val waiterTwo = CountDownLatch(1)
//        var successfullyBootstrapped = false
//        eThree.register(object : EThree.OnCompleteListener {
//            override fun onSuccess() {
//                successfullyBootstrapped = true
//                waiterTwo.countDown()
//            }
//
//            override fun onError(throwable: Throwable) {
//                fail(throwable.message)
//            }
//        }, password)
//        waiterTwo.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
//        assertTrue(successfullyBootstrapped)
//
//        assertTrue(syncKeyStorage.exists(identity + TestConfig.KEYKNOX_KEY_POSTFIX))
//        val retrievedKeyAfterBootstrap = syncKeyStorage.retrieve(identity + TestConfig.KEYKNOX_KEY_POSTFIX)
//        assertEquals(TestConfig.virgilCrypto.importPrivateKey(keyStorage.load(identity).value),
//                     TestConfig.virgilCrypto.importPrivateKey(retrievedKeyAfterBootstrap.value))
//    }

    // STE-KeyBackup-3
//    @Test
//    fun reset_backed_key() {
//        val identity = UUID.randomUUID().toString()
//        val password = UUID.randomUUID().toString()
//        val eThreeWithPass = initAndBootstrapEThreeWithPass(identity, password)
//
//        TestUtils.pause()
//
//        val waiter = CountDownLatch(1)
//        var successfulKeyReset = false
//        eThreeWithPass.resetPrivateKeyBackup(password, object : EThree.OnCompleteListener {
//            override fun onSuccess() {
//                successfulKeyReset = true
//                waiter.countDown()
//            }
//
//            override fun onError(throwable: Throwable) {
//                fail(throwable.message)
//            }
//        })
//        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
//        assertTrue(successfulKeyReset)
//
//        TestUtils.pause()
//
//        val syncKeyStorage = initSyncKeyStorage(identity, password)
//        assertFalse(syncKeyStorage.exists(identity + TestConfig.KEYKNOX_KEY_POSTFIX))
//    }

//    @Test
//    fun reset_backed_key_wrong_pass() {
//        val identity = UUID.randomUUID().toString()
//        val password = UUID.randomUUID().toString()
//        val passwordWrong = UUID.randomUUID().toString()
//        val eThreeWithPass = initAndBootstrapEThreeWithPass(identity, password)
//
//        TestUtils.pause()
//
//        val waiter = CountDownLatch(1)
//        var failedKeyReset = false
//        eThreeWithPass.resetPrivateKeyBackup(passwordWrong, object : EThree.OnCompleteListener {
//            override fun onSuccess() {
//                fail("Illegal state")
//            }
//
//            override fun onError(throwable: Throwable) {
//                if (throwable is WrongPasswordException)
//                    failedKeyReset = true
//
//                waiter.countDown()
//            }
//        })
//        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
//        assertTrue("Key reset failed with wrong error", failedKeyReset)
//    }
}