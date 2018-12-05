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

package com.virgilsecurity.android.ethreeCoroutines.interaction

import com.virgilsecurity.android.ethreeCoroutines.utils.TestConfig
import com.virgilsecurity.android.ethreeCoroutines.utils.TestConfig.Companion.virgilBaseUrl
import com.virgilsecurity.android.ethreeCoroutines.utils.TestUtils
import com.virgilsecurity.android.ethreecoroutines.interaction.EThree
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
import com.virgilsecurity.sdk.client.VirgilCardClient
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
import kotlinx.coroutines.runBlocking
import org.junit.Before
import java.net.URL
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

        runBlocking {
            eThree = EThree.initialize(
                TestConfig.context) {
                jwtGenerator.generateToken(identity).stringRepresentation()
            }.await()
        }

        return eThree!!
    }

    private fun bootstrapEThree(eThree: EThree): EThree {
        runBlocking {
            eThree.register().await()
        }

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
            VirgilCardClient(virgilBaseUrl + TestConfig.VIRGIL_CARDS_SERVICE_PATH)
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
//
//        val eThreeWithPass = initAndBootstrapEThreeWithPass(identity, password)
//
//        TestUtils.pause()
//
//        var successful = false
//        runBlocking {
//            eThreeWithPass.changePassword(password, passwordNew).awaitResult().onSuccess { successful = true }
//        }
//        assertTrue(successful)
//
//        TestUtils.pause()
//
//        eThreeWithPass.cleanup()
//
//        var failed = false
//        runBlocking {
//            eThreeWithPass.register(password).awaitResult().onError {
//                if (it is WrongPasswordException)
//                    failed = true
//            }
//        }
//        assertTrue(failed)
//
//        TestUtils.pause()
//
//        var successfulTwo = false
//        runBlocking {
//            eThreeWithPass.register(passwordNew).awaitResult().onSuccess { successfulTwo = true }
//        }
//        assertTrue(successfulTwo)
//    }
//
//    // STE-KeyBackup-2
//    @Test
//    fun backup_after_bootstrap_with_password() {
//        val identity = UUID.randomUUID().toString()
//        val password = UUID.randomUUID().toString()
//        val eThreeWithPass = initAndBootstrapEThreeWithPass(identity, password)
//
//        TestUtils.pause()
//
//        var failed = false
//        runBlocking {
//            eThreeWithPass.backupPrivateKey(password).awaitResult().onError {
//                if (it is BackupKeyException)
//                    failed = true
//            }
//        }
//        assertTrue(failed)
//    }
//
//    // STE-KeyBackup-3
//    @Test
//    fun backup_key_after_bootstrap() {
//        val identity = UUID.randomUUID().toString()
//        val password = UUID.randomUUID().toString()
//        val eThree = initAndBootstrapEThree(identity)
//
//        TestUtils.pause()
//
//        var result: Unit? = null
//        runBlocking {
//            result = eThree.backupPrivateKey(password).await()
//        }
//        assertNotNull(result)
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
//        var resultTwo: Unit? = null
//        runBlocking {
//            eThree.register(password).awaitResult().onSuccess { resultTwo = it }
//        }
//        assertNotNull(resultTwo)
//
//        assertTrue(syncKeyStorage.exists(identity + TestConfig.KEYKNOX_KEY_POSTFIX))
//        val retrievedKeyAfterBootstrap = syncKeyStorage.retrieve(identity + TestConfig.KEYKNOX_KEY_POSTFIX)
//        assertEquals(TestConfig.virgilCrypto.importPrivateKey(keyStorage.load(identity).value),
//                     TestConfig.virgilCrypto.importPrivateKey(retrievedKeyAfterBootstrap.value))
//    }
//
//    // STE-KeyBackup-3
//    @Test
//    fun reset_backed_key() {
//        val identity = UUID.randomUUID().toString()
//        val password = UUID.randomUUID().toString()
//        val eThreeWithPass = initAndBootstrapEThreeWithPass(identity, password)
//
//        TestUtils.pause()
//
//        var result: Unit? = null
//        runBlocking {
//            result = eThreeWithPass.resetPrivateKeyBackup(password).await()
//        }
//        assertNotNull(result)
//
//        TestUtils.pause()
//
//        val syncKeyStorage = initSyncKeyStorage(identity, password)
//        assertFalse(syncKeyStorage.exists(identity + TestConfig.KEYKNOX_KEY_POSTFIX))
//    }
//
//    @Test
//    fun reset_backed_key_wrong_pass() {
//        val identity = UUID.randomUUID().toString()
//        val password = UUID.randomUUID().toString()
//        val passwordWrong = UUID.randomUUID().toString()
//        val eThreeWithPass = initAndBootstrapEThreeWithPass(identity, password)
//
//        TestUtils.pause()
//
//        var failed = false
//        runBlocking {
//            eThreeWithPass.resetPrivateKeyBackup(passwordWrong).awaitResult().onError {
//                if (it is WrongPasswordException)
//                    failed = true
//            }
//        }
//        assertTrue(failed)
//    }
}