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

package com.virgilsecurity.android.ethreeCoroutines.interaction

import com.virgilsecurity.android.common.exceptions.BackupKeyException
import com.virgilsecurity.android.common.exceptions.PrivateKeyNotFoundException
import com.virgilsecurity.android.common.exceptions.RestoreKeyException
import com.virgilsecurity.android.common.exceptions.WrongPasswordException
import com.virgilsecurity.android.ethreeCoroutines.extension.awaitResult
import com.virgilsecurity.android.ethreeCoroutines.model.onError
import com.virgilsecurity.android.ethreeCoroutines.model.onSuccess
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
import org.junit.Assert
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.net.URL
import java.util.*
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

    @Before fun setup() {
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

    private fun initAndRegisterEThree(identity: String): EThree {
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
        return VirgilCrypto().generateKeyPair().let {
            Tuple(it, cardManager.generateRawCard(it.privateKey, it.publicKey, identity))
        }
    }

    // STE-15_1
    @Test fun backup_key_before_register() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()

        val eThree = initEThree(identity)

        runBlocking {
            eThree.backupPrivateKey(password).awaitResult()
                    .onSuccess { fail("Illegal state") }
                    .onError { assertTrue(it is PrivateKeyNotFoundException) }
        }
    }

    // STE-15_2-4
    @Test fun backup_key_after_register() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val eThree = initAndRegisterEThree(identity)

        TestUtils.pause()

        runBlocking {
            eThree.backupPrivateKey(password).awaitResult()
                    .onError { fail(it.message) }
        }

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        Assert.assertTrue(syncKeyStorage.exists(identity))
        val retrievedKey = syncKeyStorage.retrieve(identity)
        assertEquals(TestConfig.virgilCrypto.importPrivateKey(keyStorage.load(identity).value),
                     TestConfig.virgilCrypto.importPrivateKey(retrievedKey.value))

        TestUtils.pause()

        runBlocking {
            eThree.backupPrivateKey(password).awaitResult()
                    .onSuccess { fail("Illegal state") }
                    .onError {
                        assertTrue(it is BackupKeyException)
                    }
        }
    }

    // STE-16
    @Test fun restore_private_key() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()

        val eThreeWithPass = initAndRegisterEThree(identity)

        TestUtils.pause()

        runBlocking {
            eThreeWithPass.backupPrivateKey(password).awaitResult().onError { fail(it.message) }
        }

        TestUtils.pause()

        eThreeWithPass.cleanup()
        runBlocking {
            eThreeWithPass.restorePrivateKey(password).awaitResult().onError { fail(it.message) }
        }

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        Assert.assertTrue(syncKeyStorage.exists(identity))
        val retrievedKey = syncKeyStorage.retrieve(identity)
        assertEquals(TestConfig.virgilCrypto.importPrivateKey(keyStorage.load(identity).value),
                     TestConfig.virgilCrypto.importPrivateKey(retrievedKey.value))

        TestUtils.pause()

        runBlocking {
            eThreeWithPass.restorePrivateKey(password)
                    .awaitResult()
                    .onSuccess { fail("Illegal state") }
                    .onError { assertTrue(it is RestoreKeyException) }
        }
    }

    // STE-17
    @Test fun change_password() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val passwordNew = UUID.randomUUID().toString()

        val eThreeWithPass = initAndRegisterEThree(identity)

        TestUtils.pause()

        runBlocking {
            eThreeWithPass.backupPrivateKey(password).awaitResult().onError { fail(it.message) }
        }

        TestUtils.pause()

        runBlocking {
            eThreeWithPass.changePassword(password, passwordNew)
                    .awaitResult()
                    .onError { fail(it.message) }
        }

        TestUtils.pause()

        eThreeWithPass.cleanup()
        runBlocking {
            eThreeWithPass.restorePrivateKey(password)
                    .awaitResult()
                    .onSuccess { fail("Illegal state") }
                    .onError {
                        assertTrue(it is WrongPasswordException)
                    }
        }

        TestUtils.pause()

        var successWithNewPassword = false
        runBlocking {
            eThreeWithPass.restorePrivateKey(passwordNew)
                    .awaitResult()
                    .onSuccess { successWithNewPassword = true }
                    .onError { fail(it.message) }
        }
        Assert.assertTrue(successWithNewPassword)
    }

    // STE-18_1
    @Test fun reset_key_backup_before_backup() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val eThreeWithPass = initEThree(identity)

        TestUtils.pause()

        runBlocking {
            eThreeWithPass.resetPrivateKeyBackup(password)
                    .awaitResult()
                    .onSuccess { fail("Illegal state") }
                    .onError { assertTrue(it is PrivateKeyNotFoundException) }
        }

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        Assert.assertFalse(syncKeyStorage.exists(identity))
    }

    // STE-18_2
    @Test fun reset_key_backup_after_backup() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val eThreeWithPass = initAndRegisterEThree(identity)

        TestUtils.pause()

        runBlocking {
            eThreeWithPass.backupPrivateKey(password).awaitResult().onError { fail(it.message) }
        }

        TestUtils.pause()

        runBlocking {
            eThreeWithPass.resetPrivateKeyBackup(password)
                    .awaitResult()
                    .onError { fail(it.message) }
        }

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        Assert.assertFalse(syncKeyStorage.exists(identity))
    }

    // Reset without password
    @Test fun reset_key_backup_after_backup_no_password() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val eThreeWithPass = initAndRegisterEThree(identity)

        TestUtils.pause()

        runBlocking {
            eThreeWithPass.backupPrivateKey(password).awaitResult().onError { fail(it.message) }
        }

        TestUtils.pause()

        runBlocking {
            eThreeWithPass.resetPrivateKeyBackup()
                    .awaitResult()
                    .onError { fail(it.message) }
        }

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        Assert.assertFalse(syncKeyStorage.exists(identity))
    }

    @Test
    fun reset_backed_key_wrong_pass() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val eThreeWithPass = initAndRegisterEThree(identity)

        TestUtils.pause()

        runBlocking {
            eThreeWithPass.backupPrivateKey(password).awaitResult().onError { fail(it.message) }
        }

        TestUtils.pause()

        runBlocking {
            eThreeWithPass.resetPrivateKeyBackup(WRONG_PASSWORD)
                    .awaitResult()
                    .onSuccess { fail("Illegal state") }
                    .onError {
                        assertTrue("Key reset failed with wrong error",
                                   it is WrongPasswordException)
                    }
        }
    }

    companion object {
        const val WRONG_PASSWORD = "WRONG_PASSWORD"
    }
}
