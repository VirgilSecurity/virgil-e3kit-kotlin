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

package com.android.virgilsecurity.testscoroutines.interaction

import com.android.virgilsecurity.ethreecoroutines.interaction.EThree
import com.android.virgilsecurity.testscoroutines.extension.awaitResult
import com.android.virgilsecurity.testscoroutines.model.onError
import com.android.virgilsecurity.testscoroutines.utils.TestConfig
import com.android.virgilsecurity.testscoroutines.utils.TestConfig.Companion.KEYKNOX_KEY_POSTFIX
import com.android.virgilsecurity.testscoroutines.utils.TestConfig.Companion.LOCAL_KEY_IS_PUBLISHED
import com.android.virgilsecurity.testscoroutines.utils.TestConfig.Companion.virgilBaseUrl
import com.android.virgilsecurity.testscoroutines.utils.TestUtils
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
import com.virgilsecurity.sdk.storage.JsonKeyEntry
import com.virgilsecurity.sdk.storage.KeyStorage
import com.virgilsecurity.sdk.utils.Tuple
import kotlinx.coroutines.runBlocking
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
class EThreeAuthTest {

    private val identity = UUID.randomUUID().toString()

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
            eThree = EThree.initialize(TestConfig.context) {
                jwtGenerator.generateToken(identity).stringRepresentation()
            }.await()
        }

        return eThree!!
    }

    private fun bootstrapEThree(eThree: EThree): EThree {
        runBlocking {
            eThree.bootstrap().await()
        }

        return eThree
    }

    private fun initAndBootstrapEThreeWithPass(identity: String, password: String): EThree {
        val eThree = initEThree(identity)
        bootstrapEThree(eThree, password)
        return eThree
    }

    private fun bootstrapEThree(eThree: EThree, password: String): EThree {
        runBlocking {
            eThree.bootstrap(password).await()
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
                CardClient(TestConfig.virgilBaseUrl + TestConfig.VIRGIL_CARDS_SERVICE_PATH)
        )
    }

    private fun generateRawCard(identity: String, cardManager: CardManager): Tuple<VirgilKeyPair, RawSignedModel> {
        return VirgilCrypto().generateKeys().let {
            Tuple(it, cardManager.generateRawCard(it.privateKey, it.publicKey, identity))
        }
    }

    // STE-Auth-1
    @Test
    fun init_and_bootstrap() {
        initAndBootstrapEThree(identity)
        assertTrue(keyStorage.exists(identity))

        val card = initCardManager(identity).searchCards(identity)
        assertNotNull(card)
    }

    // STE-Auth-2
    @Test
    fun init_and_bootstrap_with_password() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()

        initAndBootstrapEThreeWithPass(identity, password)
        assertTrue(keyStorage.exists(identity))

        TestUtils.pause()

        assertTrue(initSyncKeyStorage(identity, password).exists(identity + KEYKNOX_KEY_POSTFIX))

        val card = initCardManager(identity).searchCards(identity)
        assertNotNull(card)
    }

    // STE-Auth-3
    @Test
    fun delete_local_key_and_bootstrap_with_password() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()

        val eThreeWithPass = initAndBootstrapEThreeWithPass(identity, password)

        TestUtils.pause()

        assertTrue(keyStorage.exists(identity))
        assertTrue(initSyncKeyStorage(identity, password).exists(identity + KEYKNOX_KEY_POSTFIX))

        val card = initCardManager(identity).searchCards(identity)
        assertNotNull(card)

        eThreeWithPass.cleanup()
        assertFalse(keyStorage.exists(identity))

        TestUtils.pause()

        initAndBootstrapEThreeWithPass(identity, password)
        assertTrue(keyStorage.exists(identity))

        val cardIsPublished = keyStorage.load(identity).meta[LOCAL_KEY_IS_PUBLISHED]
        assertNotNull(cardIsPublished)
        assertTrue(cardIsPublished!!.toBoolean())
    }

    // STE-Auth-4
    @Test
    fun delete_local_key_and_bootstrap() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()

        val eThreeWithPass = initAndBootstrapEThreeWithPass(identity, password)
        assertTrue(keyStorage.exists(identity))

        TestUtils.pause()

        assertTrue(initSyncKeyStorage(identity, password).exists(identity + KEYKNOX_KEY_POSTFIX))

        val card = initCardManager(identity).searchCards(identity)
        assertNotNull(card)

        eThreeWithPass.cleanup()
        assertFalse(keyStorage.exists(identity))

        var bootstrapFailed = false
        val eThreeForFail = initEThree(identity)

        runBlocking {
            eThreeForFail.bootstrap().awaitResult().onError { bootstrapFailed = true }
        }

        assertTrue(bootstrapFailed)
    }

    // STE-Auth-5
    @Test
    fun bootstrap_with_is_published_false() {
        val identityTwo = UUID.randomUUID().toString()
        val keyPair = TestConfig.virgilCrypto.generateKeys()
        keyStorage.store(JsonKeyEntry(identityTwo, keyPair.privateKey.rawKey).apply {
            meta = mapOf(LOCAL_KEY_IS_PUBLISHED to false.toString())
        })

        val cardIsPublishedBefore = keyStorage.load(identityTwo).meta[LOCAL_KEY_IS_PUBLISHED]
        assertNotNull(cardIsPublishedBefore)
        assertFalse(cardIsPublishedBefore!!.toBoolean())

        initAndBootstrapEThree(identityTwo)

        val cardIsPublishedAfter = keyStorage.load(identityTwo).meta[LOCAL_KEY_IS_PUBLISHED]
        assertNotNull(cardIsPublishedAfter)
        assertTrue(cardIsPublishedAfter!!.toBoolean())
    }

    // STE-Auth-6
    @Test
    fun restore_key_with_bootstrap_with_password() {
        val identityTwo = UUID.randomUUID().toString()
        val passwordTwo = UUID.randomUUID().toString()
        val keyPair = TestConfig.virgilCrypto.generateKeys()

        val syncKeyStorage = initSyncKeyStorage(identityTwo, passwordTwo)
        syncKeyStorage.store(listOf(JsonKeyEntry(identityTwo + KEYKNOX_KEY_POSTFIX,
                                                 keyPair.privateKey.rawKey)))
        assertTrue(syncKeyStorage.exists(identityTwo + KEYKNOX_KEY_POSTFIX))
        assertFalse(keyStorage.exists(identityTwo))

        TestUtils.pause()

        initAndBootstrapEThreeWithPass(identityTwo, passwordTwo)
        val cardIsPublished = keyStorage.load(identityTwo).meta[LOCAL_KEY_IS_PUBLISHED]
        assertNotNull(cardIsPublished)
        assertTrue(cardIsPublished!!.toBoolean())

        val card = initCardManager(identityTwo).searchCards(identityTwo)
        assertNotNull(card)
    }
}