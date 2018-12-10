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

import com.virgilsecurity.android.common.exceptions.CardNotFoundException
import com.virgilsecurity.android.common.exceptions.PrivateKeyExistsException
import com.virgilsecurity.android.common.exceptions.RegistrationException
import com.virgilsecurity.android.ethreeCoroutines.extension.awaitResult
import com.virgilsecurity.android.ethreeCoroutines.model.onError
import com.virgilsecurity.android.ethreeCoroutines.model.onSuccess
import com.virgilsecurity.android.ethreeCoroutines.utils.TestConfig
import com.virgilsecurity.android.ethreeCoroutines.utils.TestConfig.Companion.virgilBaseUrl
import com.virgilsecurity.android.ethreeCoroutines.utils.TestConfig.Companion.virgilCrypto
import com.virgilsecurity.android.ethreeCoroutines.utils.TestUtils
import com.virgilsecurity.android.ethreecoroutines.interaction.EThree
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.model.RawSignedModel
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.JsonKeyEntry
import com.virgilsecurity.sdk.storage.KeyStorage
import com.virgilsecurity.sdk.utils.Tuple
import kotlinx.coroutines.runBlocking
import org.hamcrest.core.IsEqual
import org.hamcrest.core.IsNot
import org.junit.Assert
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.lang.IllegalStateException
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
class EThreeAuthTest {

    private val identity = UUID.randomUUID().toString()

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

    // STE-Auth-8
    @Test fun delete_local_key() {
        val keys = VirgilCrypto().generateKeys()
        keyStorage.store(JsonKeyEntry(identity, keys.privateKey.rawKey))
        assertTrue(keyStorage.exists(identity))
        initEThree(identity).cleanup()
        Assert.assertFalse(keyStorage.exists(identity))
    }

    // STE-Auth-9
    @Test fun init_and_register() {
        initAndRegisterEThree(identity)
        assertTrue(keyStorage.exists(identity))

        val card = initCardManager(identity).searchCards(identity)
        assertNotNull(card)
    }

    // STE-Auth-10
    @Test fun register_existing_identity() {
        val cardManager = initCardManager(identity)
        cardManager.publishCard(generateRawCard(identity, cardManager).right)
        val eThree = initEThree(identity)

        runBlocking {
            eThree.register().awaitResult().onError { assertTrue(it is RegistrationException) }
        }
    }

    // STE-Auth-11
    @Test fun register_with_existing_private_key() {
        keyStorage.store(JsonKeyEntry(identity, virgilCrypto.generateKeys().privateKey.rawKey))
        val eThree = initEThree(identity)

        runBlocking {
            eThree.register()
                    .awaitResult()
                    .onSuccess { fail("Illegal state") }
                    .onError { assertTrue(it is PrivateKeyExistsException) }
        }
    }

    // STE-Auth-12
    @Test fun rotate_without_published_card() {
        val eThree = initEThree(identity)

        runBlocking {
            eThree.rotatePrivateKey()
                    .awaitResult()
                    .onSuccess { fail("Illegal state") }
                    .onError { assertTrue(it is CardNotFoundException) }
        }
    }

    // STE-Auth-13
    @Test fun rotate_with_local_key_present() {
        val eThree = initAndRegisterEThree(identity)

        assertTrue(initCardManager(identity).searchCards(identity).isNotEmpty())

        runBlocking {
            eThree.rotatePrivateKey()
                    .awaitResult()
                    .onSuccess { fail("Illegal state") }
                    .onError { assertTrue(it is PrivateKeyExistsException) }
        }
    }

    // STE-Auth-14
    @Test fun rotate_keys() {
        val cardManager = initCardManager(identity)
        val publishPair = generateRawCard(identity, cardManager)
        cardManager.publishCard(publishPair.right)
        val eThree = initEThree(identity)

        runBlocking {
            eThree.rotatePrivateKey().awaitResult().onError { fail(it.message) }
        }

        assertTrue(cardManager.searchCards(identity).last().previousCardId != null)

        val newKey = keyStorage.load(identity)
        Assert.assertThat(publishPair.left.privateKey.rawKey,
                          IsNot.not(IsEqual.equalTo(VirgilCrypto().importPrivateKey(newKey.value).rawKey)))
    }

    @Test fun rotate_when_multiply_cards_available() {
        val cardManager = initCardManager(identity)
        val publishPair = generateRawCard(identity, cardManager)
        val publishPairTwo = generateRawCard(identity, cardManager)
        cardManager.publishCard(publishPair.right)
        cardManager.publishCard(publishPairTwo.right)
        val eThree = initEThree(identity)

        runBlocking {
            eThree.rotatePrivateKey()
                    .awaitResult()
                    .onSuccess { fail("Illegal state") }
                    .onError {
                        assertTrue(it is IllegalStateException)
                    }
        }
    }

    @Test fun lookup_when_multiply_cards_available() {
        val cardManager = initCardManager(identity)
        val publishPair = generateRawCard(identity, cardManager)
        val publishPairTwo = generateRawCard(identity, cardManager)
        cardManager.publishCard(publishPair.right)
        cardManager.publishCard(publishPairTwo.right)
        val eThree = initEThree(identity)

        runBlocking {
            eThree.lookupPublicKeys(listOf(identity))
                    .awaitResult()
                    .onSuccess { fail("Illegal state") }
                    .onError {
                        assertTrue(it is IllegalStateException)
                    }
        }
    }
}