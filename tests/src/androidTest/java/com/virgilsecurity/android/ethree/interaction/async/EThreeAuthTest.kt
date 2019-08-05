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

package com.virgilsecurity.android.ethree.interaction.async

import com.virgilsecurity.android.common.exceptions.CardNotFoundException
import com.virgilsecurity.android.common.exceptions.PrivateKeyExistsException
import com.virgilsecurity.android.common.exceptions.RegistrationException
import com.virgilsecurity.android.common.callback.OnCompleteListener
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.callback.OnResultListener
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.android.ethree.utils.TestConfig.Companion.virgilBaseUrl
import com.virgilsecurity.android.ethree.utils.TestConfig.Companion.virgilCrypto
import com.virgilsecurity.android.ethree.utils.TestUtils
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
import org.hamcrest.core.IsEqual.equalTo
import org.hamcrest.core.IsNot.not
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

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
            VirgilAccessTokenSigner(virgilCrypto)
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

        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

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

        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

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

    private fun generateRawCard(identity: String,
                                cardManager: CardManager): Tuple<VirgilKeyPair, RawSignedModel> {
        return VirgilCrypto().generateKeyPair().let {
            Tuple(it, cardManager.generateRawCard(it.privateKey, it.publicKey, identity))
        }
    }

    // STE-Auth-8
    @Test fun delete_local_key() {
        val keys = VirgilCrypto().generateKeyPair()
        val privateKey = VirgilCrypto().exportPrivateKey(keys.privateKey)
        keyStorage.store(JsonKeyEntry(identity, privateKey))
        assertTrue(keyStorage.exists(identity))
        initEThree(identity).cleanup()
        assertFalse(keyStorage.exists(identity))
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

        val waiter = CountDownLatch(1)
        eThree.register().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Illegal state")
            }

            override fun onError(throwable: Throwable) {
                assertTrue(throwable is RegistrationException)
                waiter.countDown()
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
    }

    // STE-Auth-11
    @Test fun register_with_existing_private_key() {
        val privateKeyData =
                virgilCrypto.exportPrivateKey(virgilCrypto.generateKeyPair().privateKey)
        keyStorage.store(JsonKeyEntry(identity, privateKeyData))
        val eThree = initEThree(identity)

        val waiter = CountDownLatch(1)
        eThree.register().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Illegal state")
            }

            override fun onError(throwable: Throwable) {
                assertTrue(throwable is PrivateKeyExistsException)
                waiter.countDown()
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
    }

    // STE-Auth-12
    @Test fun rotate_without_published_card() {
        val eThree = initEThree(identity)

        val waiter = CountDownLatch(1)
        eThree.rotatePrivateKey().addCallback(
            object : OnCompleteListener {
                override fun onSuccess() {
                    fail("Illegal state")
                }

                override fun onError(throwable: Throwable) {
                    assertTrue(throwable is CardNotFoundException)
                    waiter.countDown()
                }
            }
        )
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
    }

    // STE-Auth-13
    @Test fun rotate_with_local_key_present() {
        val eThree = initAndRegisterEThree(identity)

        assertTrue(initCardManager(identity).searchCards(identity).isNotEmpty())

        val waiterTwo = CountDownLatch(1)
        eThree.rotatePrivateKey().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Illegal state")
            }

            override fun onError(throwable: Throwable) {
                assertTrue(throwable is PrivateKeyExistsException)
                waiterTwo.countDown()
            }
        })
        waiterTwo.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
    }

    // STE-Auth-14
    @Test fun rotate_keys() {
        val cardManager = initCardManager(identity)
        val publishPair = generateRawCard(identity, cardManager)
        cardManager.publishCard(publishPair.right)
        val eThree = initEThree(identity)

        val waiterTwo = CountDownLatch(1)
        eThree.rotatePrivateKey().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                waiterTwo.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiterTwo.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

        assertTrue(cardManager.searchCards(identity).last().previousCardId != null)

        val newKeyData = keyStorage.load(identity).value
        val oldKeyData = VirgilCrypto().exportPrivateKey(publishPair.left.privateKey)
        assertThat(oldKeyData, not(equalTo(newKeyData)))
    }

    @Test fun encrypt_after_rotate() {
        val cardManager = initCardManager(identity)
        val publishPair = generateRawCard(identity, cardManager)
        cardManager.publishCard(publishPair.right)
        val eThree = initEThree(identity)

        var encrypted: String? = null
        val waiterTwo = CountDownLatch(1)
        eThree.rotatePrivateKey().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                try {
                    encrypted = eThree.encrypt("Some text")
                } catch (throwable: Throwable) {
                    // Just leave encrypted == null
                }
                waiterTwo.countDown()
            }

            override fun onError(throwable: Throwable) {
                // Just leave encrypted == null
            }
        })
        waiterTwo.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

        assertNotNull("Error during keys rotation", encrypted)
    }

    @Test fun rotate_when_multiply_cards_available() {
        val cardManager = initCardManager(identity)
        val publishPair = generateRawCard(identity, cardManager)
        val publishPairTwo = generateRawCard(identity, cardManager)
        cardManager.publishCard(publishPair.right)
        cardManager.publishCard(publishPairTwo.right)
        val eThree = initEThree(identity)

        var rotateFailed = false
        val waiterTwo = CountDownLatch(1)
        eThree.rotatePrivateKey().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Illegal state")
            }

            override fun onError(throwable: Throwable) {
                if (throwable is IllegalStateException)
                    rotateFailed = true

                waiterTwo.countDown()
            }
        })
        waiterTwo.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

        assertTrue(rotateFailed)
    }

    @Test fun lookup_when_multiply_cards_available() {
        val cardManager = initCardManager(identity)
        val publishPair = generateRawCard(identity, cardManager)
        val publishPairTwo = generateRawCard(identity, cardManager)
        cardManager.publishCard(publishPair.right)
        cardManager.publishCard(publishPairTwo.right)
        val eThree = initEThree(identity)

        var rotateFailed = false
        val waiterTwo = CountDownLatch(1)
        eThree.lookupPublicKeys(listOf(identity))
                .addCallback(object : OnResultListener<Map<String, VirgilPublicKey>> {
                    override fun onSuccess(result: Map<String, VirgilPublicKey>) {
                        fail("Illegal state")
                    }

                    override fun onError(throwable: Throwable) {
                        if (throwable is IllegalStateException)
                            rotateFailed = true

                        waiterTwo.countDown()
                    }

                })
        waiterTwo.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

        assertTrue(rotateFailed)
    }

    @Test fun unregister_with_local_key() {
        val eThree = initAndRegisterEThree(identity)
        assertTrue(keyStorage.exists(identity))

        val cards = initCardManager(identity).searchCards(identity)
        assertNotNull(cards)
        assertEquals(1, cards.size)

        val waiter = CountDownLatch(1)
        eThree.unregister().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertFalse(keyStorage.exists(identity))

        val cardsUnregistered = initCardManager(identity).searchCards(identity)
        assertEquals(0, cardsUnregistered.size)
    }

    @Test fun unregister_without_local_key() {
        val eThree = initAndRegisterEThree(identity)
        assertTrue(keyStorage.exists(identity))

        val cards = initCardManager(identity).searchCards(identity)
        assertNotNull(cards)
        assertEquals(1, cards.size)

        eThree.cleanup()
        assertFalse(keyStorage.exists(identity))

        val waiter = CountDownLatch(1)
        eThree.unregister().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertFalse(keyStorage.exists(identity))

        val cardsUnregistered = initCardManager(identity).searchCards(identity)
        assertEquals(0, cardsUnregistered.size)
    }
}
