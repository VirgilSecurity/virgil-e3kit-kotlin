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

import com.virgilsecurity.android.common.model.LookupResult
import com.virgilsecurity.android.common.exceptions.PrivateKeyNotFoundException
import com.virgilsecurity.android.common.callback.OnCompleteListener
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.callback.OnResultListener
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.android.ethree.utils.TestUtils
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.model.RawSignedModel
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.exception.EmptyArgumentException
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.JsonKeyEntry
import com.virgilsecurity.sdk.storage.KeyStorage
import com.virgilsecurity.sdk.utils.Tuple
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
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
class EThreeEncryptionTest {

    private val identity = UUID.randomUUID().toString()

    private lateinit var eThree: EThree
    private lateinit var jwtGenerator: JwtGenerator
    private lateinit var keyStorage: KeyStorage

    @Before fun setup() {
        jwtGenerator = JwtGenerator(
            TestConfig.appId,
            TestConfig.apiKey,
            TestConfig.apiPublicKeyId,
            TimeSpan.fromTime(600, TimeUnit.SECONDS),
            VirgilAccessTokenSigner(TestConfig.virgilCrypto)
        )

        eThree = initAndRegisterEThree(identity)
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
            VirgilCardClient(TestConfig.virgilBaseUrl + TestConfig.VIRGIL_CARDS_SERVICE_PATH)
        )
    }

    private fun generateRawCard(identity: String,
                                cardManager: CardManager): Tuple<VirgilKeyPair, RawSignedModel> {
        return VirgilCrypto().generateKeyPair().let {
            Tuple(it, cardManager.generateRawCard(it.privateKey, it.publicKey, identity))
        }
    }

    @Test fun lookup_one_user() {
        val identityOne = UUID.randomUUID().toString()
        val cardManagerOne = initCardManager(identityOne)
        val publishedCardOne = cardManagerOne.publishCard(generateRawCard(identityOne,
                                                                          cardManagerOne).right)

        eThree.lookupPublicKeys(identityOne)
                .addCallback(object : OnResultListener<LookupResult> {
                    override fun onSuccess(result: LookupResult) {
                        assertTrue(result.isNotEmpty() && result.size == 1)
                        assertEquals(publishedCardOne.publicKey,
                                     result[identityOne])
                    }

                    override fun onError(throwable: Throwable) {
                        fail(throwable.message)
                    }
                })
    }

    // STE-1
    @Test fun lookup_multiply_users() {
        var foundCards = false

        // Card one
        val identityOne = UUID.randomUUID().toString()
        val cardManagerOne = initCardManager(identityOne)
        val publishedCardOne = cardManagerOne.publishCard(generateRawCard(identityOne,
                                                                          cardManagerOne).right)
        // Card two
        val identityTwo = UUID.randomUUID().toString()
        val cardManagerTwo = initCardManager(identityTwo)
        val publishedCardTwo = cardManagerTwo.publishCard(generateRawCard(identityTwo,
                                                                          cardManagerTwo).right)
        // Card three
        val identityThree = UUID.randomUUID().toString()
        val cardManagerThree = initCardManager(identityThree)
        val publishedCardThree = cardManagerThree.publishCard(generateRawCard(identityThree,
                                                                              cardManagerThree).right)

        eThree.lookupPublicKeys(listOf(identityOne, identityTwo, identityThree))
                .addCallback(object : OnResultListener<LookupResult> {

                    override fun onSuccess(result: LookupResult) {
                        assertTrue(result.isNotEmpty() && result.size == 3)
                        if (result[identityOne] == publishedCardOne.publicKey
                            && result[identityTwo] == publishedCardTwo.publicKey
                            && result[identityThree] == publishedCardThree.publicKey) {
                            foundCards = true
                        }

                        assertTrue(foundCards)
                    }

                    override fun onError(throwable: Throwable) {
                        fail(throwable.message)
                    }
                })
    }

    //STE-2
    @Test fun lookup_zero_users() {
        eThree.lookupPublicKeys(listOf())
                .addCallback(object : OnResultListener<LookupResult> {
                    override fun onSuccess(result: LookupResult) {
                        fail("Illegal State")
                    }

                    override fun onError(throwable: Throwable) {
                        assertTrue(throwable is EmptyArgumentException)
                    }
                })
    }

    @Test fun encrypt_adding_owner_public_key() {
        val identityTwo = UUID.randomUUID().toString()
        initAndRegisterEThree(identityTwo)

        var eThreeKeys: LookupResult? = null

        val waiter = CountDownLatch(1)
        eThree.lookupPublicKeys(listOf(identity, identityTwo))
                .addCallback(object : OnResultListener<LookupResult> {
                    override fun onSuccess(result: LookupResult) {
                        eThreeKeys = result
                        waiter.countDown()
                    }

                    override fun onError(throwable: Throwable) {
                        fail(throwable.message)
                    }
                })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertNotNull(eThreeKeys)
        assertEquals(2, eThreeKeys?.size)

        var failedEncrypt = false
        try {
            eThree.encrypt(RAW_TEXT, eThreeKeys)
        } catch (e: IllegalArgumentException) {
            failedEncrypt = true
        }
        assertTrue(failedEncrypt)
    }

    // STE-3
    @Test fun encrypt_decrypt_multiple_keys() {
        val identityTwo = UUID.randomUUID().toString()
        val eThreeTwo = initAndRegisterEThree(identityTwo)

        var eThreeKeys: LookupResult? = null

        val waiter = CountDownLatch(1)
        eThree.lookupPublicKeys(listOf(identity, identityTwo))
                .addCallback(object : OnResultListener<LookupResult> {
                    override fun onSuccess(result: LookupResult) {
                        eThreeKeys = result
                        waiter.countDown()
                    }

                    override fun onError(throwable: Throwable) {
                        fail(throwable.message)
                    }
                })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertNotNull(eThreeKeys)
        assertEquals(2, eThreeKeys?.size)

        val lookupEntry =
                eThreeKeys?.toMutableMap()?.apply { remove(identity) } // We need only identity
        val encryptedForOne = eThree.encrypt(RAW_TEXT, lookupEntry)

        val wrongPublicKey = TestConfig.virgilCrypto.generateKeyPair().publicKey
        var failedWithWrongKey = false
        try {
            eThreeTwo.decrypt(encryptedForOne, wrongPublicKey)
        } catch (throwable: Throwable) {
            failedWithWrongKey = true
        }
        assertTrue(failedWithWrongKey)

        val decryptedByTwo = eThreeTwo.decrypt(encryptedForOne, eThreeKeys!![identity])

        assertEquals(RAW_TEXT, decryptedByTwo)
    }

    // STE-4
    @Test(expected = EmptyArgumentException::class)
    fun encrypt_for_zero_users() {
        eThree.encrypt(RAW_TEXT, mapOf())
    }

    // STE-5
    @Test fun encrypt_without_sign() {
        val keyPair = TestConfig.virgilCrypto.generateKeyPair()
        val encryptedWithoutSign = TestConfig.virgilCrypto.encrypt(RAW_TEXT.toByteArray(),
                                                                   keyPair.publicKey)

        var failedDecrypt = false
        try {
            eThree.decrypt(encryptedWithoutSign, keyPair.publicKey)
        } catch (e: Exception) {
            failedDecrypt = true
        }
        assertTrue(failedDecrypt)
    }

    // STE-6
    @Test fun encrypt_decrypt_without_register() {
        var eThreeTwo: EThree? = null
        val identity = UUID.randomUUID().toString()

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
                        eThreeTwo = result
                        waiter.countDown()
                    }

                    override fun onError(throwable: Throwable) {
                        fail(throwable.message)
                    }

                })


        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

        val keys = TestConfig.virgilCrypto.generateKeyPair()

        var failedToEncrypt = false
        try {
            eThreeTwo!!.encrypt(RAW_TEXT, mapOf(identity to keys.publicKey))
        } catch (exception: PrivateKeyNotFoundException) {
            failedToEncrypt = true
        }
        assertTrue(failedToEncrypt)

        var failedToDecrypt = false
        try {
            eThreeTwo!!.decrypt("fakeEncryptedText", keys.publicKey)
        } catch (exception: PrivateKeyNotFoundException) {
            failedToDecrypt = true
        }
        assertTrue(failedToDecrypt)
    }

    @Test fun encrypt_decrypt_without_register_for_owner() {
        var eThreeTwo: EThree? = null

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
                        eThreeTwo = result
                        waiter.countDown()
                    }

                    override fun onError(throwable: Throwable) {
                        fail(throwable.message)
                    }

                })

        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

        val encryptedText = eThreeTwo!!.encrypt(RAW_TEXT)
        val decryptedText = eThreeTwo!!.decrypt(encryptedText)

        assertEquals(RAW_TEXT, decryptedText)
    }

    // STE-7
    @Test fun encrypt_decrypt_for_owner() {
        val encryptedText = eThree.encrypt(RAW_TEXT)
        val decryptedText = eThree.decrypt(encryptedText)

        assertEquals(RAW_TEXT, decryptedText)
    }

    @Test fun init_without_local_key_and_create_after() {
        val identityTwo = UUID.randomUUID().toString()
        val eThreeTwo = initEThree(identityTwo)

        val anyKeypair = TestConfig.virgilCrypto.generateKeyPair()
        keyStorage.store(JsonKeyEntry(identityTwo,
                                      VirgilCrypto().exportPrivateKey(anyKeypair.privateKey)))

        val encrypted = eThreeTwo.encrypt(RAW_TEXT)
        val decrypted = eThreeTwo.decrypt(encrypted)

        assertEquals(RAW_TEXT, decrypted)
    }

    @Test fun lookup_one_key() {
        var eThreeKeys: LookupResult? = null

        val waiter = CountDownLatch(1)
        eThree.lookupPublicKeys(identity).addCallback(object : OnResultListener<LookupResult> {
            override fun onSuccess(result: LookupResult) {
                eThreeKeys = result
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

        assertNotNull(eThreeKeys)
        assertEquals(1, eThreeKeys?.size)
    }

    @Test fun encrypt_decrypt_stream() {
        val identityTwo = UUID.randomUUID().toString()
        val eThreeTwo = initAndRegisterEThree(identityTwo)

        var eThreeKeys: LookupResult? = null

        val waiter = CountDownLatch(1)
        eThree.lookupPublicKeys(listOf(identity, identityTwo))
                .addCallback(object : OnResultListener<LookupResult> {
                    override fun onSuccess(result: LookupResult) {
                        eThreeKeys = result
                        waiter.countDown()
                    }

                    override fun onError(throwable: Throwable) {
                        fail(throwable.message)
                    }
                })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertNotNull(eThreeKeys)
        assertEquals(2, eThreeKeys?.size)

        val lookupEntry =
                eThreeKeys?.toMutableMap()?.apply { remove(identity) } // We need only identityTwo

        ByteArrayOutputStream().use {
            eThree.encrypt(ByteArrayInputStream(RAW_TEXT.toByteArray()), it, lookupEntry)
            val encrypted = it.toByteArray()

            ByteArrayOutputStream().use { outputForDecrypted ->
                eThreeTwo.decrypt(ByteArrayInputStream(encrypted), outputForDecrypted)
                assertEquals(RAW_TEXT, String(outputForDecrypted.toByteArray()))
            }
        }
    }

    companion object {
        const val RAW_TEXT = "This is the best text ever made by the whole humanity."
    }
}
