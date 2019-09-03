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
import com.virgilsecurity.android.common.exception.PrivateKeyNotFoundException
import com.virgilsecurity.android.common.exception.PublicKeyDuplicateException
import com.virgilsecurity.android.common.exception.PublicKeyNotFoundException
import com.virgilsecurity.android.common.exception.UnRegistrationException
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
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyStorage
import com.virgilsecurity.sdk.utils.Tuple
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Created by:
 * Danylo Oliinyk
 * on
 * 10/24/18
 * at Virgil Security
 */
class EThreeNegativeTest {

    private lateinit var jwtGenerator: JwtGenerator
    private lateinit var keyStorage: KeyStorage
    private lateinit var eThree: EThree
    private val identity = UUID.randomUUID().toString()
    private val password = UUID.randomUUID().toString()


    @Before fun setup() {
        jwtGenerator = JwtGenerator(
            TestConfig.appId,
            TestConfig.apiKey,
            TestConfig.apiPublicKeyId,
            TimeSpan.fromTime(600, TimeUnit.SECONDS),
            VirgilAccessTokenSigner(TestConfig.virgilCrypto)
        )

        keyStorage = DefaultKeyStorage(TestConfig.DIRECTORY_PATH, TestConfig.KEYSTORE_NAME)
        eThree = initEThree(identity)
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

    @Test(expected = PrivateKeyNotFoundException::class)
    fun cleanup_fail_without_bootstrap() {
        eThree.cleanup()
    }

    @Test fun backup_fail_without_bootstrap() {
        var failed = false
        val waiter = CountDownLatch(1)
        eThree.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Not Bootstrapped")
            }

            override fun onError(throwable: Throwable) {
                failed = true
                waiter.countDown()
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failed)
    }

    @Test fun reset_key_fail_without_bootstrap() {
        var failed = false
        val waiter = CountDownLatch(1)
        eThree.resetPrivateKeyBackup(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Not Bootstrapped")
            }

            override fun onError(throwable: Throwable) {
                failed = true
                waiter.countDown()
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failed)
    }

    @Test fun change_pass_fail_without_bootstrap() {
        var failed = false
        val waiter = CountDownLatch(1)
        eThree.changePassword(password, password + password)
                .addCallback(object : OnCompleteListener {
                    override fun onSuccess() {
                        fail("Not Bootstrapped")
                    }

                    override fun onError(throwable: Throwable) {
                        failed = true
                        waiter.countDown()
                    }
                })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failed)
    }

    @Test(expected = PrivateKeyNotFoundException::class)
    fun encrypt_text_fail_without_bootstrap() {
        eThree.encrypt("")
    }

    @Test(expected = PrivateKeyNotFoundException::class)
    fun encrypt_data_fail_without_bootstrap() {
        eThree.encrypt(ByteArray(0))
    }

    @Test(expected = PrivateKeyNotFoundException::class)
    fun decrypt_text_fail_without_bootstrap() {
        eThree.decrypt("")
    }

    @Test(expected = PrivateKeyNotFoundException::class)
    fun decrypt_data_fail_without_bootstrap() {
        eThree.decrypt(ByteArray(0))
    }

    @Test fun lookup_fail_without_bootstrap() {
        var failed = false
        val waiter = CountDownLatch(1)
        eThree.lookupPublicKeys(listOf(""))
                .addCallback(object : OnResultListener<LookupResult> {
                    override fun onSuccess(result: LookupResult) {
                        fail("Not Bootstrapped")
                    }

                    override fun onError(throwable: Throwable) {
                        failed = true
                        waiter.countDown()
                    }
                })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failed)
    }

    @Test fun lookup_fail_wrong_identity() {
        registerEThree(eThree)

        var failed = false
        val waiter = CountDownLatch(1)
        eThree.lookupPublicKeys(listOf(identity,
                                       WRONG_IDENTITY))
                .addCallback(object : OnResultListener<Map<String, VirgilPublicKey>> {
                    override fun onSuccess(result: Map<String, VirgilPublicKey>) {
                        fail("Illegal State")
                    }

                    override fun onError(throwable: Throwable) {
                        if (throwable is PublicKeyNotFoundException
                            && throwable.identity == WRONG_IDENTITY) {
                            failed = true
                        }

                        waiter.countDown()
                    }
                })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failed)
    }

    @Test fun init_ethree_with_empty_token() {
        var failed = false
        val waiter = CountDownLatch(1)
        EThree.initialize(TestConfig.context,
                          object : OnGetTokenCallback {
                              override fun onGetToken(): String {
                                  return ""
                              }
                          })
                .addCallback(object : OnResultListener<EThree> {
                    override fun onSuccess(result: EThree) {
                        fail("Illegal State")
                    }

                    override fun onError(throwable: Throwable) {
                        failed = true
                        waiter.countDown()
                    }
                })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failed)
    }

    @Test fun lookup_with_duplicate_identities() {
        var failed = false
        val waiter = CountDownLatch(1)
        registerEThree(eThree)
        eThree.lookupPublicKeys(listOf(identity, identity, identity,
                                       WRONG_IDENTITY,
                                       WRONG_IDENTITY,
                                       WRONG_IDENTITY + identity))
                .addCallback(object : OnResultListener<LookupResult> {
                    override fun onSuccess(result: LookupResult) {
                        fail("Illegal State")
                    }

                    override fun onError(throwable: Throwable) {
                        if (throwable is PublicKeyDuplicateException)
                            failed = true

                        waiter.countDown()
                    }
                })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failed)
    }

    @Test fun change_pass_with_same_new() {
        var failed = false
        val waiter = CountDownLatch(1)
        registerEThree(eThree)
        eThree.changePassword(password, password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Illegal State")
            }

            override fun onError(throwable: Throwable) {
                if (throwable is IllegalArgumentException)
                    failed = true

                waiter.countDown()
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failed)
    }

    @Test fun unregister_with_multiple_card() {
        val identityTwo = UUID.randomUUID().toString()
        val cardManager = initCardManager(identityTwo)

        val eThreeTwo = initEThree(identityTwo)
        registerEThree(eThreeTwo)

        val publishPair = generateRawCard(identityTwo, cardManager)
        cardManager.publishCard(publishPair.right)

        var failed = false
        val waiter = CountDownLatch(1)
        eThree.unregister().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Unregister should fail when there are 1+ cards published for 1 identity.")
            }

            override fun onError(throwable: Throwable) {
                if (throwable is UnRegistrationException)
                    failed = true

                waiter.countDown()
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failed)
    }

    @Test fun unregister_without_card() {
        var failed = false
        val waiter = CountDownLatch(1)
        eThree.unregister().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                fail("Unregister should fail when there are no cards published for identity.")
            }

            override fun onError(throwable: Throwable) {
                if (throwable is UnRegistrationException)
                    failed = true

                waiter.countDown()
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        assertTrue(failed)
    }

    companion object {
        const val WRONG_IDENTITY = "WRONG_IDENTITY"
    }
}
