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

import com.virgilsecurity.android.common.callback.OnCompleteListener
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.callback.OnResultListener
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.android.ethree.utils.TestUtils
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyStorage
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.util.*
import java.util.concurrent.TimeUnit

/**
 * EThreeScopesTest
 */
class EThreeScopesTest {

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

    private fun initCardManager(identity: String): CardManager {
        val cardCrypto = VirgilCardCrypto()
        return CardManager(
            cardCrypto,
            GeneratorJwtProvider(jwtGenerator, identity),
            VirgilCardVerifier(cardCrypto, false, false),
            VirgilCardClient(TestConfig.virgilBaseUrl + TestConfig.VIRGIL_CARDS_SERVICE_PATH)
        )
    }

    @Test fun init_register_ethree_unconfined_scope() {
        var eThree: EThree? = null
        val scope = CoroutineScope(Dispatchers.Unconfined)

        EThree.initialize(TestConfig.context,
                          object : OnGetTokenCallback {
                              override fun onGetToken(): String {
                                  return jwtGenerator.generateToken(identity).stringRepresentation()
                              }
                          })
                .addCallback(object : OnResultListener<EThree> {
                    override fun onSuccess(result: EThree) {
                        eThree = result
                    }

                    override fun onError(throwable: Throwable) {
                        fail(throwable.message)
                    }
                }, scope)

        assertNotNull(eThree)
        val eThreeNonNull = eThree!!

        eThreeNonNull.register().addCallback(object : OnCompleteListener {

            override fun onSuccess() {
                // Good, go on
            }

            override fun onError(throwable: Throwable) {
                fail(throwable.message)
            }
        }, scope)

        assertTrue(keyStorage.exists(identity))
        val card = initCardManager(identity).searchCards(identity)
        assertNotNull(card)
    }

    @Test fun cancel_scope() = runBlocking {
        val scope = CoroutineScope(Dispatchers.Default)
        var timesBeforeCancel = 0

        repeat(NUMBER_OF_REPEATS) {
            EThree.initialize(TestConfig.context,
                              object : OnGetTokenCallback {
                                  override fun onGetToken(): String {
                                      return jwtGenerator.generateToken(identity)
                                              .stringRepresentation()
                                  }
                              })
                    .addCallback(object : OnResultListener<EThree> {
                        override fun onSuccess(result: EThree) {
                            timesBeforeCancel++
                        }

                        override fun onError(throwable: Throwable) {
                            fail(throwable.message)
                        }
                    }, scope)
        }

        delay(A_FEW_NETWORK_CALLS_DELAY)
        scope.cancel()

        assertNotEquals(0, timesBeforeCancel)  // Called at least once
        assertTrue(timesBeforeCancel < NUMBER_OF_REPEATS) // But cancelled before initialize has
                                                          // been called NUMBER_OF_REPEATS times
    }

    @Test fun get_result_without_waiting_callback() {
        var eThree: EThree? = null
        val scope = CoroutineScope(Dispatchers.Default)

        EThree.initialize(TestConfig.context,
                          object : OnGetTokenCallback {
                              override fun onGetToken(): String {
                                  return jwtGenerator.generateToken(identity).stringRepresentation()
                              }
                          })
                .addCallback(object : OnResultListener<EThree> {
                    override fun onSuccess(result: EThree) {
                        eThree = result
                    }

                    override fun onError(throwable: Throwable) {
                        fail(throwable.message)
                    }
                }, scope)

        assertNull(eThree) // Because we haven't waited for callback to be called
    }

    companion object {
        const val NUMBER_OF_REPEATS = 100
        const val A_FEW_NETWORK_CALLS_DELAY = 5000L // 5 sec
    }
}
