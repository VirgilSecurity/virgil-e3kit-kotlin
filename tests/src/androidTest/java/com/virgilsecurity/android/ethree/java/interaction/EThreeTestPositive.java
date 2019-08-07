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

package com.virgilsecurity.android.ethree.java.interaction;

import android.support.test.runner.AndroidJUnit4;

import com.virgilsecurity.android.common.callback.OnCompleteListener;
import com.virgilsecurity.android.common.callback.OnGetTokenCallback;
import com.virgilsecurity.android.common.callback.OnResultListener;
import com.virgilsecurity.android.ethree.interaction.EThree;
import com.virgilsecurity.android.ethree.utils.TestConfig;
import com.virgilsecurity.android.ethree.utils.TestUtils;
import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardManager;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.VirgilCardClient;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider;

import org.jetbrains.annotations.NotNull;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(AndroidJUnit4.class)
public class EThreeTestPositive {

    private String identity = UUID.randomUUID().toString();
    private String tokenString;
    private EThree eThree;

    private JwtGenerator jwtGenerator;

    @Before
    public void setup() throws InterruptedException {
        jwtGenerator = new JwtGenerator(TestConfig.Companion.getAppId(),
                                        TestConfig.Companion.getApiKey(),
                                        TestConfig.Companion.getApiPublicKeyId(),
                                        TimeSpan.fromTime(600, TimeUnit.SECONDS),
                                        new VirgilAccessTokenSigner(TestConfig.Companion.getVirgilCrypto()));

        try {
            tokenString = jwtGenerator.generateToken(identity).stringRepresentation();
        } catch (CryptoException e) {
            e.printStackTrace();
        }

        final CountDownLatch lock = new CountDownLatch(1);
        EThree.initialize(TestConfig.Companion.getContext(), new OnGetTokenCallback() {
            @NotNull @Override public String onGetToken() {
                return tokenString;
            }
        }).addCallback(new OnResultListener<EThree>() {
            @Override public void onSuccess(EThree result) {
                eThree = result;
                lock.countDown();
            }

            @Override public void onError(@NotNull Throwable throwable) {
                fail(throwable.getMessage());
            }
        });
        lock.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS);
    }

    private CardManager initCardManager(String identity) {
        VirgilCardCrypto cardCrypto = new VirgilCardCrypto();
        return new CardManager(cardCrypto,
                               new GeneratorJwtProvider(jwtGenerator, identity),
                               new VirgilCardVerifier(cardCrypto, false, false),
                               new VirgilCardClient(TestConfig.Companion.getVirgilBaseUrl()
                                                            + TestConfig.VIRGIL_CARDS_SERVICE_PATH));
    }

    @Test public void register_sync() throws CryptoException, VirgilServiceException {
        eThree.register().execute();

        CardManager cardManager = initCardManager(identity);
        List<Card> cards = cardManager.searchCards(identity);
        assertNotNull(cards);
        assertEquals(1, cards.size());
    }

    @Test public void register_async() throws InterruptedException, CryptoException, VirgilServiceException {
        final CountDownLatch lock = new CountDownLatch(1);
        eThree.register().addCallback(new OnCompleteListener() {

            @Override
            public void onSuccess() {
                lock.countDown();
            }

            @Override
            public void onError(@NotNull Throwable throwable) {
                fail();
            }
        });
        lock.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS);

        CardManager cardManager = initCardManager(identity);
        List<Card> cards = cardManager.searchCards(identity);
        assertNotNull(cards);
        assertEquals(1, cards.size());
    }

    @Test public void initialize_with_null_token() throws InterruptedException {
        final CountDownLatch lock = new CountDownLatch(1);
        EThree.initialize(TestConfig.Companion.getContext(), new OnGetTokenCallback() {
            @NotNull @Override public String onGetToken() {
                //noinspection ConstantConditions
                return null;
            }
        }).addCallback(new OnResultListener<EThree>() {
            @Override public void onSuccess(EThree result) {
                fail("Null token should throw exception");

            }

            @Override public void onError(@NotNull Throwable throwable) {
                assertTrue(throwable instanceof IllegalArgumentException);

                lock.countDown();
            }
        });
        lock.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS);
    }
}
