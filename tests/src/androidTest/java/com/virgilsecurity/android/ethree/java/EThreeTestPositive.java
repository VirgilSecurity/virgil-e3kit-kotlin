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

package com.virgilsecurity.android.ethree.java;

import android.support.test.runner.AndroidJUnit4;

import com.virgilsecurity.android.ethree.kotlin.callback.OnCompleteListener;
import com.virgilsecurity.android.ethree.kotlin.callback.OnGetTokenCallback;
import com.virgilsecurity.android.ethree.kotlin.callback.OnResultListener;
import com.virgilsecurity.android.ethree.kotlin.interaction.EThree;
import com.virgilsecurity.android.ethree.utils.TestConfig;
import com.virgilsecurity.android.ethree.utils.TestUtils;
import com.virgilsecurity.sdk.cards.CardManager;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.VirgilCardClient;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKeyExporter;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider;
import com.virgilsecurity.sdk.storage.JsonFileKeyStorage;
import com.virgilsecurity.sdk.storage.PrivateKeyStorage;
import com.virgilsecurity.sdk.utils.Tuple;

import org.jetbrains.annotations.NotNull;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Created by:
 * Danylo Oliinyk
 * on
 * 10/19/18
 * at Virgil Security
 */
@RunWith(AndroidJUnit4.class)
public class EThreeTestPositive {

    private static final int SUCCESS = 1;

    private String identity = UUID.randomUUID().toString();
    private String tokenString;
    private EThree eThree;

    private JwtGenerator jwtGenerator;

    private CountDownLatch lock = new CountDownLatch(1);


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

        EThree.initialize(TestConfig.Companion.getContext(), new OnGetTokenCallback() {
            @NotNull
            @Override
            public String onGetToken() {
                return tokenString;
            }
        }, new OnResultListener<EThree>() {
            @Override
            public void onSuccess(EThree result) {
                eThree = result;
                lock.countDown();
            }

            @Override
            public void onError(@NotNull Throwable throwable) {
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

    private PrivateKeyStorage initPrivateKeyStorage() {
        return new PrivateKeyStorage(new VirgilPrivateKeyExporter(), new JsonFileKeyStorage());
    }

    private Tuple<VirgilKeyPair, RawSignedModel> generateRawCard(String identity, CardManager cardManager) {
        VirgilCrypto virgilCrypto = new VirgilCrypto();
        try {
            VirgilKeyPair keyPair = virgilCrypto.generateKeyPair();
            return new Tuple<>(keyPair,
                               cardManager.generateRawCard(keyPair.getPrivateKey(),
                                                           keyPair.getPublicKey(),
                                                           identity));
        } catch (CryptoException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Test public void register() throws InterruptedException {
        final int[] result = new int[1];

        final CountDownLatch lock = new CountDownLatch(1);
        eThree.register(new OnCompleteListener() {

            @Override
            public void onSuccess() {
                result[0]++;
                lock.countDown();
            }

            @Override
            public void onError(@NotNull Throwable throwable) {
                fail();
            }
        });
        lock.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS);
        assertEquals(SUCCESS, result[0]);
    }
}
