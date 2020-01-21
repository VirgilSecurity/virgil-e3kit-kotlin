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

package com.virgilsecurity.android.common.utils

import com.virgilsecurity.android.common.utils.TestConfig.Companion.virgilCrypto
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.cards.ModelSigner
import com.virgilsecurity.sdk.cards.model.RawCardContent
import com.virgilsecurity.sdk.cards.model.RawSignedModel
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto
import com.virgilsecurity.sdk.jwt.Jwt
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.ConstAccessTokenProvider
import com.virgilsecurity.sdk.utils.ConvertionUtils
import java.util.*
import java.util.concurrent.TimeUnit

class TestUtils {

    companion object {
        fun generateTokenString(identity: String): String =
                JwtGenerator(
                    TestConfig.appId,
                    TestConfig.appKey,
                    TestConfig.appPublicKeyId,
                    TimeSpan.fromTime(600, TimeUnit.SECONDS),
                    VirgilAccessTokenSigner(virgilCrypto)
                ).generateToken(identity).stringRepresentation()

        fun generateToken(identity: String): Jwt =
                JwtGenerator(
                    TestConfig.appId,
                    TestConfig.appKey,
                    TestConfig.appPublicKeyId,
                    TimeSpan.fromTime(600, TimeUnit.SECONDS),
                    VirgilAccessTokenSigner(virgilCrypto)
                ).generateToken(identity)

        fun publishCard(identity: String? = null, previousCardId: String? = null): Card {
            val keyPair = virgilCrypto.generateKeyPair()
            val exportedPublicKey = virgilCrypto.exportPublicKey(keyPair.publicKey)
            val identityNew = identity ?: UUID.randomUUID().toString()
            val content = RawCardContent(identityNew,
                                         ConvertionUtils.toBase64String(exportedPublicKey),
                                         "5.0",
                                         Date(),
                                         previousCardId)
            val snapshot = content.snapshot()
            val rawCard = RawSignedModel(snapshot)
            val token = generateToken(identityNew)
            val provider = ConstAccessTokenProvider(token)
            val signer = ModelSigner(VirgilCardCrypto(virgilCrypto))
            signer.selfSign(rawCard, keyPair.privateKey)
            val cardClient = VirgilCardClient(TestConfig.virgilServiceAddress + TestConfig.VIRGIL_CARDS_SERVICE_PATH)

            val responseRawCard =
                    cardClient.publishCard(rawCard,
                                           provider.getToken(null).stringRepresentation())

            return Card.parse(VirgilCardCrypto(virgilCrypto), responseRawCard)
        }
    }
}
