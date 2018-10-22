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

package interaction

import com.virgilsecurity.e2ee.data.exception.InitException
import com.virgilsecurity.e2ee.data.exception.SessionException
import com.virgilsecurity.e2ee.interaction.EThree
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.model.RawSignedModel
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.CardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider
import com.virgilsecurity.sdk.storage.JsonFileKeyStorage
import com.virgilsecurity.sdk.storage.PrivateKeyStorage
import com.virgilsecurity.sdk.utils.Tuple
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import utils.TestConfig
import java.util.*
import java.util.concurrent.TimeUnit

/**
 * Created by:
 * Danylo Oliinyk
 * on
 * 10/9/18
 * at Virgil Security
 */
class EndToEndEncryptionTestNegative {

    private val identity = UUID.randomUUID().toString()
    private val password = UUID.randomUUID().toString()
    private lateinit var tokenString: String
    private lateinit var encryption: EThree

    private lateinit var jwtGenerator: JwtGenerator

    @BeforeEach
    fun setup() {
        jwtGenerator = JwtGenerator(TestConfig.appId,
                                    TestConfig.apiKey,
                                    TestConfig.apiPublicKeyId,
                                    TimeSpan.fromTime(600, TimeUnit.SECONDS),
                                    VirgilAccessTokenSigner(TestConfig.virgilCrypto))

        tokenString = jwtGenerator.generateToken(identity).stringRepresentation()
        encryption = EThree { tokenString }
    }

    private fun initCardManager(identity: String): CardManager {
        val cardCrypto = VirgilCardCrypto()
        return CardManager(cardCrypto,
                           GeneratorJwtProvider(jwtGenerator, identity),
                           VirgilCardVerifier(cardCrypto, false, false),
                           CardClient("https://api-dev.virgilsecurity.com/card/v5/"))
    }

    private fun initPrivateKeyStorage() = PrivateKeyStorage(VirgilPrivateKeyExporter(), JsonFileKeyStorage())

    private fun generateRawCard(identity: String, cardManager: CardManager): Tuple<VirgilKeyPair, RawSignedModel> {
        return VirgilCrypto().generateKeys().let {
            Tuple(it, cardManager.generateRawCard(it.privateKey, it.publicKey, identity))
        }
    }


}