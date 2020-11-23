/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
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

package com.virgilsecurity.android.ethree.interaction.sync

import com.virgilsecurity.android.common.exception.EThreeException
import com.virgilsecurity.android.common.exception.GroupException
import com.virgilsecurity.android.common.model.EThreeParams
import com.virgilsecurity.android.common.model.FindUsersResult
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.keyknox.exception.KeyknoxServiceException
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.model.RawSignedModel
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyStorage
import com.virgilsecurity.sdk.utils.Tuple
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.util.*
import java.util.concurrent.TimeUnit

class EThreeGroupsTest {

    private lateinit var identity: String
    private lateinit var users: List<Card>
    private lateinit var jwtGenerator: JwtGenerator
    private lateinit var keyStorage: KeyStorage

    @Before
    fun setup() {
        jwtGenerator = JwtGenerator(
                TestConfig.appId,
                TestConfig.appKey,
                TestConfig.appPublicKeyId,
                TimeSpan.fromTime(600, TimeUnit.SECONDS),
                VirgilAccessTokenSigner(TestConfig.virgilCrypto)
        )

        keyStorage = DefaultKeyStorage(TestConfig.DIRECTORY_PATH, TestConfig.KEYSTORE_NAME)
        identity = UUID.randomUUID().toString()
    }

    @Test
    fun createGroup() {
        // Register a set of identities
        val otherUsers: MutableSet<String> = mutableSetOf()
        while (otherUsers.size < EThreeGroupsTest.IDENTITIES_AMOUNT) {
            otherUsers.add(UUID.randomUUID().toString())
        }
        Assert.assertEquals(EThreeGroupsTest.IDENTITIES_AMOUNT, otherUsers.size)

        otherUsers.forEach { identity ->
            val cardManager = initCardManager(identity)
            val rawCard = generateRawCard(identity, cardManager).right
            cardManager.publishCard(rawCard)
        }

        // Initialize eThree
        val params = EThreeParams(identity, {jwtGenerator.generateToken(identity).stringRepresentation()}, TestConfig.context)
        val eThree = EThree(params)

        try {
            if(!eThree.hasLocalPrivateKey()) {
                eThree.register().execute()
            }
        } catch (e: EThreeException) {
            if (e.description != EThreeException.Description.USER_IS_ALREADY_REGISTERED) {
                // if user is already registered, we can safely ignore, otherwise rethrow
                throw e
            }
        }

        val userCards =
                if (otherUsers.isEmpty()) {
                    FindUsersResult()
                } else eThree.findUsers(
                        otherUsers.toList(),
                        forceReload = true,
                        checkResult = false
                ).get()
        val userTimelineGroup = eThree.createGroup("feed-group-${identity}", userCards).get()
    }

    @Test
    fun createGroup_alreadyExists_shouldFail() {
        // Register a set of identities
        val size = 2
        val otherUsers: MutableSet<String> = mutableSetOf()
        for (i in 1..size) {
            otherUsers.add(UUID.randomUUID().toString())
        }
        Assert.assertEquals(size, otherUsers.size)

        otherUsers.forEach { identity ->
            val cardManager = initCardManager(identity)
            val rawCard = generateRawCard(identity, cardManager).right
            cardManager.publishCard(rawCard)
        }

        // Initialize eThree
        val params = EThreeParams(identity, {jwtGenerator.generateToken(identity).stringRepresentation()}, TestConfig.context)
        val eThree = EThree(params)
        eThree.register().execute()

        val userCards = eThree.findUsers(
                        otherUsers.toList(),
                        forceReload = true,
                        checkResult = false
                ).get()
        val createdGroup = eThree.createGroup("feed-group-${identity}", userCards).get()
        Assert.assertNotNull(createdGroup)

        try {
            eThree.createGroup("feed-group-${identity}", userCards).get()
            Assert.fail("Group with the same Id shouldn't be created");
        }
        catch (e: GroupException) {
            Assert.assertEquals(GroupException.Description.GROUP_ALREADY_EXISTS, e.description);
        }
    }

    private fun initCardManager(identity: String): CardManager {
        val cardCrypto = VirgilCardCrypto()
        return CardManager(
                cardCrypto,
                GeneratorJwtProvider(jwtGenerator, identity),
                VirgilCardVerifier(cardCrypto, false, false),
                VirgilCardClient(TestConfig.virgilServiceAddress + TestConfig.VIRGIL_CARDS_SERVICE_PATH)
        )
    }

    private fun generateRawCard(identity: String,
                                cardManager: CardManager): Tuple<VirgilKeyPair, RawSignedModel> {
        return VirgilCrypto().generateKeyPair().let {
            Tuple(it, cardManager.generateRawCard(it.privateKey, it.publicKey, identity))
        }
    }

    companion object {
        private const val IDENTITIES_AMOUNT = 0
    }
}
