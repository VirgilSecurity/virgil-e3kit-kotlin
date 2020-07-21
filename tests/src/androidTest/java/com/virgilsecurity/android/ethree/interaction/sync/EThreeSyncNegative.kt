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

import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.exception.EThreeException
import com.virgilsecurity.android.common.model.EThreeParams
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
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyStorage
import com.virgilsecurity.sdk.utils.Tuple
import org.hamcrest.core.IsEqual
import org.hamcrest.core.IsNot
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.util.*
import java.util.concurrent.TimeUnit

/**
 * EThreeSyncPositive
 */
class EThreeSyncNegative {

    private lateinit var identity: String
    private lateinit var jwtGenerator: JwtGenerator
    private lateinit var keyStorage: KeyStorage

    @Before fun setup() {
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

    private fun initAndRegisterEThree(identity: String): EThree {
        val eThree = initEThree(identity)
        eThree.register().execute()
        return eThree
    }

    private fun initEThree(identity: String): EThree {
        return EThree.initialize(TestConfig.context,
                                 object : OnGetTokenCallback {
                                     override fun onGetToken(): String {
                                         return jwtGenerator.generateToken(
                                             identity)
                                                 .stringRepresentation()
                                     }
                                 }).get()
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

    @Test fun register_existing_identity() {
        val cardManager = initCardManager(identity)
        cardManager.publishCard(generateRawCard(identity, cardManager).right)
        val eThree = initEThree(identity)

        try {
            eThree.register().execute()
            fail()
        } catch (throwable: Throwable) {
            assertTrue(throwable is EThreeException
                       && throwable.description ==
                       EThreeException.Description.USER_IS_ALREADY_REGISTERED)
        }
    }

    @Test fun unregister_without_card() {
        val eThree = initEThree(identity)

        try {
            eThree.unregister().execute()
            fail()
        } catch (throwable: EThreeException) {
            assertTrue(throwable.description == EThreeException.Description.USER_IS_NOT_REGISTERED)
        }
    }

    // STE-15_1 - Sync
    @Test fun backup_key_before_register() {
        val password = UUID.randomUUID().toString()
        val eThree = initEThree(identity)

        try {
            eThree.backupPrivateKey(password).execute()
            fail()
        } catch (exception: EThreeException) {
            assertTrue(exception.description == EThreeException.Description.MISSING_PRIVATE_KEY)
        }
    }

    // STE-18_1
    @Test fun reset_key_backup_before_backup() {
        val password = UUID.randomUUID().toString()
        val eThreeWithPass = initEThree(identity)

        try {
            eThreeWithPass.resetPrivateKeyBackup(password).execute()
            fail()
        } catch (exception: EThreeException) {
            assertTrue(exception.description == EThreeException.Description.MISSING_PRIVATE_KEY)
        }
    }

    @Test fun restore_private_key_before_backup() {
        val password = UUID.randomUUID().toString()
        val eThree = initAndRegisterEThree(identity)

        eThree.cleanup()
        try {
            eThree.restorePrivateKey(password).execute()
            fail()
        } catch (exception: EThreeException) {
            assertTrue(exception.description == EThreeException.Description.NO_PRIVATE_KEY_BACKUP)
        }
    }

    // STE-Auth-12 - Sync
    @Test fun rotate_without_published_card() {
        val eThree = initEThree(identity)

        try {
            eThree.rotatePrivateKey().execute()
            fail()
        } catch (throwable: EThreeException) {
            assertTrue(throwable.description == EThreeException.Description.USER_IS_NOT_REGISTERED)
        }
    }

    //STE-2
    @Test fun lookup_zero_users() {
        val eThree = initEThree(identity)
        try {
            eThree.lookupPublicKeys(listOf()).get()
            fail()
        } catch (throwable: Throwable) {
            assertTrue(throwable is IllegalArgumentException)
        }
    }

    @Test fun key_rotated_by_other_instance() {
        /* Initialize EThree and register identity */
        val eThreeParams = EThreeParams(identity, { jwtGenerator.generateToken(identity).stringRepresentation() }, TestConfig.context)
        val eThree = EThree(eThreeParams)
        eThree.register().execute()

        /** Find identity Card and store it's ID for future checks */
        // Private key that stored in local storage
        val privateKeyData = keyStorage.load(identity).value
        val keyPair = TestConfig.virgilCrypto.importPrivateKey(privateKeyData)

        // Get the latest card for identity
        val cardManager = initCardManager(identity)
        var cards = cardManager.searchCards(identity)
        val card = cards.first { it.publicKey.identifier.contentEquals(keyPair.publicKey.identifier) }
        val cardId = card.identifier

        /* Simulate private key rotation by other eThree instance */
        val newKeyPair = TestConfig.virgilCrypto.generateKeyPair(eThreeParams.keyPairType)

        // Publish a new card for the same identity
        cardManager.publishCard(newKeyPair.privateKey, newKeyPair.publicKey, identity, card.previousCardId)

        /* Verify that private key was rotated */
        // Find a new card that replaces used by this instance
        val newCard = cardManager.searchCards(identity).first { it.identifier == cardId }

        // If new card exists, private key was rotated by other instance
        assertNotNull(newCard)
    }
}
