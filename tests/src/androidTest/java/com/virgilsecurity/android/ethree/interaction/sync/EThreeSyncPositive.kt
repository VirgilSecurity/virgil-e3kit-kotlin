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

package com.virgilsecurity.android.ethree.interaction.sync

import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.android.ethree.utils.TestUtils
import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.cloud.CloudKeyStorage
import com.virgilsecurity.keyknox.crypto.KeyknoxCrypto
import com.virgilsecurity.keyknox.storage.SyncKeyStorage
import com.virgilsecurity.pythia.brainkey.BrainKey
import com.virgilsecurity.pythia.brainkey.BrainKeyContext
import com.virgilsecurity.pythia.client.VirgilPythiaClient
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto
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
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyStorage
import com.virgilsecurity.sdk.utils.Tuple
import junit.framework.Assert.*
import org.hamcrest.core.IsEqual
import org.hamcrest.core.IsNot
import org.junit.Assert.assertThat
import org.junit.Before
import org.junit.Test
import java.net.URL
import java.util.*
import java.util.concurrent.TimeUnit

/**
 * EThreeSyncPositive
 */
class EThreeSyncPositive {

    private lateinit var identity: String
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
            VirgilCardClient(TestConfig.virgilBaseUrl + TestConfig.VIRGIL_CARDS_SERVICE_PATH)
        )
    }

    private fun initSyncKeyStorage(identity: String, passwordBrainKey: String): SyncKeyStorage {
        val tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback {
            jwtGenerator.generateToken(identity)
        })
        val brainKeyContext = BrainKeyContext.Builder()
                .setAccessTokenProvider(tokenProvider)
                .setPythiaClient(VirgilPythiaClient(TestConfig.virgilBaseUrl))
                .setPythiaCrypto(VirgilPythiaCrypto())
                .build()
        val keyPair = BrainKey(brainKeyContext).generateKeyPair(passwordBrainKey)

        val syncKeyStorage =
                SyncKeyStorage(
                    identity, keyStorage, CloudKeyStorage(
                        KeyknoxManager(
                            tokenProvider,
                            KeyknoxClient(URL(TestConfig.virgilBaseUrl)),
                            listOf(keyPair.publicKey),
                            keyPair.privateKey,
                            KeyknoxCrypto()
                        )
                    )
                )

        syncKeyStorage.sync()

        return syncKeyStorage
    }

    private fun generateRawCard(identity: String,
                                cardManager: CardManager): Tuple<VirgilKeyPair, RawSignedModel> {
        return VirgilCrypto().generateKeyPair().let {
            Tuple(it, cardManager.generateRawCard(it.privateKey, it.publicKey, identity))
        }
    }

    @Test fun init_and_register() {
        initAndRegisterEThree(identity)
        assertTrue(keyStorage.exists(identity))

        val card = initCardManager(identity).searchCards(identity)
        assertNotNull(card)
    }

    @Test fun unregister_with_local_key() {
        val eThree = initAndRegisterEThree(identity)
        assertTrue(keyStorage.exists(identity))

        val cards = initCardManager(identity).searchCards(identity)
        assertNotNull(cards)
        assertEquals(1, cards.size)

        eThree.unregister().execute()
        assertFalse(keyStorage.exists(identity))

        val cardsUnregistered = initCardManager(identity).searchCards(identity)
        assertEquals(0, cardsUnregistered.size)
    }

    // STE-15_2-4 - Sync
    @Test fun backup_key_after_register() {
        val password = UUID.randomUUID().toString()
        val eThree = initAndRegisterEThree(identity)

        TestUtils.pause()

        eThree.backupPrivateKey(password).execute()

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        assertTrue(syncKeyStorage.exists(identity))
        val retrievedKey = syncKeyStorage.retrieve(identity)
        assertEquals(TestConfig.virgilCrypto.importPrivateKey(keyStorage.load(identity).value),
                     TestConfig.virgilCrypto.importPrivateKey(retrievedKey.value))
    }

    // STE-18_2 - Sync
    @Test fun reset_key_backup_after_backup() {
        val password = UUID.randomUUID().toString()
        val eThreeWithPass = initAndRegisterEThree(identity)

        eThreeWithPass.backupPrivateKey(password).execute()

        TestUtils.pause()

        eThreeWithPass.resetPrivateKeyBackup(password).execute()

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        assertFalse(syncKeyStorage.exists(identity))

        TestUtils.pause() // To avoid throttling in next test
    }

    // STE-16 - Sync
    @Test fun restore_private_key() {
        val password = UUID.randomUUID().toString()
        val eThreeWithPass = initAndRegisterEThree(identity)
        eThreeWithPass.backupPrivateKey(password).execute()

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        assertTrue(syncKeyStorage.exists(identity))
        val retrievedKey = syncKeyStorage.retrieve(identity)
        assertEquals(TestConfig.virgilCrypto.importPrivateKey(keyStorage.load(identity).value),
                     TestConfig.virgilCrypto.importPrivateKey(retrievedKey.value))

        TestUtils.pause()

        eThreeWithPass.cleanup()
        eThreeWithPass.restorePrivateKey(password).execute()
        assertTrue(keyStorage.exists(identity))
    }

    // STE-Auth-14 - Sync
    @Test fun rotate_keys() {
        val cardManager = initCardManager(identity)
        val pairForPublish = generateRawCard(identity, cardManager)
        cardManager.publishCard(pairForPublish.right)
        val eThree = initEThree(identity)

        eThree.rotatePrivateKey().execute()

        assertTrue(cardManager.searchCards(identity).last().previousCardId != null)

        val newKeyData = keyStorage.load(identity).value
        val oldKeyData = VirgilCrypto().exportPrivateKey(pairForPublish.left.privateKey)
        assertThat(oldKeyData, IsNot.not(IsEqual.equalTo(newKeyData)))
    }

    // STE-17 - Sync
    @Test fun change_password() {
        val password = UUID.randomUUID().toString()
        val passwordNew = UUID.randomUUID().toString()
        val eThreeWithPass = initAndRegisterEThree(identity)
        eThreeWithPass.backupPrivateKey(password).execute()

        TestUtils.pause()

        eThreeWithPass.changePassword(password, passwordNew).execute()

        TestUtils.pause()

        eThreeWithPass.cleanup()
        assertFalse(keyStorage.exists(identity))
        eThreeWithPass.restorePrivateKey(passwordNew).execute()
        assertTrue(keyStorage.exists(identity))
    }

    @Test fun lookup_one_user() {
        val eThree = initEThree(identity)
        val cardManager = initCardManager(identity)
        val publishedCardOne =
                cardManager.publishCard(generateRawCard(identity, cardManager).right)

        val lookupResult = eThree.lookupPublicKeys(identity).get()

        assertTrue(lookupResult.isNotEmpty() && lookupResult.size == 1)
        assertEquals(publishedCardOne.publicKey, lookupResult[identity])
    }

    // STE-1 - Sync
    @Test fun lookup_multiply_users() {
        val eThree = initAndRegisterEThree(identity)

        // Card one
        val identityOne = UUID.randomUUID().toString()
        val cardManagerOne = initCardManager(identityOne)
        val publishedCardOne =
                cardManagerOne.publishCard(generateRawCard(identityOne, cardManagerOne).right)

        // Card two
        val identityTwo = UUID.randomUUID().toString()
        val cardManagerTwo = initCardManager(identityTwo)
        val publishedCardTwo =
                cardManagerTwo.publishCard(generateRawCard(identityTwo, cardManagerTwo).right)

        // Card three
        val identityThree = UUID.randomUUID().toString()
        val cardManagerThree = initCardManager(identityThree)
        val publishedCardThree =
                cardManagerThree.publishCard(generateRawCard(identityThree, cardManagerThree).right)

        val lookupResult =
                eThree.lookupPublicKeys(listOf(identityOne, identityTwo, identityThree)).get()

        assertTrue(lookupResult.isNotEmpty() && lookupResult.size == 3)

        assertTrue(lookupResult[identityOne] == publishedCardOne.publicKey
                   && lookupResult[identityTwo] == publishedCardTwo.publicKey
                   && lookupResult[identityThree] == publishedCardThree.publicKey)
    }
}
