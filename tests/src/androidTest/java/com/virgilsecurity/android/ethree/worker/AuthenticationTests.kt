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

package com.virgilsecurity.android.ethree.worker

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.exception.EThreeException
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.android.ethree.utils.TestConfig.Companion.virgilCrypto
import com.virgilsecurity.android.ethree.utils.TestUtils
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.exceptions.KeyEntryNotFoundException
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.JsonKeyEntry
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.*

/**
 * AuthenticationTests
 */
@RunWith(AndroidJUnit4::class)
class AuthenticationTests {

    private lateinit var identity: String
    private lateinit var password: String
    private lateinit var crypto: VirgilCrypto
    private lateinit var keyStorage: DefaultKeyStorage
    private lateinit var ethree: EThree

    @Before fun setup() {
        this.identity = UUID.randomUUID().toString()
        this.password = UUID.randomUUID().toString()
        this.crypto = VirgilCrypto()
        this.keyStorage = DefaultKeyStorage(TestConfig.DIRECTORY_PATH, TestConfig.KEYSTORE_NAME)
        this.ethree = EThree(identity,
                             object : OnGetTokenCallback {
                                 override fun onGetToken(): String {
                                     return TestUtils.generateTokenString(identity)
                                 }
                             },
                             TestConfig.context)

        assertNotNull(this.ethree)
    }

    // test01 STE_8
    @Test fun cleanup() {
        val keyPair = virgilCrypto.generateKeyPair()
        val data = virgilCrypto.exportPrivateKey(keyPair.privateKey)

        keyStorage.store(JsonKeyEntry(ethree.identity, data))

        ethree.cleanup()

        try {
            keyStorage.load(ethree.identity)
        } catch (throwable: Throwable) {
            if (throwable !is KeyEntryNotFoundException)
                fail()
        }
    }

    // test02 STE_9
    @Test fun register() {
        ethree.register().execute()

        val retrievedEntry = keyStorage.load(ethree.identity)
        assertNotNull(retrievedEntry)

        val cards = ethree.cardManager.searchCards(ethree.identity)
        assertTrue(cards.isNotEmpty())
    }

    // test03 STE_10
    @Test fun register_with_published_card() {
        val card = TestUtils.publishCard(ethree.identity)
        assertNotNull(card)

        try {
            ethree.register().execute()
        } catch (throwable: Throwable) {
            if (throwable !is EThreeException)
                fail()
        }
    }

    // test04 STE_11
    @Test fun register_with_local_key_present() {
        val keyPair = virgilCrypto.generateKeyPair()
        val data = virgilCrypto.exportPrivateKey(keyPair.privateKey)

        keyStorage.store(JsonKeyEntry(ethree.identity, data))

        try {
            ethree.register().execute()
        } catch (throwable: Throwable) {
            if (throwable !is EThreeException)
                fail()
        }
    }

    // test05 STE_12
    @Test(expected = EThreeException::class) fun rotate_without_published_card() {
        ethree.rotatePrivateKey().execute()
    }

    // test06 STE_13

    @Test fun rotate_with_local_key_present() {
        ethree.register().execute()

        try {
            ethree.rotatePrivateKey().execute()
        } catch (throwable: Throwable) {
            if (throwable !is EThreeException)
                fail()
        }
    }

    // test07 STE_14
    @Test fun rotate_private_key() {
        val card = TestUtils.publishCard(ethree.identity)
        assertNotNull(card)

        ethree.rotatePrivateKey().execute()

        val cards = ethree.cardManager.searchCards(ethree.identity)

        assertEquals(card.identifier, cards.first().previousCardId)
        assertNotEquals(card.identifier, cards.first().identifier)

        val retrievedEntry = keyStorage.load(ethree.identity)
        assertNotNull(retrievedEntry)

        val keyPair = crypto.importPrivateKey(retrievedEntry.value)

        val keyOne = crypto.exportPublicKey(card.publicKey)
        val keyTwo = crypto.exportPublicKey(keyPair.publicKey)
        val keyThree = crypto.exportPublicKey(cards.first().publicKey)

        assertFalse(Arrays.equals(keyOne, keyTwo))
        assertTrue(Arrays.equals(keyTwo, keyThree))
    }

    // test08 STE_20
    @Test fun unregister() {
        try {
            ethree.unregister().execute()
        } catch (throwable: Throwable) {
            if (throwable !is EThreeException)
                fail()
        }

        ethree.register().execute()
        ethree.unregister().execute()

        try {
            keyStorage.load(ethree.identity)
        } catch (throwable: Throwable) {
            if (throwable !is KeyEntryNotFoundException)
                fail()
        }

        val cards = ethree.cardManager.searchCards(ethree.identity)
        assertTrue(cards.isEmpty())
    }

    // test09 STE_44
    @Test fun register_with_provided_key() {
        val keyPair = virgilCrypto.generateKeyPair()
        val data = virgilCrypto.exportPrivateKey(keyPair.privateKey)

        ethree.register(keyPair).execute()

        val keyEntry = keyStorage.load(ethree.identity)
        assertNotNull(keyEntry)
        assertArrayEquals(data, keyEntry.value)

        val cards = ethree.cardManager.searchCards(ethree.identity)
        assertTrue(cards.isNotEmpty())
        assertEquals(ethree.identity, cards.first().identity)
    }
}
