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

package com.virgilsecurity.android.ethree.common.storage.sql

import android.hardware.camera2.CameraManager
import androidx.room.Room
import androidx.test.runner.AndroidJUnit4
import com.google.gson.Gson
import com.virgilsecurity.android.common.storage.CardStorage
import com.virgilsecurity.android.common.storage.sql.ETheeDatabase
import com.virgilsecurity.android.common.storage.sql.SQLCardStorage
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.*


@RunWith(AndroidJUnit4::class)
class SQLCardStorageTest {

    private val cIdentity1 = "8DA6A11D-F8BC-4A1D-A221-CEE3A2D70631"
    private val cIdentity2 = "D4E8E4CA-6FB4-42B6-A3FF-DBBC19201DD6"

    private val cCardId1 = "b2e6c8bee5cfa40fa2ac2bc8961057600bced26bc5b29aab04014c5141a91bd4"
    private val cCardId2 = "9ff917a7a1aa0891b875d4a9e43972a0fb694879bf8987790c1615dd864a38a4"
    private val cCardId3 = "e66465a08232beb55e33b4ce5e8772d748911c9b830797336e1ce342c78829a2"

    private lateinit var identity: String
    private lateinit var storage: CardStorage
    private lateinit var crypto: VirgilCrypto
    private lateinit var verifier: VirgilCardVerifier
    private lateinit var dbName: String

    @Before
    fun setup() {
        identity = UUID.randomUUID().toString()
        crypto = VirgilCrypto()
        verifier = VirgilCardVerifier(VirgilCardCrypto(crypto))

        dbName = String.format("ethree-database-%s", identity)
//        DbHelper(TestConfig.context, "cards.sqlite3", dbName).installDatabase()
        val db = Room.databaseBuilder(TestConfig.context, ETheeDatabase::class.java, dbName)
                .createFromAsset("databases/cards.sqlite3")
                .build()

        this.storage = SQLCardStorage(TestConfig.context, identity, crypto, verifier)
    }

    @After
    fun tearDown() {
        TestConfig.context.deleteDatabase(this.dbName)
    }

    @Test
    fun getCard() {
        // Cards predefined in database should match
        checkCardsById()
    }

    @Test
    fun searchCards() {
        // Cards predefined in database should match
        checkCardsByIdentity()
    }

    @Test
    fun storeCard() {
        // Cards predefined in database should match
        val identity2 = UUID.randomUUID().toString()
        val storage2 = SQLCardStorage(TestConfig.context, identity2, crypto, verifier)

        val cards = storage.searchCards(listOf(this.cIdentity1, this.cIdentity2))

        storage2.storeCard(cards[0])
        storage2.storeCard(cards[1])

        checkCardsByIdentity(storage2)
        checkCardsById(storage2)
    }

    @Test
    fun storeCard_rotate_card() {
        // Rotate card should update both cards
        val identity2 = UUID.randomUUID().toString()
        val storage2 = SQLCardStorage(TestConfig.context, identity2, crypto, verifier)

        val card1 = storage.getCard(this.cCardId1)
        assertNotNull(card1)
        val card2 = storage.getCard(this.cCardId2)
        assertNotNull(card2)
        val card3 = storage.getCard(this.cCardId3)
        assertNotNull(card3)

        card2!!.isOutdated = false
        storage2.storeCard(card2)
        storage2.storeCard(card1!!)
        storage2.storeCard(card3!!)

        checkCardsByIdentity(storage2)
        checkCardsById(storage2)
    }

    @Test
    fun getNewestCardIds() {
        // Cards predefined in database should match
        val identity2 = UUID.randomUUID().toString()
        val storage2 = SQLCardStorage(TestConfig.context, identity2, crypto, verifier)

        val cards = storage.searchCards(listOf(this.cIdentity1, this.cIdentity2))
        assertEquals(2, cards.size)

        storage2.storeCard(cards[0])
        storage2.storeCard(cards[1])

        val ids = storage2.getNewestCardIds()
        assertEquals(2, ids.size)

        assertTrue(ids.contains(this.cCardId1))
        assertTrue(ids.contains(this.cCardId3))
    }

    @Test
    fun reset() {
        // Predefined database should be empty
        val identity2 = UUID.randomUUID().toString()
        val storage2 = SQLCardStorage(TestConfig.context, identity2, crypto, verifier)

        val cards = storage.searchCards(listOf(this.cIdentity1, this.cIdentity2))

        storage2.storeCard(cards[0])
        storage2.storeCard(cards[1])

        storage2.reset()

        assertNull(storage2.getCard(this.cCardId1))
        assertNull(storage2.getCard(this.cCardId2))
        assertNull(storage2.getCard(this.cCardId3))
    }

    @Test
    fun store_load() {
        val tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback(function = {
            return@RenewJwtCallback null
        }))
        val cardManager = CardManager(VirgilCardCrypto(VirgilCrypto()), tokenProvider, VirgilCardVerifier(VirgilCardCrypto(VirgilCrypto())))
        val card1 = cardManager.importCardAsJson("{\"content_snapshot\":\"eyJ2ZXJzaW9uIjoiNS4wIiwicHVibGljX2tleSI6Ik1Db3dCUVlESzJWd0F5RUFkV2ZBWXowNnNoQUNjeFdUVWlhZkRIcE9PcHBrUkdrNWdCZjllUzQ0SlM0PSIsImlkZW50aXR5IjoiRDRFOEU0Q0EtNkZCNC00MkI2LUEzRkYtREJCQzE5MjAxREQ2IiwiY3JlYXRlZF9hdCI6MTU2NDU4NTYwOX0=\",\"signatures\":[{\"signature\":\"MFEwDQYJYIZIAWUDBAIDBQAEQIR0PND1Yic36leh\\/vQ+oMXmR8vJX+Vm6pRF4C6z52IP5PK4TMWobPcymrkY+lOllxQNG1ORROoXBfcKSWxkWAw=\",\"signer\":\"self\"}\n,{\"signature\":\"MFEwDQYJYIZIAWUDBAIDBQAEQDFlyBswkrCV3+NSGwn67KFLwU\\/FznY\\/5o+wThgdCzliCP7oMjMe8uGSq4A1GNOEcNoMZhPz7Tku24dncXA0cgk=\",\"signer\":\"virgil\"}]}")

        storage.storeCard(card1)

        val importedCard1 = storage.getCard(this.cCardId3)
        assertNotNull(importedCard1)
    }

    private fun checkCardsById(storage: CardStorage = this.storage) {
        val card1 = storage.getCard(this.cCardId1)
        assertNotNull(card1)
        val card2 = storage.getCard(this.cCardId2)
        assertNotNull(card2)
        val card3 = storage.getCard(this.cCardId3)
        assertNotNull(card2)

        assertEquals(this.cIdentity1, card1!!.identity)
        assertEquals(this.cIdentity1, card2!!.identity)
        assertEquals(this.cIdentity2, card3!!.identity)

        assertEquals(card2.identifier, card1.previousCardId)
        assertNull(card2.previousCardId)
        assertNull(card3.previousCardId)

        assertNull(card1.previousCard)
        assertNull(card2.previousCard)
        assertNull(card3.previousCard)

        assertFalse(card1.isOutdated)
        assertTrue(card2.isOutdated)
        assertFalse(card3.isOutdated)
    }

    private fun checkCardsByIdentity(storage: CardStorage = this.storage) {
        val cards = storage.searchCards(listOf(this.cIdentity1, this.cIdentity2))
        assertEquals(2, cards.size)


        val card1 = cards.first{ it.identity == this.cIdentity1}
        val card2 = cards.first{ it.identity == this.cIdentity2}

        assertNotNull(card1.previousCardId)
        assertNull(card2.previousCardId)

        assertNotNull(card1.previousCard)
        assertNull(card1.previousCard.previousCard)
        assertNull(card2.previousCard)

        assertFalse(card1.isOutdated)
        assertTrue(card1.previousCard.isOutdated)
        assertFalse(card2.isOutdated)
    }
}
