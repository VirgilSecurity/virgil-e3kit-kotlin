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

package com.virgilsecurity.android.common.worker

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.virgilsecurity.android.common.build.VirgilInfo
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.exception.*
import com.virgilsecurity.android.common.manager.GroupManager
import com.virgilsecurity.android.common.manager.LookupManager
import com.virgilsecurity.android.common.model.*
import com.virgilsecurity.android.common.storage.cloud.CloudTicketStorage
import com.virgilsecurity.android.common.storage.local.FileGroupStorage
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.android.common.storage.sql.SQLCardStorage
import com.virgilsecurity.android.common.util.Const
import com.virgilsecurity.android.common.utils.TestConfig
import com.virgilsecurity.android.common.utils.TestUtils
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.common.extension.toData
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.crypto.foundation.Base64
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.HttpClient
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.JsonKeyEntry
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.InputStreamReader
import java.util.*
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class GroupTests {
    private lateinit var crypto: VirgilCrypto
    private lateinit var ethree: EThree
    private lateinit var groupId: Data

    @Before
    fun setup() {
        this.crypto = TestConfig.virgilCrypto

        this.ethree = createEThree()
        this.groupId = this.crypto.generateRandomData(100).toData()
    }

    // test001 STE_26
    @Test fun create_with_invalid_participants_count() {
        val card = this.ethree.findUser(ethree.identity).get()

        val lookup = FindUsersResult()
        for (i in 0 until 100) {
            val identity = UUID.randomUUID().toString()
            lookup[identity] = card
        }
        try {
            this.ethree.createGroup(groupId, lookup).get()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description
                               == GroupException.Description.INVALID_PARTICIPANTS_COUNT)
        }

        val firstEntry = lookup.entries.first()
        val newLookup = FindUsersResult()
        newLookup[firstEntry.key] = firstEntry.value

        val group = this.ethree.createGroup(groupId, newLookup).get()
        assertEquals(2, group.participants.size)
        assertTrue(group.participants.contains(this.ethree.identity))
        assertTrue(group.participants.contains(newLookup.keys.first()))
    }

    // test002 STE_27
    @Test fun create_should_add_self() {
        val ethree2 = createEThree()

        val groupId2 = this.crypto.generateRandomData(100).toData()

        val users = this.ethree.findUsers(listOf(ethree.identity, ethree2.identity)).get()

        val group1 = this.ethree.createGroup(groupId, users).get()

        val users2 = FindUsersResult()
        val ethree2Card = users.get(ethree2.identity)
        assertNotNull(ethree2Card)
        users2[ethree2.identity] = ethree2Card!!
        val group2 = this.ethree.createGroup(groupId2, users2).get()

        assertTrue(group2.participants.contains(ethree.identity))
        assertEquals(group1.participants, group2.participants)
    }

    // test003 STE_28
    @Test fun groupId_should_not_be_short() {
        val ethree2 = createEThree()
        val invalidGroupId = this.crypto.generateRandomData(5).toData()

        val lookup = this.ethree.findUsers(listOf(ethree2.identity)).get()

        try {
            this.ethree.createGroup(invalidGroupId, lookup).get()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.SHORT_GROUP_ID)
        }
    }

    // test004 STE_29
    @Test fun get_group() {
        val ethree2 = createEThree()
        assertNull(this.ethree.getGroup(groupId))

        val lookup = this.ethree.findUsers(listOf(ethree2.identity)).get()

        val group = this.ethree.createGroup(groupId, lookup).get()
        assertNotNull(group)

        val cachedGroup = this.ethree.getGroup(groupId)
        assertNotNull(cachedGroup)
        assertEquals(cachedGroup!!.participants, group.participants)
        assertEquals(cachedGroup.initiator, group.initiator)
    }

    // test005 STE_30
    @Test fun load_group() {
        val ethree2 = createEThree()

        val lookup = this.ethree.findUsers(listOf(ethree2.identity)).get()

        val group1 = this.ethree.createGroup(groupId, lookup).get()

        val card = ethree2.findUser(this.ethree.identity).get()

        val group2 = ethree2.loadGroup(groupId, card).get()
        assertNotNull(group2)
        assertEquals(group1.participants, group2.participants)
        assertEquals(group1.initiator, group2.initiator)
    }

    // test006 STE_31
    @Test fun load_alien_or_unexistent_group() {
        val ethree2 = createEThree()
        val ethree3 = createEThree()

        val card1 = ethree2.findUser(this.ethree.identity).get()

        try {
            ethree2.loadGroup(groupId, card1).get()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.GROUP_WAS_NOT_FOUND)
        }

        val lookup = this.ethree.findUsers(listOf(ethree3.identity)).get()

        this.ethree.createGroup(groupId, lookup).get()

        try {
            ethree2.loadGroup(groupId, card1).get()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.GROUP_WAS_NOT_FOUND)
        }
    }

    // test007 STE_32
    @Test fun actions_on_deleted_group() {
        val ethree2 = createEThree()

        val lookup = this.ethree.findUsers(listOf(ethree2.identity)).get()
        this.ethree.createGroup(groupId, lookup).get()
        val card1 = ethree2.findUser(this.ethree.identity).get()
        val group2 = ethree2.loadGroup(groupId, card1).get()

        this.ethree.deleteGroup(groupId).execute()
        val gr = this.ethree.getGroup(groupId)
        assertNull(gr)

        try {
            this.ethree.loadGroup(groupId, card1).get()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.GROUP_WAS_NOT_FOUND)
        }

        try {
            group2.update().execute()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.GROUP_WAS_NOT_FOUND)
        }

        try {
            ethree2.loadGroup(groupId, card1).get()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.GROUP_WAS_NOT_FOUND)
        }

        assertNull(ethree2.getGroup(groupId))
    }

    // test008 STE_33
    @Test fun add_more_than_max() {
        val identity = UUID.randomUUID().toString()
        val selfKeyPair = crypto.generateKeyPair()

        val localGroupStorage = FileGroupStorage(identity,
                                                 crypto,
                                                 selfKeyPair,
                                                 TestConfig.context.filesDir.absolutePath)
        val accessTokenProvider = CachingJwtProvider {
            TestUtils.generateToken(identity)
        }
        val keyStorage = DefaultKeyStorage(TestConfig.context.filesDir.absolutePath,
                                           "virgil.keystore")
        val localKeyStorage = LocalKeyStorage(identity, keyStorage, crypto)
        val ticketStorageCloud = CloudTicketStorage(accessTokenProvider, localKeyStorage)
        val virgilCardVerifier = VirgilCardVerifier(VirgilCardCrypto(crypto))
        val cardStorageSqlite = SQLCardStorage(TestConfig.context,
                                               identity,
                                               crypto,
                                               virgilCardVerifier)
        val httpClient = HttpClient(Const.ETHREE_NAME, VirgilInfo.VERSION)
        val cardManager = CardManager(VirgilCardCrypto(crypto),
                                      accessTokenProvider,
                                      VirgilCardVerifier(VirgilCardCrypto(crypto), false, false),
                                      VirgilCardClient(Const.VIRGIL_BASE_URL + Const.VIRGIL_CARDS_SERVICE_PATH,
                                                       httpClient))
        val lookupManager = LookupManager(cardStorageSqlite, cardManager, null)

        val groupManager = GroupManager(localGroupStorage,
                                        ticketStorageCloud,
                                        localKeyStorage,
                                        lookupManager)

        val participants = mutableSetOf<String>()

        for (i in 0 until 100) {
            val identity = UUID.randomUUID().toString()
            participants.add(identity)
        }

        val sessionId = this.crypto.generateRandomData(32).toData()

        val ticket = Ticket(this.crypto, sessionId, participants)
        val rawGroup = RawGroup(GroupInfo(identity), listOf(ticket))

        assertNotNull(groupManager)
        val group = Group(rawGroup, localKeyStorage, groupManager, lookupManager)

        val card = TestUtils.publishCard()

        try {
            group.add(card).execute()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description
                               == GroupException.Description.INVALID_PARTICIPANTS_COUNT)
        }
    }

    // test009 STE_72
    @Test fun remove_last_participant() {
        val ethree2 = createEThree()

        val card = ethree2.findUser(ethree2.identity).get()
        assertNotNull(card)

        val group = ethree2.createGroup(this.groupId).get()

        try {
            group.remove(card).execute()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description
                               == GroupException.Description.INVALID_PARTICIPANTS_COUNT)
        }
    }

    // test010 STE_35
    @Test fun remove() {
        val ethree2 = createEThree()
        val ethree3 = createEThree()

        val lookup = this.ethree.findUsers(listOf(ethree2.identity, ethree3.identity)).get()
        val card2 = lookup[ethree2.identity]
        assertNotNull(card2)

        val group1 = this.ethree.createGroup(groupId, lookup).get()

        val card1 = ethree2.findUser(this.ethree.identity).get()
        val group2 = ethree2.loadGroup(groupId, card1).get()
        val group3 = ethree3.loadGroup(groupId, card1).get()

        group1.remove(card2!!).execute()
        assertFalse(group1.participants.contains(ethree2.identity))

        group3.update().execute()
        assertFalse(group3.participants.contains(ethree2.identity))

        try {
            group2.update().execute()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.GROUP_WAS_NOT_FOUND)
        }

        try {
            ethree2.loadGroup(groupId, card1).get()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.GROUP_WAS_NOT_FOUND)
        }

        assertNull(ethree2.getGroup(groupId))
    }

    // test011 STE_37
    @Test fun add() {
        val ethree2 = createEThree()
        val ethree3 = createEThree()

        val lookup = this.ethree.findUsers(listOf(ethree2.identity)).get()

        val card1 = ethree2.findUser(this.ethree.identity).get()

        val group1 = this.ethree.createGroup(this.groupId, lookup).get()

        val group2 = ethree2.loadGroup(this.groupId, card1).get()

        val card3 = this.ethree.findUser(ethree3.identity).get()
        group1.add(card3).execute()

        val participants = setOf(this.ethree.identity, ethree2.identity, ethree3.identity)
        assertEquals(participants, group1.participants)

        group2.update().execute()

        val group3 = ethree3.loadGroup(this.groupId, card1).get()

        assertEquals(participants, group2.participants)
        assertEquals(participants, group3.participants)
    }

    // test012 STE_36
    @Test fun change_group_by_non_initiator() {
        val ethree2 = createEThree()
        val ethree3 = createEThree()
        val ethree4 = createEThree()
        val identities = listOf(ethree2.identity, ethree3.identity)

        val lookup = this.ethree.findUsers(identities).get()
        this.ethree.createGroup(this.groupId, lookup).get()
        val card3 = lookup[ethree3.identity]
        assertNotNull(card3)

        val ethree1Card = ethree2.findUser(this.ethree.identity).get()
        val group2 = ethree2.loadGroup(this.groupId, ethree1Card).get()

        try {
            group2.remove(lookup[ethree3.identity]!!).execute()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.GROUP_PERMISSION_DENIED)
        }

        try {
            val ethree4Card = ethree2.findUser(ethree4.identity).get()
            group2.add(ethree4Card).execute()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.GROUP_PERMISSION_DENIED)
        }
    }

    // test013 STE_38
    @Test fun decrypt_with_old_card() {
        val ethree2 = createEThree()

        val lookup = this.ethree.findUsers(listOf(ethree2.identity)).get()
        val group1 = this.ethree.createGroup(groupId, lookup).get()

        val card1 = ethree2.findUser(this.ethree.identity).get()
        val group2 = ethree2.loadGroup(this.groupId, card1).get()

        val card2 = this.ethree.findUser(ethree2.identity).get()

        ethree2.cleanup()
        ethree2.rotatePrivateKey().execute()

        val encrypted = group2.encrypt("Some text")

        try {
            group1.decrypt(encrypted, card2)
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.VERIFICATION_FAILED)
        }
    }

    // test014 STE_39
    @Test fun integration_encryption() {
        val ethree2 = createEThree()
        val ethree3 = createEThree()

        val identities = listOf(ethree2.identity)

        val card1 = ethree2.findUser(this.ethree.identity).get()

        // User1 creates group, encrypts
        val lookup = this.ethree.findUsers(identities).get()
        val group1 = this.ethree.createGroup(this.groupId, lookup).get()

        val message1 = UUID.randomUUID().toString()
        val encrypted1 = group1.encrypt(message1)
        val selfDecrypted1 = group1.decrypt(encrypted1, card1)
        assertEquals(message1, selfDecrypted1)

        // User2 updates group, decrypts
        val group2 = ethree2.loadGroup(this.groupId, card1).get()
        val decrypted1 = group2.decrypt(encrypted1, card1)
        assertEquals(message1, decrypted1)

        // Add User3, encrypts
        val card3 = this.ethree.findUser(ethree3.identity).get()
        group1.add(card3).execute()

        val message2 = UUID.randomUUID().toString()
        val encrypted2 = group1.encrypt(message2)
        val selfDecrypted2 = group1.decrypt(encrypted2, card1)
        assertEquals(message2, selfDecrypted2)

        // Other updates, decrypts
        group2.update().execute()
        val group3 = ethree3.loadGroup(groupId, card1).get()

        val decrypted22 = group2.decrypt(encrypted2, card1)
        assertEquals(message2, decrypted22)

        val decrypted23 = group3.decrypt(encrypted2, card1)
        assertEquals(message2, decrypted23)

        // Remove User2
        group1.remove(lookup).execute()

        val message3 = UUID.randomUUID().toString()
        val encrypted3 = group1.encrypt(message3)
        val selfDecrypted3 = group1.decrypt(encrypted3, card1)
        assertEquals(message3, selfDecrypted3)

        // Other updates, decrypts
        try {
            group2.decrypt(encrypted3, card1)
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.GROUP_IS_OUTDATED)
        }

        group3.update().execute()
        val decrypted3 = group3.decrypt(encrypted3, card1)
        assertEquals(message3, decrypted3)

        // User3 rotates key
        ethree3.cleanup()
        ethree3.rotatePrivateKey().execute()

        try {
            group3.update().execute()
            fail()
        } catch (e: Exception) {
        }

        assertNull(ethree3.getGroup(this.groupId))

        try {
            ethree3.loadGroup(groupId, card1).get()
            fail()
        } catch (e: Exception) {
        }

        // User 1 encrypts, reAdds User3
        val message4 = UUID.randomUUID().toString()
        val encrypted4 = group1.encrypt(message4)

        val newCard3 = this.ethree.findUser(ethree3.identity, true).get()
        group1.reAdd(newCard3).execute()

        val newGroup3 = ethree3.loadGroup(this.groupId, card1).get()
        val decrypted4 = newGroup3.decrypt(encrypted4, card1)
        assertEquals(message4, decrypted4)
    }

    // test015 STE_42
    @Test fun decrypt_with_old_group() {
        val ethree2 = createEThree()
        val ethree3 = createEThree()

        val lookup = this.ethree.findUsers(listOf(ethree2.identity, ethree3.identity)).get()
        val card3 = lookup[ethree3.identity]
        assertNotNull(card3)

        val group1 = this.ethree.createGroup(this.groupId, lookup).get()

        val card1 = ethree2.findUser(this.ethree.identity).get()
        val group2 = ethree2.loadGroup(this.groupId, card1).get()

        group1.remove(card3!!).execute()

        val message = UUID.randomUUID().toString()
        val encrypted = group1.encrypt(message)

        try {
            group2.decrypt(encrypted, card1)
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.GROUP_IS_OUTDATED)
        }
    }

    // test016 STE_43
    @Test fun decrypt_with_old_group_two() {
        val ethree2 = createEThree()

        val lookup = this.ethree.findUsers(listOf(ethree2.identity)).get()
        val group1 = this.ethree.createGroup(this.groupId, lookup).get()

        val card1 = ethree2.findUser(this.ethree.identity).get()
        val group2 = ethree2.loadGroup(this.groupId, card1).get()

        val date1 = Date()
        val message1 = UUID.randomUUID().toString()
        val encrypted1 = group2.encrypt(message1)

        Thread.sleep(1000)

        ethree2.cleanup()
        ethree2.rotatePrivateKey().execute()

        val date2 = Date()
        val message2 = UUID.randomUUID().toString()
        val encrypted2 = group2.encrypt(message2)

        val card2 = this.ethree.findUser(ethree2.identity, true).get()

        try {
            group1.decrypt(encrypted1, card2)
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.VERIFICATION_FAILED)
        }

        try {
            group1.decrypt(encrypted1, card2, date2)
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.VERIFICATION_FAILED)
        }

        val dectypted1 = group1.decrypt(encrypted1, card2, date1)
        assertEquals(message1, dectypted1)

        try {
            group1.decrypt(encrypted2, card2, date1)
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.VERIFICATION_FAILED)
        }

        val dectypted2 = group1.decrypt(encrypted2, card2, date2)
        assertEquals(message2, dectypted2)
    }

    // test017 STE_45
    @Test fun compatibility() {
        val compatDataStream = this.javaClass
                .classLoader
                ?.getResourceAsStream("compat/compat_data.json")
        val compatJson = JsonParser().parse(InputStreamReader(compatDataStream)) as JsonObject
        val groupCompatJson = compatJson.getAsJsonObject("Group")

        val keyStorage = DefaultKeyStorage(TestConfig.DIRECTORY_PATH, TestConfig.KEYSTORE_NAME)
        if (keyStorage.exists(groupCompatJson.get("Identity").asString)) {
            keyStorage.delete(groupCompatJson.get("Identity").asString)
        }

        val privateKeyData = Base64.decode(groupCompatJson.get("PrivateKey").asString.toByteArray())
        keyStorage.store(JsonKeyEntry(groupCompatJson.get("Identity").asString, privateKeyData))

        val privateKeyCompat = crypto.importPrivateKey(Base64.decode(compatJson.get("ApiPrivateKey").asString.toByteArray()))
        val jwtGenerator = JwtGenerator(
            compatJson.get("AppId").asString,
            privateKeyCompat.privateKey,
            compatJson.get("ApiKeyId").asString,
            TimeSpan.fromTime(600, TimeUnit.SECONDS),
            VirgilAccessTokenSigner(TestConfig.virgilCrypto)
        )

        val tokenCallback = object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return jwtGenerator
                        .generateToken(groupCompatJson.get("Identity").asString)
                        .stringRepresentation()
            }
        }

        val ethree = EThree(groupCompatJson.get("Identity").asString,
                            tokenCallback,
                            TestConfig.context)

        // Load group
        val initiatorCard = ethree.findUser(groupCompatJson.get("Initiator").asString).get()

        val groupIdData = Data.fromBase64String(groupCompatJson.get("GroupId").asString)
        val group = ethree.loadGroup(groupIdData, initiatorCard).get()

        val compatParticipants =
                groupCompatJson.get("Participants").asJsonArray.map { it.asString }.toSet()
        assertTrue(group.participants.sorted() == compatParticipants.sorted())

        val decrypted = group.decrypt(groupCompatJson.get("EncryptedText").asString, initiatorCard)
        val originCompatText = groupCompatJson.get("OriginText").asString

        assertEquals(originCompatText, decrypted)
    }

    // test018 STE_46
    @Test fun string_identifier() {
        val ethree2 = createEThree()

        val identifier = this.crypto.generateRandomData(32).toData()

        val result = this.ethree.findUsers(listOf(ethree2.identity)).get()
        this.ethree.createGroup(identifier, result).get()

        val card1 = ethree2.findUser(this.ethree.identity).get()
        ethree2.loadGroup(identifier, card1)

        this.ethree.getGroup(identifier)
        ethree2.getGroup(identifier)

        this.ethree.deleteGroup(identifier)
    }

    // test019 STE_73
    @Test fun added_participant_should_decrypt_history() {
        val ethree2 = createEThree()

        val identifier = UUID.randomUUID().toString()
        val group1 = this.ethree.createGroup(identifier).get()

        val message = UUID.randomUUID().toString()
        val encrypted = group1.encrypt(message)

        val card2 = ethree.findUser(ethree2.identity).get()
        group1.add(card2).execute()

        val card1 = ethree2.findUser(ethree.identity).get()
        val group2 = ethree2.loadGroup(identifier, card1).get()

        val decrypted = group2.decrypt(encrypted, card1)

        assertEquals(message, decrypted)
    }

    // test020 STE_85
    @Test fun delete_unexistent_channel() {
        val fakeId = UUID.randomUUID().toString()
        ethree.deleteGroup(fakeId).execute()
    }

    // test021 STE_86
    @Test fun add_participants() {
        val ethree2 = createEThree()

        val identifier = UUID.randomUUID().toString()
        val group = this.ethree.createGroup(identifier).get()
        val card2 = ethree.findUser(ethree2.identity).get()
        group.add(card2).execute()
        val cachedGroup = this.ethree.getGroup(identifier)!!

        assertEquals(cachedGroup.participants.toSet(), setOf(ethree.identity, ethree2.identity))
    }

    @Test fun initiator_removes_self_should_fail() {
        val ethree2 = createEThree()
        val users = this.ethree.findUsers(listOf(ethree.identity, ethree2.identity)).get()
        val group = this.ethree.createGroup(groupId, users).get()
        val card = this.ethree.findUser(ethree.identity).get()

        // Single user removal
        try {
            group.remove(card).execute()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.INITIATOR_REMOVAL_FAILED)
        }

        // Multiple user removal
        try {
            val participants = FindUsersResult()
            participants[this.ethree.identity] = card
            group.remove(participants).execute()
            fail()
        } catch (exception: GroupException) {
            assertTrue(exception.description == GroupException.Description.INITIATOR_REMOVAL_FAILED)
        }
    }

    @Test fun restored_ethree_encryption() {
        val ethree2 = createEThree()

        val identities = listOf(ethree2.identity)

        val card1 = ethree2.findUser(this.ethree.identity).get()

        // User1 creates group, encrypts
        val lookup = this.ethree.findUsers(identities).get()
        val group1 = this.ethree.createGroup(this.groupId, lookup).get()

        val message1 = UUID.randomUUID().toString()
        val encrypted1 = group1.encrypt(message1)
        val selfDecrypted1 = group1.decrypt(encrypted1, card1)
        assertEquals(message1, selfDecrypted1)

        // User2 updates group, decrypts
        val group2 = ethree2.loadGroup(this.groupId, card1).get()
        val decrypted1 = group2.decrypt(encrypted1, card1)
        assertEquals(message1, decrypted1)

        val message2 = UUID.randomUUID().toString()
        val encrypted2 = group2.encrypt(message2)

        // User1 restarts ethree, decrypts
        val ethreeRestored = createEThree(this.ethree.identity)
        val restoredGroup1 = ethreeRestored.getGroup(this.groupId)
        val restoredDecrypted1 = restoredGroup1?.decrypt(encrypted1, card1)
        assertEquals(message1, restoredDecrypted1)

        val card2 = ethreeRestored.findUser(ethree2.identity).get()
        val decrypted2 = restoredGroup1?.decrypt(encrypted2, card2)
        assertEquals(message2, decrypted2)
    }

    private fun createEThree(identity: String? = null): EThree {
        val ethreeIdentity = identity ?: UUID.randomUUID().toString()
        val tokenCallback = object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return TestUtils.generateTokenString(ethreeIdentity)
            }
        }

        val ethree = EThree(ethreeIdentity, tokenCallback, TestConfig.context)
        if (identity == null) {
            ethree.register().execute()
        }
        return ethree
    }
}
