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

package com.virgilsecurity.android.ethree.java.interaction

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.exception.*
import com.virgilsecurity.android.common.model.*
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.android.ethree.utils.TestUtils
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.crypto.foundation.Base64
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.jwt.JwtGenerator
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
class EThreeGroupTests {
    private lateinit var crypto: VirgilCrypto
    private lateinit var ethree: EThree
    private lateinit var groupId: Data

    @Before
    fun setup() {
        this.crypto = TestConfig.virgilCrypto

        this.ethree = createEThree()
        this.groupId = Data(this.crypto.generateRandomData(100))
    }

    @Test
    fun ste26() {
        // Create with invalid participants count. Should throw error
        val card = this.ethree.findUser(ethree.identity).get()

        try {
            val users = FindUsersResult()
            users[ethree.identity] = card
            this.ethree.createGroup(groupId, users).get()
            fail()
        } catch (e: InvalidParticipantsCountGroupException) {
        }

        val users = FindUsersResult()
        for (i in 0 until 100) {
            val identity = UUID.randomUUID().toString()
            users[identity] = card
        }
        try {
            this.ethree.createGroup(groupId, users).get()
            fail()
        } catch (e: InvalidParticipantsCountGroupException) {
        }

        val firstEntry = users.entries.first()
        val newUsers = FindUsersResult()
        newUsers[firstEntry.key] = firstEntry.value

        val group = this.ethree.createGroup(groupId, newUsers).get()
        assertEquals(2, group.participants.size)
        assertTrue(group.participants.contains(this.ethree.identity))
        assertTrue(group.participants.contains(newUsers.keys.first()))
    }

    @Test
    fun ste27() {
        // createGroup should add self
        val ethree2 = createEThree()

        val groupId2 = Data(this.crypto.generateRandomData(100))

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

    @Test
    fun ste28() {
        // groupId should not be short
        val ethree2 = createEThree()
        val invalidGroupId = Data(this.crypto.generateRandomData(5))

        val lookup = this.ethree.findUsers(listOf(ethree2.identity)).get()

        try {
            this.ethree.createGroup(invalidGroupId, lookup).get()
            fail()
        } catch (e: GroupIdTooShortException) {
        }
    }

    @Test
    fun ste29() {
        // get group
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

    @Test
    fun ste30() {
        // load_group
        val ethree2 = createEThree()

        val lookup = this.ethree.findUsers(listOf(ethree2.identity)).get()

        val group1 = this.ethree.createGroup(groupId, lookup).get()

        val card = ethree2.findUser(this.ethree.identity).get()

        val group2 = ethree2.loadGroup(groupId, card).get()
        assertNotNull(group2)
        assertEquals(group1.participants, group2.participants)
        assertEquals(group1.initiator, group2.initiator)
    }

    @Test
    fun ste31() {
        // load alien or non-existing group should throw error
        val ethree2 = createEThree()
        val ethree3 = createEThree()

        val card1 = ethree2.findUser(this.ethree.identity).get()

        try {
            ethree2.loadGroup(groupId, card1).get()
            fail()
        } catch (e: GroupNotFoundException) {
        }

        val lookup = this.ethree.findUsers(listOf(ethree3.identity)).get()

        this.ethree.createGroup(groupId, lookup).get()

        try {
            ethree2.loadGroup(groupId, card1).get()
            fail()
        } catch (e: GroupNotFoundException) {
        }
    }

    @Test
    fun ste32() {
        // actions on deleted group should throw error
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
        } catch (e: GroupNotFoundException) {
        }

        try {
            group2.update().execute()
            fail()
        } catch (e: GroupNotFoundException) {
        }

        try {
            ethree2.loadGroup(groupId, card1).get()
            fail()
        } catch (e: GroupNotFoundException) {
        }

        assertNull(ethree2.getGroup(groupId))
    }

    @Test
    fun ste33() {
        // add more than max should throw error
        val participants = mutableSetOf<String>()

        for (i in 0 until 100) {
            val identity = UUID.randomUUID().toString()
            participants.add(identity)
        }

        val sessionId = Data(this.crypto.generateRandomData(32))

        val ticket = Ticket(this.crypto, sessionId, participants)
        val rawGroup = RawGroup(GroupInfo(this.ethree.identity), listOf(ticket))

        assertNotNull(this.ethree.groupManager)
        val group = Group(rawGroup, this.crypto, ethree.keyStorageLocal,
                          this.ethree.groupManager!!, this.ethree.lookupManager)

        val card = TestUtils.publishCard()

        try {
            group.add(card).execute()
            fail()
        } catch (e: InvalidParticipantsCountGroupException) {
        }
    }

    @Test
    fun ste34() {
        // remove last participant should throw error
        val ethree2 = createEThree()

        val lookup = this.ethree.findUsers(listOf(ethree2.identity)).get()
        val card = lookup[ethree2.identity]
        assertNotNull(card)

        val group1 = this.ethree.createGroup(groupId, lookup).get()

        try {
            group1.remove(card!!).execute()
            fail()
        } catch (e: InvalidParticipantsCountGroupException) {
        }
    }

    @Test
    fun ste35() {
        // remove
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
        } catch (e: GroupNotFoundException) {
        }

        try {
            ethree2.loadGroup(groupId, card1).get()
            fail()
        } catch (e: GroupNotFoundException) {
        }

        assertNull(ethree2.getGroup(groupId))
    }

    @Test
    fun ste36() {
        // change group by noninitiator should_throw_error
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
            ethree2.deleteGroup(groupId).execute()
            fail()
        } catch (e: PermissionDeniedGroupException) {
        }

        try {
            group2.remove(card3!!).execute()
            fail()
        } catch (e: PermissionDeniedGroupException) {
        }

        try {
            val ethree4Card = ethree2.findUser(ethree4.identity).get()
            group2.add(ethree4Card).execute()
            fail()
        } catch (e: PermissionDeniedGroupException) {
        }
    }

    @Test
    fun ste37() {
        // add
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

    @Test
    fun ste38() {
        // decrypt with old card should throw error
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
        } catch (e: VerificationFailedGroupException) {
        }
    }

    @Test
    fun ste39() {
        // integration_encryption
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
        group2.update()
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
        } catch (e: GroupException) {
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
        } catch (e: GroupException) {
        }

        assertNull(ethree3.getGroup(this.groupId))

        try {
            ethree3.loadGroup(groupId, card1).get()
            fail()
        } catch (e: GroupException) {
        }

        // User 1 encrypts, reAdds User3
        val message4 = UUID.randomUUID().toString()
        val encrypted4 = group1.encrypt(message4)

        val newCard3 = this.ethree.findUser(ethree3.identity, true).get()
        group1.reAdd(newCard3)

        val newGroup3 = ethree3.loadGroup(this.groupId, card1).get()
        val decrypted4 = newGroup3.decrypt(encrypted4, card1)
        assertEquals(message4, decrypted4)
    }

    @Test
    fun ste42() {
        // decrypt with old group should throw error
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
        } catch (e: GroupIsOutdatedGroupException) {
        }
    }

    @Test
    fun ste43() {
        // decrypt with old group should throw error
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
        } catch (e: VerificationFailedGroupException) {
        }

        try {
            group1.decrypt(encrypted1, card2, date2)
            fail()
        } catch (e: VerificationFailedGroupException) {
        }

        val dectypted1 = group1.decrypt(encrypted1, card2, date1)
        assertEquals(message1, dectypted1)

        try {
            group1.decrypt(encrypted2, card2, date1)
            fail()
        } catch (e: VerificationFailedGroupException) {
        }

        val dectypted2 = group1.decrypt(encrypted2, card2, date2)
        assertEquals(message2, dectypted2)
    }

    @Test
    fun ste45() {
        val compatDataStream =
                this.javaClass.classLoader?.getResourceAsStream("compat_data.json")
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

        val groupIdData = groupCompatJson.get("GroupId").asString
        val group = ethree.loadGroup(groupIdData, initiatorCard).get()

        val compatParticipants =
                groupCompatJson.get("GroupId").asJsonArray.map { it.asString }.toSet().sorted()
        assertTrue(group.participants.sorted() == compatParticipants)

        val decrypted = group.decrypt(groupCompatJson.get("EncryptedText").asString, initiatorCard)
        val originCompatText = groupCompatJson.get("OriginText").asString

        assertEquals(originCompatText, decrypted)
    }

    @Test
    fun ste46() {
        // string identifier
        val ethree2 = createEThree()

        val identifier = Data(this.crypto.generateRandomData(32))

        val result = this.ethree.findUsers(listOf(ethree2.identity)).get()
        this.ethree.createGroup(identifier, result).get()

        val card1 = ethree2.findUser(this.ethree.identity).get()
        ethree2.loadGroup(identifier, card1)

        this.ethree.getGroup(identifier)
        ethree2.getGroup(identifier)

        this.ethree.deleteGroup(identifier)
    }

    private fun createEThree(): EThree {
        val identity = UUID.randomUUID().toString()
        val tokenCallback = object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return TestUtils.generateTokenString(identity)
            }
        }

        val ethree = EThree(identity, tokenCallback, TestConfig.context)
        ethree.register().execute()
        return ethree
    }
}
