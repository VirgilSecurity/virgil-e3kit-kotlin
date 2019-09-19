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

import android.support.test.runner.AndroidJUnit4
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.exception.GroupNotFoundGroupException
import com.virgilsecurity.android.common.exception.InvalidParticipantsCountGroupException
import com.virgilsecurity.android.common.exception.ShortGroupIdGroupException
import com.virgilsecurity.android.common.model.FindUsersResult
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.android.ethree.utils.TestUtils
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.*

@RunWith(AndroidJUnit4::class)
class EThreeGroupTests {

    private lateinit var identity: String
    private lateinit var crypto: VirgilCrypto
    private lateinit var ethree: EThree

    @Before
    fun setup() {
        this.identity = UUID.randomUUID().toString()
        this.crypto = TestConfig.virgilCrypto

        this.ethree = createEThree()
    }

    @Test
    fun ste26() {
        // Create with invalid participants count. Should throw error
        val groupId = Data(this.crypto.generateRandomData(100))
        val card = this.ethree.findUser(ethree.identity).get()

        try {
            val users = FindUsersResult()
            users[ethree.identity] = card
            this.ethree.createGroup(groupId, users)
            fail()
        } catch (e: InvalidParticipantsCountGroupException) {
        }

        val users = FindUsersResult()
        for (i in 0 until 100) {
            val identity = UUID.randomUUID().toString()
            users[identity] = card
        }
        try {
            this.ethree.createGroup(groupId, users)
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

        val groupId1 = Data(this.crypto.generateRandomData(100))
        val groupId2 = Data(this.crypto.generateRandomData(100))

        val users = this.ethree.findUsers(listOf(ethree.identity, ethree2.identity)).get()

        val group1 = this.ethree.createGroup(groupId1, users).get()

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

        val groupId = Data(this.crypto.generateRandomData(5))

        val lookup = this.ethree.findUsers(listOf(ethree2.identity)).get()

        try {
            this.ethree.createGroup(groupId, lookup).get()
            fail()
        } catch (e: ShortGroupIdGroupException) {
        }
    }

    @Test
    fun ste29() {
        // get_group
        val ethree2 = createEThree()

        val groupId = Data(this.crypto.generateRandomData(100))
        assertNull(this.ethree.getGroup(groupId))

        val lookup = this.ethree.findUsers(listOf(ethree2.identity)).get()

        val group = this.ethree.createGroup(groupId, lookup).get()

        val cachedGroup = this.ethree.getGroup(groupId)
        assertNotNull(cachedGroup)
        assertEquals(cachedGroup!!.participants, group.participants)
        assertEquals(cachedGroup.initiator, group.initiator)
    }

    @Test
    fun ste30() {
        // load_group
        val ethree2 = createEThree()

        val groupId = Data(this.crypto.generateRandomData(100))

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

        val groupId = Data(this.crypto.generateRandomData(100))

        val card1 = ethree2.findUser(this.ethree.identity).get()

        try {
            ethree2.loadGroup(groupId, card1).get()
            fail()
        } catch (e: GroupNotFoundGroupException) {
        }

        val lookup = this.ethree.findUsers(listOf(ethree3.identity)).get()

        this.ethree.createGroup(groupId, lookup).get()

        try {
            ethree2.loadGroup(groupId, card1).get()
            fail()
        } catch (e: GroupNotFoundGroupException) {
        }
    }

    private fun createEThree(): EThree {
        val tokenCallback = object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return TestUtils.generateTokenString(identity)
            }
        }

        val ethree = EThree(this.identity, tokenCallback, TestConfig.context)
        ethree.register()
        return ethree
    }
}
