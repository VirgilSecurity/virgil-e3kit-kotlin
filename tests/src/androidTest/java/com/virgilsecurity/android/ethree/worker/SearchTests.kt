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
import com.virgilsecurity.android.common.callback.OnKeyChangedCallback
import com.virgilsecurity.android.common.exception.FindUsersException
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.android.ethree.utils.TestUtils
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.exception.EmptyArgumentException
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.*

/**
 * SearchTests
 */
@RunWith(AndroidJUnit4::class)
class SearchTests {

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
        this.ethree = setupDevice()

        assertNotNull(this.ethree)
    }

    private fun setupDevice(identity: String? = null): EThree {
        val identityNew = identity ?: UUID.randomUUID().toString()

        val tokenCallback = object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return TestUtils.generateTokenString(identityNew)
            }
        }

        val ethree = EThree(identityNew, tokenCallback, TestConfig.context)

        ethree.register().execute()

        return ethree
    }

    // test01 STE_1
    @Test fun find_users() {
        val cardOne = TestUtils.publishCard()
        val cardTwo = TestUtils.publishCard()
        val cardThree = TestUtils.publishCard(cardTwo.identity, cardTwo.identifier)

        val lookup = ethree.findUsers(listOf(cardOne.identity,
                                             cardTwo.identity,
                                             cardThree.identity)).get()

        assertEquals(2, lookup.size)
        assertTrue(lookup.filterValues { it.identifier == cardOne.identifier }.isNotEmpty())
        assertTrue(lookup.filterValues { it.identifier == cardThree.identifier }.isNotEmpty())
    }

    // test02 STE_2
    @Test fun find_empty_list() {
        try {
            ethree.findUsers(listOf())
        } catch (throwable: Throwable) {
            if (throwable !is EmptyArgumentException)
                fail()
        }
    }

    // test03 STE_23
    @Test fun find_cached_user() {
        val cardOne = TestUtils.publishCard()

        val foundCardOne = ethree.findUser(cardOne.identity).get()
        assertEquals(cardOne.identifier, foundCardOne.identifier)

        val cardTwo = TestUtils.publishCard(cardOne.identity, cardOne.identifier)

        val foundCardTwo = ethree.findUser(cardOne.identity).get()
        assertEquals(foundCardOne.identifier, foundCardTwo.identifier)

        val foundCardThree = ethree.findUser(cardOne.identity, true).get()
        assertEquals(cardTwo.identifier, foundCardThree.identifier)

        val cachedCard = ethree.findCachedUser(cardOne.identity).get() ?: error("")
        assertEquals(cachedCard.identifier, cardTwo.identifier)
    }

    // test04 STE_24
    @Test fun find_duplicate_cards() {
        val cardOne = TestUtils.publishCard()
        TestUtils.publishCard(cardOne.identity)

        try {
            ethree.findUser(cardOne.identity).get()
        } catch (throwable: Throwable) {
            if (throwable !is FindUsersException)
                fail()
        }
    }

    // test05 STE_25
    @Test fun ethree_with_key_changed_callback() {
        val card = TestUtils.publishCard()

        val onKeyChangedCallback = object : OnKeyChangedCallback {
            var called = false

            override fun keyChanged(identity: String) {
                assertEquals(card.identity, identity)
                called = true
            }
        }

        ethree.findUser(card.identity).get()

        val cardNew = TestUtils.publishCard(card.identity, card.identifier)
        val tokenCallback = object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return TestUtils.generateTokenString(ethree.identity)
            }
        }

        val ethreeNew = EThree(ethree.identity,
                               tokenCallback,
                               TestConfig.context,
                               onKeyChangedCallback)

        TestUtils.pause(3 * 1000) // 3 sec

        assertTrue(onKeyChangedCallback.called)

        val cardCached = ethreeNew.findCachedUser(card.identity).get() ?: error("")

        assertEquals(cardNew.identifier, cardCached.identifier)
    }
}
