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

package com.virgilsecurity.android.ethree_benchmark

import androidx.benchmark.junit4.BenchmarkRule
import androidx.benchmark.junit4.measureRepeated
import androidx.test.filters.LargeTest
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.utils.TestConfig
import com.virgilsecurity.android.common.utils.TestUtils
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.sdk.crypto.KeyPairType
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import org.junit.Ignore
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import java.util.*

@LargeTest
@RunWith(Parameterized::class)
class EThreeBenchmark(
        private val keyType: KeyPairType
) {

    @get:Rule
    val benchmarkRule = BenchmarkRule()

    private fun setupDevice(keyPair: VirgilKeyPair? = null): EThree {
        val identity = UUID.randomUUID().toString()

        val tokenCallback = object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return TestUtils.generateTokenString(identity)
            }
        }

        val ethree = EThree(identity, tokenCallback, TestConfig.context)

        ethree.register(keyPair).execute()

        return ethree
    }

    // test01
    @Ignore("Run only on a purpose on a real device (takes a lot of time ~1h+)")
    @Test
    fun findUser_encrypt() {
        println("Testing $keyType")

        val aliceKeyPair = TestConfig.virgilCrypto.generateKeyPair(keyType)
        val bobKeyPair = TestConfig.virgilCrypto.generateKeyPair(keyType)

        val alice = setupDevice(aliceKeyPair)
        val bob = setupDevice(bobKeyPair)

        alice.findUser(bob.identity).get()

        benchmarkRule.measureRepeated {
            val bobCard = alice.findCachedUser(bob.identity).get()!!

            alice.authEncrypt(TEXT, bobCard)
        }
    }

    // test02
    @Ignore("Run only on a purpose on a real device (takes a lot of time ~1h+)")
    @Test
    fun findUser_decrypt() {
        val aliceKeyPair = TestConfig.virgilCrypto.generateKeyPair(keyType)
        val bobKeyPair = TestConfig.virgilCrypto.generateKeyPair(keyType)

        val alice = setupDevice(aliceKeyPair)
        val bob = setupDevice(bobKeyPair)

        val bobCard = alice.findUser(bob.identity).get()
        val encrypted = alice.authEncrypt(TEXT, bobCard)

        bob.findUser(alice.identity).get()

        benchmarkRule.measureRepeated {
            val aliceCard = bob.findCachedUser(alice.identity).get()!!

            bob.authDecrypt(encrypted, aliceCard)
        }
    }

    // test03
    @Ignore("Run only on a purpose on a real device (takes a lot of time ~1h+)")
    @Test
    fun group_update() {
        val ethree1 = setupDevice()
        val ethree2 = setupDevice()
        val ethree3 = setupDevice()

        val identifier = UUID.randomUUID().toString()

        val result = ethree1.findUsers(listOf(ethree2.identity, ethree3.identity)).get()
        val group1 = ethree1.createGroup(identifier, result).get()

        val card1 = ethree2.findUser(ethree1.identity).get()
        val card3 = ethree1.findUser(ethree3.identity).get()

        val group2 = ethree2.loadGroup(identifier, card1).get()

        val state = benchmarkRule.getState()

        while (state.keepRunning()) {
            state.pauseTiming()

            group1.remove(card3).execute()
            group1.add(card3).execute()

            state.resumeTiming()

            group2.update().execute()
        }
    }

    @Test
    fun dummy_test() {
        val state = benchmarkRule.getState()

        while (state.keepRunning()) {
            UUID.randomUUID()
        }
    }

    companion object {
        private const val TEXT = "Hello, my name is text. I am here to be encrypted (:"

        @JvmStatic
        @Parameterized.Parameters
        fun data(): Collection<Array<KeyPairType>> = arrayListOf(
            arrayOf(KeyPairType.ED25519),
            arrayOf(KeyPairType.SECP256R1)
        )
    }
}
