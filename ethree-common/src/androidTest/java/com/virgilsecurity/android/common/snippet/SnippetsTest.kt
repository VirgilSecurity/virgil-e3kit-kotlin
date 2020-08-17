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

package com.virgilsecurity.android.common.snippet

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.utils.TestConfig
import com.virgilsecurity.android.common.utils.TestUtils
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.*

/**
 * This test covers snippets that used in documentation.
 */
@RunWith(AndroidJUnit4::class)
class SnippetsTest {

    private lateinit var aliceIdentity: String
    private lateinit var bobIdentity: String
    private lateinit var crypto: VirgilCrypto
    private lateinit var aliceEthree: EThree
    private lateinit var bobEthree: EThree

    @Before
    fun setup() {
        this.crypto = VirgilCrypto()
        this.aliceIdentity = UUID.randomUUID().toString()
        this.aliceEthree = EThree(aliceIdentity,
                object : OnGetTokenCallback {
                    override fun onGetToken(): String {
                        return TestUtils.generateTokenString(aliceIdentity)
                    }
                },
                TestConfig.context)
        assertNotNull(this.aliceEthree)
        this.aliceEthree.register().execute()

        this.bobIdentity = UUID.randomUUID().toString()
        this.bobEthree = EThree(bobIdentity,
                object : OnGetTokenCallback {
                    override fun onGetToken(): String {
                        return TestUtils.generateTokenString(bobIdentity)
                    }
                },
                TestConfig.context)
        assertNotNull(this.bobEthree)
        this.bobEthree.register().execute()
    }

    @Test
    fun encryptShared_complex() {
        val triple = encryptShared()
        val p2pEncryptedStreamKeyData = triple.first
        val groupEncryptedStreamKeyData = triple.second
        val encryptedData = triple.third

        val decryptedData = decryptShared(p2pEncryptedStreamKeyData, groupEncryptedStreamKeyData, encryptedData)

        assertArrayEquals("Hello".toByteArray(), decryptedData)
    }

    private fun encryptShared(): Triple<ByteArray, ByteArray, ByteArray> {
        // encryptShared >>

        // 1. Prepare streams.
        val plaintext = "Hello"
        val data = plaintext.toByteArray()
        val inputStream = ByteArrayInputStream(data)
        val inputStreamSize = data.size
        val encryptedOutputStream = ByteArrayOutputStream()

        // 2. Encrypt stream.
        val streamKeyData = aliceEthree.encryptShared(inputStream, inputStreamSize, encryptedOutputStream)

        // 3. Upload data from `encryptedOutputStream` to a remote storage.

        /**
         * Application specific code.
         */

        // 4.1 Encrypt `streamKeyData` to a specific user (peer-to-peer).
        val bobCard = aliceEthree.findUser(bobIdentity).get()
        val p2pEncryptedStreamKeyData = aliceEthree.authEncrypt(Data(streamKeyData), bobCard)

        // 4.2 Encrypt `streamKeyData` to a group.
        val groupId = "group-chat-1"
        val bobUsersResult = aliceEthree.findUsers(arrayListOf(bobIdentity)).get()
        val aliceGroup = aliceEthree.createGroup(groupId, bobUsersResult).get()
        val groupEncryptedStreamKeyData = aliceGroup.encrypt(streamKeyData)

        // 5. Send encrypted `streamKeyData` (p2pEncryptedStreamKeyData, or groupEncryptedStreamKeyData) to destination device.

        /**
         * Application specific code.
         */

        // << encryptShared

        return Triple(p2pEncryptedStreamKeyData.value, groupEncryptedStreamKeyData, encryptedOutputStream.toByteArray())
    }

    private fun decryptShared(p2pEncryptedStreamKeyData: ByteArray, groupEncryptedStreamKeyData: ByteArray, encryptedData: ByteArray): ByteArray? {
        // decryptShared >>

        // 1. Receive `encryptedStreamKeyData` and download data from the remote storage.
        /**
         * Application specific code.
         */

        // 2. Prepare streams.
        val encryptedInputStream = ByteArrayInputStream(encryptedData)
        val decryptedOutputStream = ByteArrayOutputStream()

        // 3. Find initiator's Card.
        val aliceCard = bobEthree.findUser(aliceIdentity).get()

        // 4.1 Decrypt `encryptedStreamKeyData` received peer-to-peer.
        val p2pDecryptedStreamKeyData = bobEthree.authDecrypt(Data(p2pEncryptedStreamKeyData), aliceCard).value

        // 4.2 Decrypt `encryptedStreamKeyData` received to the group.
        val groupId = "group-chat-1"
        val bobGroup = bobEthree.loadGroup(groupId, aliceCard).get() // load correspond group
        val groupDecryptedStreamKeyData = bobGroup.decrypt(groupEncryptedStreamKeyData, aliceCard) // decrypt key

        // 5. Decrypt stream.
        val decryptedStreamKeyData = p2pDecryptedStreamKeyData ?: groupDecryptedStreamKeyData

        bobEthree.decryptShared(encryptedInputStream, decryptedOutputStream, decryptedStreamKeyData, aliceCard)

        // << decryptShared

        return decryptedOutputStream.toByteArray()
    }
}