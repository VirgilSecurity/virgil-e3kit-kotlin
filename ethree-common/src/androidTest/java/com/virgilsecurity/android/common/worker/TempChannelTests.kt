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

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.exception.TemporaryChannelException
import com.virgilsecurity.android.common.model.temporary.TemporaryChannel
import com.virgilsecurity.android.common.storage.local.FileTempKeysStorage
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.android.common.utils.TestConfig
import com.virgilsecurity.android.common.utils.TestUtils
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.common.extension.toData
import com.virgilsecurity.crypto.foundation.Base64
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import org.junit.Assert
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.InputStreamReader
import java.util.*
import java.util.concurrent.TimeUnit

/**
 * TempChannelTests
 */
class TempChannelTests {

    private lateinit var identity: String
    private lateinit var keyStorage: DefaultKeyStorage

    @Before fun setup() {
        this.identity = UUID.randomUUID().toString()
        this.keyStorage = DefaultKeyStorage(TestConfig.DIRECTORY_PATH, TestConfig.KEYSTORE_NAME)
    }

    private fun setupDevice(identity: String? = null,
                            keyPair: VirgilKeyPair? = null): EThree {
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

    fun encryptDecrypt100Times(channel1: TemporaryChannel, channel2: TemporaryChannel) {
        for (i in 1..100) {
            val sender: TemporaryChannel
            val receiver: TemporaryChannel

            if (Random().nextBoolean()) {
                sender = channel1
                receiver = channel2
            } else {
                sender = channel2
                receiver = channel1
            }

            val encrypted = sender.encrypt(TEXT)
            val decrypted = receiver.decrypt(encrypted)

            Assert.assertEquals(TEXT, decrypted)
        }
    }

    // test01 STE_74
    @Test fun encrypt_decrypt() {
        val ethree1 = setupDevice()

        val identity2 = UUID.randomUUID().toString()
        val chat1 = ethree1.createTemporaryChannel(identity2).get()

        val encrypted = chat1.encrypt(TEXT)

        val ethree2 = setupDevice(identity2)
        val chat2 = ethree2.loadTemporaryChannel(false, ethree1.identity).get()
        val decrypted = chat2.decrypt(encrypted)
        assertEquals(TEXT, decrypted)

        encryptDecrypt100Times(chat1, chat2)

        val newChat1 = ethree1.loadTemporaryChannel(true, identity2).get()
        val newChat2 = ethree2.getTemporaryChannel(ethree1.identity)!!

        encryptDecrypt100Times(newChat1, newChat2)
    }

    // test02 STE_75
    @Test fun create_existent_chat() {
        val ethree = setupDevice()

        ethree.createTemporaryChannel(this.identity).get()

        try {
            ethree.createTemporaryChannel(identity).get()
            fail()
        } catch (exception: TemporaryChannelException) {
            assertEquals(exception.description,
                         TemporaryChannelException.Description.CHANNEL_ALREADY_EXISTS)
        }
    }

    // test03 STE_76
    @Test fun create_with_self() {
        val ethree = setupDevice()

        try {
            ethree.createTemporaryChannel(ethree.identity).get()
            fail()
        } catch (exception: TemporaryChannelException) {
            assertEquals(exception.description,
                         TemporaryChannelException.Description.SELF_CHANNEL_IS_FORBIDDEN)
        }
    }

    // test04 STE_77
    @Test fun create_with_registered() {
        val ethree1 = setupDevice()
        val ethree2 = setupDevice()

        try {
            ethree1.createTemporaryChannel(ethree2.identity).get()
            fail()
        } catch (exception: TemporaryChannelException) {
            assertEquals(exception.description,
                         TemporaryChannelException.Description.USER_IS_REGISTERED)
        }
    }

    // test05 STE_78
    @Test fun get() {
        val ethree1 = setupDevice()

        val identity2 = UUID.randomUUID().toString()
        assertNull(ethree1.getTemporaryChannel(identity2))

        ethree1.createTemporaryChannel(identity2).get()
        assertNotNull(ethree1.getTemporaryChannel(identity2))

        val ethree2 = setupDevice(identity2)
        assertNull(ethree2.getTemporaryChannel(ethree1.identity))

        ethree2.loadTemporaryChannel(false, ethree1.identity).get()
        assertNotNull(ethree2.getTemporaryChannel(ethree1.identity))

        ethree1.deleteTemporaryChannel(identity2).execute()
        assertNull(ethree1.getTemporaryChannel(identity2))
    }

    // test06 STE_79
    @Test fun load_with_self() {
        val ethree = setupDevice()

        try {
            ethree.loadTemporaryChannel(true, identity).get()
        } catch (exception: TemporaryChannelException) {
            assertEquals(exception.description,
                         TemporaryChannelException.Description.CHANNEL_NOT_FOUND)
        }
    }

    // test07 STE_80
    @Test fun load_unexistent_chat() {
        val ethree = setupDevice()

        try {
            ethree.loadTemporaryChannel(true, identity).get()
        } catch (exception: TemporaryChannelException) {
            assertEquals(exception.description,
                         TemporaryChannelException.Description.CHANNEL_NOT_FOUND)
        }
    }

    // test08 STE_81
    @Test fun load_after_delete() {
        val ethree1 = setupDevice()

        val identity2 = UUID.randomUUID().toString()

        ethree1.createTemporaryChannel(identity2).get()
        ethree1.deleteTemporaryChannel(identity2).execute()

        try {
            ethree1.loadTemporaryChannel(true, identity2).get()
        } catch (exception: TemporaryChannelException) {
            assertEquals(exception.description,
                         TemporaryChannelException.Description.CHANNEL_NOT_FOUND)
        }

        val ethree2 = setupDevice(identity2)

        try {
            ethree2.loadTemporaryChannel(false, ethree1.identity).get()
        } catch (exception: TemporaryChannelException) {
            assertEquals(exception.description,
                         TemporaryChannelException.Description.CHANNEL_NOT_FOUND)
        }
    }

    // test09 STE_82
    @Test fun delete_unexistent_chat() {
        val ethree = setupDevice()

        try {
            ethree.deleteTemporaryChannel(this.identity).execute()
        } catch (exception: Exception) {
            fail()
        }
    }

    // test10 STE_83
    @Test fun compatibility() {
        val compatDataStream = this.javaClass
                .classLoader
                ?.getResourceAsStream("compat/compat_data.json")
        val compatJson = JsonParser.parseReader(InputStreamReader(compatDataStream)) as JsonObject
        val tempChannelCompatJson = compatJson.getAsJsonObject("TemporaryChannel")

        val identity = tempChannelCompatJson.get("Identity").asString

        val privateKeyCompat = TestConfig.virgilCrypto.importPrivateKey(
            Base64.decode(compatJson.get("ApiPrivateKey").asString.toByteArray())
        )
        val jwtGenerator = JwtGenerator(
            compatJson.get("AppId").asString,
            privateKeyCompat.privateKey,
            compatJson.get("ApiKeyId").asString,
            TimeSpan.fromTime(600, TimeUnit.SECONDS),
            VirgilAccessTokenSigner(TestConfig.virgilCrypto)
        )

        val tokenCallback = object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return jwtGenerator.generateToken(identity).stringRepresentation()
            }
        }

        val ethree = EThree(identity, tokenCallback, TestConfig.context)
        var ethreeNew: EThree? = null

        if (!ethree.hasLocalPrivateKey()) {
            val privateKeyData = Base64.decode(
                tempChannelCompatJson.get("PrivateKey").asString.toByteArray()
            ).toData()
            val localKeyStorage = LocalKeyStorage(identity, keyStorage, VirgilCrypto())
            localKeyStorage.store(privateKeyData)

            // Should call privateKeyChanged()
            ethreeNew = EThree(identity, tokenCallback, TestConfig.context)
        }

        val initiator = tempChannelCompatJson.get("Initiator").asString
        val ethreeNew2 = ethreeNew ?: ethree
        val chat = ethreeNew2.loadTemporaryChannel(false, initiator).get()

        val originText = tempChannelCompatJson.get("OriginText").asString
        val encryptedText = tempChannelCompatJson.get("EncryptedText").asString
        val decrypted = chat.decrypt(encryptedText)
        assertEquals(originText, decrypted)
    }

    // test11 STE_84
    @Test fun cleanup_should_reset_local_storage() {
        val keyPair = TestConfig.virgilCrypto.generateKeyPair()
        val ethree = setupDevice(keyPair = keyPair)

        val localTempStorage = FileTempKeysStorage(ethree.identity,
                                                   TestConfig.virgilCrypto,
                                                   keyPair,
                                                   TestConfig.context.filesDir.absolutePath)
        assertNull(localTempStorage.retrieve(identity))

        ethree.createTemporaryChannel(identity).get()
        assertNotNull(localTempStorage.retrieve(identity))

        ethree.cleanup()

        assertNull(localTempStorage.retrieve(identity))
    }

    companion object {
        private const val TEXT = "Hello, my name is text. I am here to be encrypted (:"
    }
}
