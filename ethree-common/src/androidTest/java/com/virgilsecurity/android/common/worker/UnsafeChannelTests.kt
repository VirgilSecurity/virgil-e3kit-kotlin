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

package com.virgilsecurity.android.common.worker

import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.exception.UnsafeChannelException
import com.virgilsecurity.android.common.model.unsafe.UnsafeChannel
import com.virgilsecurity.android.common.storage.local.FileUnsafeKeysStorage
import com.virgilsecurity.android.common.utils.TestConfig
import com.virgilsecurity.android.common.utils.TestUtils
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import org.junit.Assert
import org.junit.Assert.*
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import java.util.*

/**
 * UnsafeChannelTests
 */
class UnsafeChannelTests {

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

    fun encryptDecrypt100Times(channel1: UnsafeChannel, channel2: UnsafeChannel) {
        for (i in 1..100) {
            val sender: UnsafeChannel
            val receiver: UnsafeChannel

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
        val chat1 = ethree1.createUnsafeChannel(identity2).get()

        val encrypted = chat1.encrypt(TEXT)

        val ethree2 = setupDevice(identity2)
        val chat2 = ethree2.loadUnsafeChannel(false, ethree1.identity).get()
        val decrypted = chat2.decrypt(encrypted)
        assertEquals(TEXT, decrypted)

        encryptDecrypt100Times(chat1, chat2)

        val newChat1 = ethree1.loadUnsafeChannel(true, identity2).get()
        val newChat2 = ethree2.getUnsafeChannel(ethree1.identity)!!

        encryptDecrypt100Times(newChat1, newChat2)
    }

    // test02 STE_75
    @Test fun create_existent_chat() {
        val ethree = setupDevice()

        ethree.createUnsafeChannel(this.identity).get()

        try {
            ethree.createUnsafeChannel(identity).get()
            fail()
        } catch (exception: UnsafeChannelException) {
            assertEquals(exception.description,
                         UnsafeChannelException.Description.CHANNEL_ALREADY_EXISTS)
        }
    }

    // test03 STE_76
    @Test fun create_with_self() {
        val ethree = setupDevice()

        try {
            ethree.createUnsafeChannel(ethree.identity).get()
            fail()
        } catch (exception: UnsafeChannelException) {
            assertEquals(exception.description,
                         UnsafeChannelException.Description.SELF_CHANNEL_IS_FORBIDDEN)
        }
    }

    // test04 STE_77
    @Test fun create_with_registered() {
        val ethree1 = setupDevice()
        val ethree2 = setupDevice()

        try {
            ethree1.createUnsafeChannel(ethree2.identity).get()
            fail()
        } catch (exception: UnsafeChannelException) {
            assertEquals(exception.description,
                         UnsafeChannelException.Description.USER_IS_REGISTERED)
        }
    }

    // test05 STE_78
    @Test fun get() {
        val ethree1 = setupDevice()

        val identity2 = UUID.randomUUID().toString()
        assertNull(ethree1.getUnsafeChannel(identity2))

        ethree1.createUnsafeChannel(identity2).get()
        assertNotNull(ethree1.getUnsafeChannel(identity2))

        val ethree2 = setupDevice(identity2)
        assertNull(ethree2.getUnsafeChannel(ethree1.identity))

        ethree2.loadUnsafeChannel(false, ethree1.identity).get()
        assertNotNull(ethree2.getUnsafeChannel(ethree1.identity))

        ethree1.deleteUnsafeChannel(identity2).execute()
        assertNull(ethree1.getUnsafeChannel(identity2))
    }

    // test06 STE_79
    @Test fun load_with_self() {
        val ethree = setupDevice()

        try {
          ethree.loadUnsafeChannel(true, identity).get()
        } catch (exception: UnsafeChannelException) {
            assertEquals(exception.description,
                         UnsafeChannelException.Description.CHANNEL_NOT_FOUND)
        }
    }

    // test07 STE_80
    @Test fun load_unexistent_chat() {
        val ethree = setupDevice()

        try {
            ethree.loadUnsafeChannel(true, identity).get()
        } catch (exception: UnsafeChannelException) {
            assertEquals(exception.description,
                         UnsafeChannelException.Description.CHANNEL_NOT_FOUND)
        }
    }

    // test08 STE_81
    @Test fun load_after_delete() {
        val ethree1 = setupDevice()

        val identity2 = UUID.randomUUID().toString()

        ethree1.createUnsafeChannel(identity2).get()
        ethree1.deleteUnsafeChannel(identity2).execute()

        try {
            ethree1.loadUnsafeChannel(true, identity2).get()
        } catch (exception: UnsafeChannelException) {
            assertEquals(exception.description,
                         UnsafeChannelException.Description.CHANNEL_NOT_FOUND)
        }

        val ethree2 = setupDevice(identity2)

        try {
            ethree2.loadUnsafeChannel(false, ethree1.identity).get()
        } catch (exception: UnsafeChannelException) {
            assertEquals(exception.description,
                         UnsafeChannelException.Description.CHANNEL_NOT_FOUND)
        }
    }

    // test09 STE_82
    @Test fun delete_unexistent_chat() {
        val ethree = setupDevice()

        try {
            ethree.deleteUnsafeChannel(this.identity).execute()
        } catch (exception: Exception) {
            fail()
        }
    }

    // test10 STE_83
    @Ignore @Test fun compatibility() {
        // FIXME implement
    }

    // test11 STE_84
    @Test fun cleanup_should_reset_local_storage() {
        val keyPair = TestConfig.virgilCrypto.generateKeyPair()
        val ethree = setupDevice(keyPair = keyPair)

        val localUnsafeStorage = FileUnsafeKeysStorage(ethree.identity,
                                                       TestConfig.virgilCrypto,
                                                       keyPair,
                                                       TestConfig.context.filesDir.absolutePath)
        assertNull(localUnsafeStorage.retrieve(identity))

        ethree.createUnsafeChannel(identity).get()
        assertNotNull(localUnsafeStorage.retrieve(identity))

        ethree.cleanup()

        assertNull(localUnsafeStorage.retrieve(identity))
    }

    companion object {
        private const val TEXT = "Hello, my name is text. I am here to be encrypted (:"
    }
}
