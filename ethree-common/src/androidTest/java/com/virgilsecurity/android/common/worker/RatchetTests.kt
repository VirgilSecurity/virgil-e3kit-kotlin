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
import com.virgilsecurity.android.common.exception.EThreeRatchetException
import com.virgilsecurity.android.common.model.ratchet.RatchetChannel
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.android.common.util.Defaults
import com.virgilsecurity.android.common.utils.TestConfig
import com.virgilsecurity.android.common.utils.TestUtils
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.ratchet.securechat.SecureChat
import com.virgilsecurity.ratchet.securechat.SecureChatContext
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import org.junit.Assert.*
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import java.lang.Exception
import java.util.*

/**
 * RatchetTests
 */
class RatchetTests {

    private lateinit var crypto: VirgilCrypto
    private lateinit var keyStorage: DefaultKeyStorage

    @Before fun setup() {
        this.crypto = VirgilCrypto()
        this.keyStorage = DefaultKeyStorage(TestConfig.DIRECTORY_PATH, TestConfig.KEYSTORE_NAME)
    }

    private fun setupDevice(enableRatchet: Boolean = true,
                            keyRotationInterval: TimeSpan = Defaults.keyRotationInterval): Pair<EThree, Card> {
        val identityNew = UUID.randomUUID().toString()

        val tokenCallback = object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return TestUtils.generateTokenString(identityNew)
            }
        }

        val ethree = EThree(identityNew,
                            tokenCallback,
                            TestConfig.context,
                            enableRatchet = enableRatchet,
                            keyRotationInterval = keyRotationInterval)

        ethree.register().execute()

        val card = ethree.findUser(identityNew).get()

        return Pair(ethree, card)
    }

    fun encryptDecrypt100Times(channel1: RatchetChannel, channel2: RatchetChannel) {
        for (i in 1..100) {
            val sender: RatchetChannel
            val receiver: RatchetChannel

            if (Random().nextBoolean()) {
                sender = channel1
                receiver = channel2
            } else {
                sender = channel2
                receiver = channel1
            }

            val encrypted = sender.encrypt(TEXT)
            val decrypted = receiver.decrypt(encrypted)

            assertEquals(TEXT, decrypted)
        }
    }

    // test001 STE_51
    @Test fun encrypt_decrypt_should_succeed() {
        val (ethree1, card1) = setupDevice()
        val (ethree2, card2) = setupDevice()

        val chat1 = ethree1.createRatchetChannel(card2).get()
        val chat2 = ethree2.joinRatchetChannel(card1).get()

        encryptDecrypt100Times(chat1, chat2)
    }

    // test002 STE_52
    @Test fun create_with_self_should_throw_error() {
        val (ethree, card) = setupDevice()

        try {
            ethree.createRatchetChannel(card).get()
            fail()
        } catch (exception: EThreeRatchetException) {
            if (exception.description != EThreeRatchetException.Description.SELF_CHANNEL_IS_FORBIDDEN)
                fail()
        }
    }

    // test003 STE_53
    @Test fun create_with_disabled_ratchet_user_should_throw_error() {
        val (_, card1) = setupDevice(enableRatchet = false)
        val (ethree2, _) = setupDevice()

        try {
            ethree2.createRatchetChannel(card1).get()
            fail()
        } catch (exception: EThreeRatchetException) {
            if (exception.description != EThreeRatchetException.Description.USER_IS_NOT_USING_RATCHET)
                fail()
        }
    }

    // test004 STE_54
    @Test fun create_which_exists_should_throw_error() {
        val (ethree1, _) = setupDevice()
        val (_, card2) = setupDevice()

        ethree1.createRatchetChannel(card2).get()

        try {
            ethree1.createRatchetChannel(card2).get()
            fail()
        } catch (exception: EThreeRatchetException) {
            if (exception.description != EThreeRatchetException.Description.CHANNEL_ALREADY_EXISTS)
                fail()
        }

        val secureChat1 = getSecureChat(ethree1)
        secureChat1.deleteSession(card2.identity)

        try {
            ethree1.createRatchetChannel(card2).get()
            fail()
        } catch (exception: EThreeRatchetException) {
            if (exception.description != EThreeRatchetException.Description.CHANNEL_ALREADY_EXISTS)
                fail()
        }
    }

    // test005 STE_55
    @Test fun create_after_delete_should_succeed() {
        val (ethree1, card1) = setupDevice()
        val (ethree2, card2) = setupDevice()

        ethree1.createRatchetChannel(card2).get()
        ethree2.joinRatchetChannel(card1).get()

        ethree1.deleteRatchetChannel(card2).execute()
        ethree2.deleteRatchetChannel(card1).execute()

        val newChat1 = ethree1.createRatchetChannel(card2).get()
        val newChat2 = ethree2.joinRatchetChannel(card1).get()

        encryptDecrypt100Times(newChat1, newChat2)
    }

    // test006 STE_56
    @Test fun join_with_self_should_throw_error() {
        val (ethree, card) = setupDevice()

        try {
            ethree.joinRatchetChannel(card).get()
            fail()
        } catch (exception: EThreeRatchetException) {
            if (exception.description != EThreeRatchetException.Description.SELF_CHANNEL_IS_FORBIDDEN)
                fail()
        }
    }

    // test007 STE_57
    @Test fun join_which_exists_should_throw_error() {
        val (ethree1, card1) = setupDevice()
        val (ethree2, card2) = setupDevice()

        ethree1.createRatchetChannel(card2).get()
        ethree2.joinRatchetChannel(card1).get()

        try {
            ethree2.joinRatchetChannel(card1).get()
            fail()
        } catch (exception: EThreeRatchetException) {
            if (exception.description != EThreeRatchetException.Description.CHANNEL_ALREADY_EXISTS)
                fail()
        }
    }

    // test 008 STE_58
    @Test fun join_without_invitation_should_throw_error() {
        val (_, card1) = setupDevice()
        val (ethree2, _) = setupDevice()

        try {
            ethree2.joinRatchetChannel(card1).get()
            fail()
        } catch (exception: EThreeRatchetException) {
            if (exception.description != EThreeRatchetException.Description.NO_INVITE)
                fail()
        }
    }

    // test 009 STE_59
    @Test fun join_after_delete_should_throw_error() {
        val (ethree1, card1) = setupDevice()
        val (ethree2, card2) = setupDevice()

        ethree1.createRatchetChannel(card2).get()
        ethree1.deleteRatchetChannel(card2).execute()

        try {
            ethree2.joinRatchetChannel(card1).get()
            fail()
        } catch (exception: EThreeRatchetException) {
            if (exception.description != EThreeRatchetException.Description.NO_INVITE)
                fail()
        }
    }

    // test 010 STE_60
    @Test fun join_after_rotate_should_throw_error() {
        val (ethree1, card1) = setupDevice()
        val (ethree2, card2) = setupDevice()

        ethree1.createRatchetChannel(card2).get()
        ethree1.cleanup()
        ethree1.rotatePrivateKey().execute()

        try {
            ethree2.joinRatchetChannel(card1).get()
        } catch (exception: EThreeRatchetException) {
            if (exception.description != EThreeRatchetException.Description.NO_INVITE)
                fail()
        }
    }

    // test 011 STE_61
    @Test fun join_after_unregister_should_succeed() {
        val (ethree1, card1) = setupDevice()
        val (ethree2, card2) = setupDevice()

        val chat1 = ethree1.createRatchetChannel(card2).get()

        val encrypted = chat1.encrypt(TEXT)

        ethree1.unregister().execute()

        val chat2 = ethree2.joinRatchetChannel(card1).get()
        val decrypted = chat2.decrypt(encrypted)

        assertEquals(TEXT, decrypted)
    }

    // test 012 STE_62
    @Test fun getRatchetChannel_should_succeed() {
        val (ethree1, card1) = setupDevice()
        val (ethree2, card2) = setupDevice()

        assertNull(ethree1.getRatchetChannel(card2))
        assertNull(ethree2.getRatchetChannel(card1))

        ethree1.createRatchetChannel(card2).get()
        assertNotNull(ethree1.getRatchetChannel(card2))

        ethree2.createRatchetChannel(card1).get()
        assertNotNull(ethree2.getRatchetChannel(card1))

        ethree1.deleteRatchetChannel(card2).execute()
        assertNull(ethree1.getRatchetChannel(card2))

        ethree2.deleteRatchetChannel(card1).execute()
        assertNull(ethree2.getRatchetChannel(card1))
    }

    // test 013 STE_63
    @Test fun delete_nonexistent_chat_should_succeed() {
        val (ethree1, _) = setupDevice()
        val (_, card2) = setupDevice()

        try {
            ethree1.deleteRatchetChannel(card2).execute()
        } catch (exception: Exception) {
            fail()
        }
    }

    // test 014 STE_64
    @Test fun enableRatchet() {
        val (ethree1, _) = setupDevice(enableRatchet = false)
        val (_, card2) = setupDevice()

        try {
            ethree1.createRatchetChannel(card2).get()
        } catch (exception: EThreeRatchetException) {
            if (exception.description != EThreeRatchetException.Description.RATCHET_IS_DISABLED)
                fail()
        }

        try {
            ethree1.joinRatchetChannel(card2).get()
        } catch (exception: EThreeRatchetException) {
            if (exception.description != EThreeRatchetException.Description.RATCHET_IS_DISABLED)
                fail()
        }

        try {
            ethree1.getRatchetChannel(card2)
        } catch (exception: EThreeRatchetException) {
            if (exception.description != EThreeRatchetException.Description.RATCHET_IS_DISABLED)
                fail()
        }

        try {
            ethree1.deleteRatchetChannel(card2).execute()
        } catch (exception: EThreeRatchetException) {
            if (exception.description != EThreeRatchetException.Description.RATCHET_IS_DISABLED)
                fail()
        }
    }

    // test 015 STE_65
    @Test fun auto_keys_rotation() {
        val (ethree1, card1) = setupDevice()
        val (ethree2, card2) = setupDevice()

        ethree2.createRatchetChannel(card1).get()

        val secureChat1 = getSecureChat(ethree1)

        secureChat1.oneTimeKeysStorage.startInteraction()
        val keys1 = secureChat1.oneTimeKeysStorage.retrieveAllKeys()
        secureChat1.oneTimeKeysStorage.stopInteraction()

        ethree1.joinRatchetChannel(card2).get()

        TestUtils.pause(5)

        secureChat1.oneTimeKeysStorage.startInteraction()
        val keys2 = secureChat1.oneTimeKeysStorage.retrieveAllKeys()
        secureChat1.oneTimeKeysStorage.stopInteraction()

        var keysRotated = false
        for (key1 in keys1) {
            if (keys2.find { it.identifier.contentEquals(key1.identifier) } == null) {
                keysRotated = true
                break
            }
        }

        assertTrue(keysRotated)
    }

    // test 016 STE_66
    @Test fun multiple_encrypt_decrypt_should_succeed() {
        val (ethree1, card1) = setupDevice()
        val (ethree2, card2) = setupDevice()

        val chat1 = ethree1.createRatchetChannel(card2).get()

        var messages = mutableListOf<String>()
        for (i in 0 until 100) {
            messages.add(UUID.randomUUID().toString())
        }

        val encrypted = chat1.encryptMultiple(RatchetChannel.MultipleString(messages))

        val chat2 = ethree2.joinRatchetChannel(card1).get()

        val decrypted = chat2.decryptMultiple(encrypted)

        for (i in 0 until messages.size) {
            assertEquals(messages[i],
                         decrypted.multipleText.toList()[i]) // TODO do we need Iterable really here?
        }
    }

    // test 017 STE_67
    @Test fun decrypt_messages_after_rotate_identity_key_should_succeed() {
        val (ethree1, _) = setupDevice()
        val (ethree2, card2) = setupDevice()

        ethree1.createRatchetChannel(card2).get()

        ethree1.cleanup()
        ethree1.rotatePrivateKey().execute()

        val newCard1 = ethree2.findUser(ethree1.identity, forceReload = true).get()

        val chat1 = ethree1.createRatchetChannel(card2).get()
        val chat2 = ethree2.joinRatchetChannel(newCard1).get()

        encryptDecrypt100Times(chat1, chat2)
    }

    // test 018 STE_68
    @Test fun chats_with_different_names() {
        val (ethree1, card1) = setupDevice()
        val (ethree2, card2) = setupDevice()

        val name1 = UUID.randomUUID().toString()
        val chat11 = ethree1.createRatchetChannel(card2, name1).get()

        val name2 = UUID.randomUUID().toString()
        val chat22 = ethree2.createRatchetChannel(card1, name2).get()

        val chat12 = ethree1.joinRatchetChannel(card2, name2).get()
        val chat21 = ethree2.joinRatchetChannel(card1, name1).get()

        encryptDecrypt100Times(chat11, chat21)
        encryptDecrypt100Times(chat12, chat22)
    }

    private fun getSecureChat(ethree: EThree): SecureChat {
        val localKeyStorage = LocalKeyStorage(ethree.identity, keyStorage, crypto)

        val card = ethree.findCachedUser(ethree.identity).get()!!

        val keyPair = localKeyStorage.retrieveKeyPair()
        val cachingTokenProvider = CachingJwtProvider(
            CachingJwtProvider.RenewJwtCallback { TestUtils.generateToken(ethree.identity) }
        )
        val context = SecureChatContext(card,
                                        keyPair,
                                        cachingTokenProvider,
                                        TestConfig.DIRECTORY_PATH)

        return SecureChat(context)
    }

    companion object {
        private const val TEXT = "Hello, my name is text. I am here to be encrypted (:"
    }
}
