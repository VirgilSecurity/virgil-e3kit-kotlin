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
import com.virgilsecurity.android.common.exception.EThreeException
import com.virgilsecurity.android.common.model.FindUsersResult
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.android.ethree.utils.TestUtils
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.utils.ConvertionUtils
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.*

/**
 * PeerToPeerTest
 */
@RunWith(AndroidJUnit4::class)
class PeerToPeerTest {

    private lateinit var identity: String
    private lateinit var crypto: VirgilCrypto
    private lateinit var ethree: EThree

    @Before fun setup() {
        this.identity = UUID.randomUUID().toString()
        this.crypto = VirgilCrypto()
        this.ethree = EThree(identity,
                             object : OnGetTokenCallback {
                                 override fun onGetToken(): String {
                                     return TestUtils.generateTokenString(identity)
                                 }
                             },
                             TestConfig.context)

        assertNotNull(this.ethree)
    }

    // test01 STE_3
    @Test fun encrypt_decrypt() {
        val identityTwo = UUID.randomUUID().toString()

        ethree.register().execute()

        val ethreeTwo = EThree(identityTwo,
                               object : OnGetTokenCallback {
                                   override fun onGetToken(): String {
                                       return TestUtils.generateTokenString(identityTwo)
                                   }
                               },
                               TestConfig.context)

        assertNotNull(ethreeTwo)

        ethreeTwo.register().execute()

        val card = ethree.findUser(ethreeTwo.identity).get()
        assertNotNull(card)

        val encrypted = ethree.encrypt(TEXT, card)

        val otherCard = TestUtils.publishCard()

        try {
            ethreeTwo.decrypt(encrypted, otherCard)
            fail()
        } catch (throwable: Throwable) {
            // We're good
        }

        val cardTwo = ethreeTwo.findUser(ethree.identity).get()
        val decryptedTwo = ethreeTwo.decrypt(encrypted, cardTwo)
        assertEquals(TEXT, decryptedTwo)
    }

    // test02 STE_4
    @Test(expected = IllegalArgumentException::class) fun encrypt_empty_keys() {
        ethree.register().execute()

        ethree.encrypt(TEXT, FindUsersResult())
    }

    // test03 STE_5
    @Test fun decrypted_text_not_verified() {
        ethree.register().execute()

        val plainData = TEXT.toByteArray()
        val card = ethree.findUser(ethree.identity).get()
        val encryptedData = crypto.encrypt(plainData, card.publicKey)
        val encryptedString = ConvertionUtils.toBase64String(encryptedData)

        val otherCard = TestUtils.publishCard()

        try {
            ethree.decrypt(encryptedString, otherCard)
            fail()
        } catch (throwable: Throwable) {
            // We're food
        }
    }

    // test04 STE_6
    @Test fun encrypt_decrypt_without_private_key() {
        val keyStorage = DefaultKeyStorage(TestConfig.DIRECTORY_PATH, TestConfig.KEYSTORE_NAME)
        assertFalse(keyStorage.exists(ethree.identity))
//        keyStorage.delete(ethree.identity) // FIXME check why we delete key in swift

        val card = TestUtils.publishCard()

        try {
            ethree.encrypt(TEXT, FindUsersResult(mapOf(ethree.identity to card)))
        } catch (throwable: Throwable) {
            if (throwable !is EThreeException)
                fail()
        }

        try {
            ethree.decrypt(Data(TEXT.toByteArray()).toBase64String(), card)
        } catch (throwable: Throwable) {
            if (throwable !is EThreeException)
                fail()
        }
    }

    // test05 STE_22
    @Test fun encrypt_decrypt_stream() {
        ethree.register().execute()

        val inputStream = ByteArrayInputStream(TEXT.toByteArray())
        val outputStream = ByteArrayOutputStream()

        ethree.encrypt(inputStream, outputStream)
        val encryptedData = outputStream.toByteArray()

        val inputStreamTwo = ByteArrayInputStream(encryptedData)
        val outputStreamTwo = ByteArrayOutputStream()

        ethree.decrypt(inputStreamTwo, outputStreamTwo)

        val decryptedData = outputStreamTwo.toByteArray()

        assertArrayEquals(TEXT.toByteArray(), decryptedData)
    }

    // test06 STE_40
    @Test fun decrypt_encrypted_text_with_old_card() {
        val identityTwo = UUID.randomUUID().toString()

        ethree.register().execute()

        val ethreeTwo = EThree(identityTwo,
                               object : OnGetTokenCallback {
                                   override fun onGetToken(): String {
                                       return TestUtils.generateTokenString(identityTwo)
                                   }
                               },
                               TestConfig.context)

        assertNotNull(ethreeTwo)

        ethreeTwo.register().execute()

        val card = ethree.findUser(ethreeTwo.identity).get()
        assertNotNull(card)

        val dateOne = Date()

        TestUtils.pause(1000) // 1 sec

        val encrypted = ethree.encrypt(TEXT, FindUsersResult(mapOf(card.identity to card)))

        ethree.cleanup()

        ethree.rotatePrivateKey().execute()

        val dateTwo = Date()

        val encryptedTwo =
                ethree.encrypt(TEXT + TEXT, FindUsersResult(mapOf(card.identity to card)))

        val cardTwo = ethreeTwo.findUser(ethree.identity).get()
        assertNotNull(cardTwo)

        try {
            ethreeTwo.decrypt(encrypted, cardTwo)
            fail()
        } catch (throwable: Throwable) {
            // We're good
        }

        try {
            ethreeTwo.decrypt(encrypted, cardTwo, dateTwo)
            fail()
        } catch (throwable: Throwable) {
            // We're good
        }

        val decrypted = ethreeTwo.decrypt(encrypted, cardTwo, dateOne)
        assertEquals(TEXT, decrypted)

        try {
            ethreeTwo.decrypt(encryptedTwo, cardTwo, dateOne)
            fail()
        } catch (throwable: Throwable) {
            // We're good
        }

        val decryptedTwo = ethreeTwo.decrypt(encryptedTwo, cardTwo, dateTwo)
        assertEquals(TEXT + TEXT, decryptedTwo)
    }

    // test07 STE_41
    @Test fun encrypt_decrypt_deprecated_methods() {
        val identityTwo = UUID.randomUUID().toString()

        ethree.register().execute()

        val ethreeTwo = EThree.initialize(TestConfig.context,
                                          object : OnGetTokenCallback {
                                              override fun onGetToken(): String {
                                                  return TestUtils.generateTokenString(identityTwo)
                                              }
                                          }).get()

        ethreeTwo.register().execute()

        val lookupResult = ethree.lookupPublicKeys(ethreeTwo.identity).get()
        assertTrue(lookupResult.isNotEmpty())

        val encrypted = ethree.encrypt(TEXT, lookupResult)

        val lookupResultTwo = ethreeTwo.lookupPublicKeys(ethree.identity).get()
        assertTrue(lookupResultTwo.isNotEmpty())

        val publicKey = lookupResultTwo[ethree.identity]
                        ?: error("publicKey should not be null")

        val decrypted = ethreeTwo.decrypt(encrypted, publicKey)

        assertEquals(TEXT, decrypted)
    }

    companion object {
        private const val TEXT = "Hello, my name is text. I am here to be encrypted (:"
    }
}
