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

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.exception.EThreeException
import com.virgilsecurity.android.common.model.FindUsersResult
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.android.common.utils.TestConfig
import com.virgilsecurity.android.common.utils.TestUtils
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.common.extension.toData
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.KeyPairType
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.utils.ConvertionUtils
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStreamReader
import java.util.*
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/**
 * PeerToPeerTest
 */
@RunWith(AndroidJUnit4::class)
class PeerToPeerTest {

    private lateinit var identity: String
    private lateinit var identity2: String
    private lateinit var crypto: VirgilCrypto
    private lateinit var ethree: EThree
    private lateinit var ethree2: EThree

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

        this.identity2 = UUID.randomUUID().toString()
        this.ethree2 = EThree(identity2,
                object : OnGetTokenCallback {
                    override fun onGetToken(): String {
                        return TestUtils.generateTokenString(identity2)
                    }
                },
                TestConfig.context)
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
                               TestConfig.context,
                               enableRatchet = false,
                               keyRotationInterval = TimeSpan.fromTime(3600, TimeUnit.SECONDS))

        assertNotNull(ethreeTwo)

        ethreeTwo.register().execute()

        val card = ethree.findUser(ethreeTwo.identity).get()
        assertNotNull(card)

        val encrypted = ethree.authEncrypt(TEXT, card)

        val otherCard = TestUtils.publishCard()

        try {
            ethreeTwo.authDecrypt(encrypted, otherCard)
            fail()
        } catch (throwable: Throwable) {
            // We're good
        }

        val cardTwo = ethreeTwo.findUser(ethree.identity).get()
        val decryptedTwo = ethreeTwo.authDecrypt(encrypted, cardTwo)
        assertEquals(TEXT, decryptedTwo)
    }

    @Test fun encrypt_decrypt_many_cards() {
        ethree.register().execute()

        val totalIdentities = 100
        val identities = mutableListOf<String>()
        val ethrees = mutableMapOf<String, EThree>() // identity, EThree
        val cards = mutableMapOf<String, Card>() // identity, Card
        for (i in 1..totalIdentities) {
            val identityTwo = UUID.randomUUID().toString()
            identities.add(identityTwo)

            val ethreeTwo = EThree(identityTwo,
                    object : OnGetTokenCallback {
                        override fun onGetToken(): String {
                            return TestUtils.generateTokenString(identityTwo)
                        }
                    },
                    TestConfig.context,
                    enableRatchet = false,
                    keyRotationInterval = TimeSpan.fromTime(3600, TimeUnit.SECONDS))
            ethreeTwo.register().execute()
            ethrees[identityTwo] = ethreeTwo
        }

        // Encrypt many messages
        val encryptedMessages = mutableListOf<Pair<String, String>>() // from identity, message
        for (i in 1..1000) {
            val index = Random.nextInt(0, totalIdentities)
            val identityTwo = identities[index]
            val ethreeTwo = ethrees[identityTwo]!!

            val message = TEXT
            val encryptedMessage = ethreeTwo.authEncrypt(message, ethreeTwo.findUser(identity).get())
            encryptedMessages.add(Pair(identityTwo, encryptedMessage))
        }

        // Decrypt many messages at the same time
        val decryptedMessages = ConcurrentLinkedQueue<String>()
        runBlocking {
            encryptedMessages.forEach { pair ->
                launch(Dispatchers.IO) {
                    decryptedMessages.add(ethree.authDecrypt(pair.second, ethree.findUser(pair.first).get()))
                }
            }
        }

        Log.d(TAG, "${decryptedMessages.size} of ${encryptedMessages.size} messages decrypted")
        decryptedMessages.forEach {
            assertEquals(TEXT, it)
        }
    }

    @Test fun encrypt_decrypt_empty_text() {
        ethree.register().execute()

        val emptyText = ""
        val encryptedText = ethree.authEncrypt(emptyText)
        val decryptedText = ethree.authDecrypt(encryptedText)

        assertEquals(emptyText, decryptedText)
    }

    @Test fun encrypt_decrypt_empty_data() {
        ethree.register().execute()

        val identityTwo = UUID.randomUUID().toString()
        val ethreeTwo = EThree(identityTwo,
                object : OnGetTokenCallback {
                    override fun onGetToken(): String {
                        return TestUtils.generateTokenString(identityTwo)
                    }
                },
                TestConfig.context,
                enableRatchet = false,
                keyRotationInterval = TimeSpan.fromTime(3600, TimeUnit.SECONDS))
        ethreeTwo.register().execute()
        val card = ethree.findUser(ethreeTwo.identity).get()

        val emptyData = byteArrayOf()
        val encryptedData = ethree.authEncrypt(Data(emptyData), card)

        val cardTwo = ethreeTwo.findUser(ethree.identity).get()
        val decryptedData = ethreeTwo.authDecrypt(encryptedData, cardTwo)

        assertArrayEquals(emptyData, decryptedData.value)
    }

    @Test fun decrypt_empty_text() {
        ethree.register().execute()

        val emptyText = ""
        try {
            ethree.authDecrypt(emptyText)
            fail("Decryption should fail")
        }
        catch (e: CryptoException) {
            // Expected
        }
    }

    @Test fun ste3_stream() {
        val identityTwo = UUID.randomUUID().toString()
        val randombytes = ByteArray(1000000)
        Random.nextBytes(randombytes)

        ethree.register().execute()

        val ethreeTwo = EThree(identityTwo,
                object : OnGetTokenCallback {
                    override fun onGetToken(): String {
                        return TestUtils.generateTokenString(identityTwo)
                    }
                },
                TestConfig.context,
                enableRatchet = false,
                keyRotationInterval = TimeSpan.fromTime(3600, TimeUnit.SECONDS))

        assertNotNull(ethreeTwo)

        ethreeTwo.register().execute()

        val card = ethree.findUser(ethreeTwo.identity).get()
        assertNotNull(card)

        val encrypted = ethree.authEncrypt(Data(randombytes), card)

        val otherCard = TestUtils.publishCard()
        ByteArrayInputStream(randombytes).read()

        try {
            val decryptedStream = ByteArrayOutputStream()
            ethreeTwo.authDecrypt(ByteArrayInputStream(encrypted.value), decryptedStream, otherCard)
            fail()
        } catch (throwable: Throwable) {
            // We're good
        }

        val cardTwo = ethreeTwo.findUser(ethree.identity).get()
        val decryptedStream = ByteArrayOutputStream()
        ethreeTwo.authDecrypt(ByteArrayInputStream(encrypted.value), decryptedStream, cardTwo)
        assertArrayEquals(randombytes, decryptedStream.toByteArray())
    }

    // test02 STE_4
    @Test(expected = IllegalArgumentException::class) fun encrypt_empty_keys() {
        ethree.register().execute()

        ethree.authEncrypt(TEXT, FindUsersResult())
    }

    // test03 STE_5
    @Test fun decrypted_text_not_verified() {
        ethree.register().execute()

        val plainData = TEXT.toByteArray()
        val card = ethree.findUser(ethree.identity).get()
        val encryptedData = crypto.encrypt(plainData, card.publicKey, false)
        val encryptedString = ConvertionUtils.toBase64String(encryptedData)

        val otherCard = TestUtils.publishCard()

        try {
            ethree.authDecrypt(encryptedString, otherCard)
            fail()
        } catch (throwable: Throwable) {
            // We're food
        }
    }

    // test04 STE_6
    @Test fun encrypt_decrypt_without_private_key() {
        val keyStorage = DefaultKeyStorage(TestConfig.DIRECTORY_PATH, TestConfig.KEYSTORE_NAME)
        assertFalse(keyStorage.exists(ethree.identity))

        val card = TestUtils.publishCard()

        try {
            ethree.authEncrypt(TEXT, FindUsersResult(mapOf(ethree.identity to card)))
        } catch (exception: EThreeException) {
            assertTrue(exception.description == EThreeException.Description.MISSING_PRIVATE_KEY)
        }

        try {
            ethree.authDecrypt(TEXT.toData().toBase64String(), card)
        } catch (exception: EThreeException) {
            assertTrue(exception.description == EThreeException.Description.MISSING_PRIVATE_KEY)
        }
    }

    // test05 STE_22
    @Test fun encrypt_decrypt_stream() {
        ethree.register().execute()

        val data = TEXT.toByteArray()
        val inputStream = ByteArrayInputStream(data)
        val outputStream = ByteArrayOutputStream()

        ethree.authEncrypt(inputStream, inputStream.available(), outputStream)
        val encryptedData = outputStream.toByteArray()

        val inputStreamTwo = ByteArrayInputStream(encryptedData)
        val outputStreamTwo = ByteArrayOutputStream()

        ethree.authDecrypt(inputStreamTwo, outputStreamTwo)

        val decryptedData = outputStreamTwo.toByteArray()

        assertArrayEquals(TEXT.toByteArray(), decryptedData)
    }

    @Test fun encrypt_decrypt_empty_stream() {
        ethree.register().execute()

        val data = byteArrayOf()
        val inputStream = ByteArrayInputStream(data)
        val outputStream = ByteArrayOutputStream()

        ethree.authEncrypt(inputStream, inputStream.available(), outputStream)
        val encryptedData = outputStream.toByteArray()

        val inputStreamTwo = ByteArrayInputStream(encryptedData)
        val outputStreamTwo = ByteArrayOutputStream()

        ethree.authDecrypt(inputStreamTwo, outputStreamTwo)

        val decryptedData = outputStreamTwo.toByteArray()

        assertArrayEquals(data, decryptedData)
    }

    @Test fun encrypt_decrypt_stream_compatibility() {
        val dataJson = JsonParser.parseReader(InputStreamReader(
                this.javaClass.classLoader.getResourceAsStream("testProperties/compatibility_data.json"))) as JsonObject

        val keyStorage = DefaultKeyStorage(TestConfig.context.filesDir.absolutePath, "virgil.keystore")
        val localKeyStorage = LocalKeyStorage(identity, keyStorage, crypto)
        localKeyStorage.store(Data(ConvertionUtils.base64ToBytes(dataJson["authEncryptFile"].asJsonObject["privateKey"].asString)))

        val encryptedData = ConvertionUtils.base64ToBytes(dataJson["authEncryptFile"].asJsonObject["data"].asString)
        val encryptedStream = ByteArrayInputStream(encryptedData)
        val decryptedStream = ByteArrayOutputStream()

        ethree.authDecrypt(encryptedStream, decryptedStream)
        val decryptedData = decryptedStream.toByteArray()

        val originString = "All work and no pay makes Alexey a dull boy\n".repeat(128)
        assertArrayEquals(originString.toByteArray(), decryptedData)
    }

    @Test fun encrypt_decrypt_shared_stream_compatibility() {
        val dataJson = JsonParser.parseReader(InputStreamReader(
                this.javaClass.classLoader.getResourceAsStream("testProperties/compatibility_data.json"))) as JsonObject
        val originString = dataJson["encryptSharedFile"].asJsonObject["originData"].asString
        val encryptedData = ConvertionUtils.base64ToBytes(dataJson["encryptSharedFile"].asJsonObject["encryptedData"].asString)
        val fileKeyData = ConvertionUtils.base64ToBytes(dataJson["encryptSharedFile"].asJsonObject["fileKey"].asString)
        val senderPublicKeyData = ConvertionUtils.base64ToBytes(dataJson["encryptSharedFile"].asJsonObject["senderPublicKey"].asString)
        val senderPublicKey = this.crypto.importPublicKey(senderPublicKeyData)

        val encryptedStream = ByteArrayInputStream(encryptedData)
        val decryptedStream = ByteArrayOutputStream()

        ethree.decryptShared(encryptedStream, decryptedStream, fileKeyData,  senderPublicKey)
        val decryptedString = decryptedStream.toString()

        assertEquals(originString, decryptedString)
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
                               TestConfig.context,
                               keyPairType = KeyPairType.ED25519,
                               enableRatchet = false,
                               keyRotationInterval = TimeSpan.fromTime(3600, TimeUnit.SECONDS))

        assertNotNull(ethreeTwo)

        ethreeTwo.register().execute()

        val card = ethree.findUser(ethreeTwo.identity).get()
        assertNotNull(card)

        val dateOne = Date()

        Thread.sleep(1000) // 1 sec

        val encrypted = ethree.authEncrypt(TEXT, FindUsersResult(mapOf(card.identity to card)))

        ethree.cleanup()

        ethree.rotatePrivateKey().execute()

        val dateTwo = Date()

        val encryptedTwo =
                ethree.authEncrypt(TEXT + TEXT, FindUsersResult(mapOf(card.identity to card)))

        val cardTwo = ethreeTwo.findUser(ethree.identity).get()
        assertNotNull(cardTwo)

        try {
            ethreeTwo.authDecrypt(encrypted, cardTwo)
            fail()
        } catch (throwable: Throwable) {
            assertTrue(throwable is VerificationException)
        }

        try {
            ethreeTwo.authDecrypt(encrypted, cardTwo, dateTwo)
            fail()
        } catch (throwable: Throwable) {
            assertTrue(throwable is VerificationException)
        }

        val decrypted = ethreeTwo.authDecrypt(encrypted, cardTwo, dateOne)
        assertEquals(TEXT, decrypted)

        try {
            ethreeTwo.authDecrypt(encryptedTwo, cardTwo, dateOne)
            fail()
        } catch (throwable: Throwable) {
            assertTrue(throwable is VerificationException)
        }

        val decryptedTwo = ethreeTwo.authDecrypt(encryptedTwo, cardTwo, dateTwo)
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

    // test08 STE_71
    @Test fun encrypt_decrypt_deprecated_methods_should_succeed() {
        val identityTwo = UUID.randomUUID().toString()

        ethree.register().execute()

        val ethreeTwo = EThree(identityTwo,
                               object : OnGetTokenCallback {
                                   override fun onGetToken(): String {
                                       return TestUtils.generateTokenString(identityTwo)
                                   }
                               },
                               TestConfig.context,
                               keyPairType = KeyPairType.ED25519,
                               enableRatchet = false,
                               keyRotationInterval = TimeSpan.fromTime(3600, TimeUnit.SECONDS))

        assertNotNull(ethreeTwo)

        ethreeTwo.register().execute()

        val card = ethree.findUser(ethreeTwo.identity, forceReload = false).get()
        assertNotNull(card)

        val encrypted = ethree.encrypt(TEXT, card)

        val otherCard = TestUtils.publishCard()

        try {
            ethreeTwo.decrypt(encrypted, otherCard)
            fail()
        } catch (throwable: Throwable) {
            assertTrue(throwable is EThreeException
                       && throwable.description == EThreeException.Description.VERIFICATION_FAILED)
        }

        val cardTwo = ethreeTwo.findUser(ethree.identity, forceReload = false).get()
        val decryptedTwo = ethreeTwo.decrypt(encrypted, cardTwo)
        assertEquals(TEXT, decryptedTwo)
    }

    @Test fun signature_invalid_test() {
        ethree.register().execute()

        val identityTwo = UUID.randomUUID().toString()
        val ethreeTwo = EThree(identityTwo,
                               object : OnGetTokenCallback {
                                   override fun onGetToken(): String {
                                       return TestUtils.generateTokenString(identityTwo)
                                   }
                               },
                               TestConfig.context)
        ethreeTwo.register().execute()

        val cardTwo = ethree.findUser(ethreeTwo.identity).get()
        val encrypted = ethree.encrypt(TEXT, cardTwo)

        // Outdate ethree pub key
        ethree.cleanup()
        ethree.rotatePrivateKey().execute()

        val cardOne = ethreeTwo.findUser(ethree.identity).get()

        try {
            ethreeTwo.decrypt(encrypted, cardOne)
            fail()
        } catch (exception: EThreeException) {
            assertTrue(exception.description == EThreeException.Description.VERIFICATION_FAILED)
        }
    }

    @Test fun encrypt_decrypt_shared_self_decryption() {
        ethree.register().execute()

        val data = TEXT.toByteArray()
        val inputStream = ByteArrayInputStream(data)
        val outputStream = ByteArrayOutputStream()

        val privKeyData = ethree.encryptShared(inputStream, inputStream.available(), outputStream)
        val encryptedData = outputStream.toByteArray()

        val inputStreamTwo = ByteArrayInputStream(encryptedData)
        val outputStreamTwo = ByteArrayOutputStream()

        // Decrypt with private key data
        ethree.decryptShared(inputStreamTwo, outputStreamTwo, privKeyData, null)
        val decryptedData = outputStreamTwo.toByteArray()
        assertArrayEquals(TEXT.toByteArray(), decryptedData)
    }

    @Test fun encrypt_decrypt_shared() {
        ethree.register().execute()

        val identityTwo = UUID.randomUUID().toString()
        val ethreeTwo = EThree(identityTwo,
                object : OnGetTokenCallback {
                    override fun onGetToken(): String {
                        return TestUtils.generateTokenString(identityTwo)
                    }
                },
                TestConfig.context)
        ethreeTwo.register().execute()
        val cardOne = ethreeTwo.findUser(ethree.identity).get()

        val data = TEXT.toByteArray()
        val inputStream = ByteArrayInputStream(data)
        val outputStream = ByteArrayOutputStream()

        val privKeyData = ethree.encryptShared(inputStream, inputStream.available(), outputStream)
        val encryptedData = outputStream.toByteArray()

        var inputStreamTwo = ByteArrayInputStream(encryptedData)
        var outputStreamTwo = ByteArrayOutputStream()

        // Decrypt with private key by card
        ethreeTwo.decryptShared(inputStreamTwo, outputStreamTwo, privKeyData, cardOne)
        var decryptedData = outputStreamTwo.toByteArray()
        assertArrayEquals(TEXT.toByteArray(), decryptedData)

        // Decrypt with private key by public key
        inputStreamTwo = ByteArrayInputStream(encryptedData)
        outputStreamTwo = ByteArrayOutputStream()
        ethreeTwo.decryptShared(inputStreamTwo, outputStreamTwo, privKeyData, cardOne.publicKey)
        decryptedData = outputStreamTwo.toByteArray()
        assertArrayEquals(TEXT.toByteArray(), decryptedData)
    }

    companion object {
        private const val TAG = "PeerToPeerTest"
        private const val TEXT = "Hello, my name is text. I am here to be encrypted (:"
    }

    fun <T> CoroutineScope.asyncIO(ioFun: () -> T) = async(Dispatchers.IO) { ioFun() } // CoroutineDispatcher - runs and schedules coroutines
}
