/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
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

package interaction

import com.virgilsecurity.e2ee.interaction.EThree
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.model.RawSignedModel
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.CardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider
import com.virgilsecurity.sdk.storage.JsonFileKeyStorage
import com.virgilsecurity.sdk.storage.PrivateKeyStorage
import com.virgilsecurity.sdk.utils.Tuple
import org.junit.jupiter.api.BeforeEach
import utils.TestConfig
import java.util.*
import java.util.concurrent.TimeUnit

/**
 * Created by:
 * Danylo Oliinyk
 * on
 * 10/9/18
 * at Virgil Security
 */
class EndToEndEncryptionTestPositive {

    private val identity = UUID.randomUUID().toString()
    private val password = UUID.randomUUID().toString()
    private lateinit var tokenString: String
    private lateinit var eThree: EThree

    private lateinit var jwtGenerator: JwtGenerator

    @BeforeEach
    fun setup() {
        jwtGenerator = JwtGenerator(TestConfig.appId,
                                    TestConfig.apiKey,
                                    TestConfig.apiPublicKeyId,
                                    TimeSpan.fromTime(600, TimeUnit.SECONDS),
                                    VirgilAccessTokenSigner(TestConfig.virgilCrypto))

        tokenString = jwtGenerator.generateToken(identity).stringRepresentation()
        eThree = EThree(object : EThree.OnGetTokenCallback {
            override fun onGetToken(): String {
                return tokenString
            }

        })
//        eThree.bootstrap()
    }

    private fun initCardManager(identity: String): CardManager {
        val cardCrypto = VirgilCardCrypto()
        return CardManager(cardCrypto,
                           GeneratorJwtProvider(jwtGenerator, identity),
                           VirgilCardVerifier(cardCrypto, false, false),
                           CardClient("https://api-dev.virgilsecurity.com/card/v5/"))
    }

    private fun initPrivateKeyStorage() = PrivateKeyStorage(VirgilPrivateKeyExporter(), JsonFileKeyStorage())

    private fun generateRawCard(identity: String, cardManager: CardManager): Tuple<VirgilKeyPair, RawSignedModel> {
        return VirgilCrypto().generateKeys().let {
            Tuple(it, cardManager.generateRawCard(it.privateKey, it.publicKey, identity))
        }
    }

//    @Disabled
//    @Test
//    fun initEncryptionMultiplyTimes() {
//        for (i in 0..MULTIPLY_TIMES)
//            eThree.initUser()
//    }
//
//    @Disabled
//    @Test
//    fun initEncryptionWithPasswordMultiplyTimes() {
//        for (i in 0..MULTIPLY_TIMES)
//            eThree.initAndSyncUser(password)
//    }
//
//    @Test
//    fun lookup_one_user() {
//        val identityOne = UUID.randomUUID().toString()
//        val cardManagerOne = initCardManager(identityOne)
//        cardManagerOne.publishCard(generateRawCard(identityOne, cardManagerOne).right)
//
//        eThree.startSession(listOf(identityOne))
//    }
//
//    @Test
//    fun lookup_multiply_users() {
//        val identityOne = UUID.randomUUID().toString()
//        val cardManagerOne = initCardManager(identityOne)
//        cardManagerOne.publishCard(generateRawCard(identityOne, cardManagerOne).right)
//
//        eThree.startSession(listOf(identityOne))
//    }
//
//    @Test
//    fun startSessionWithMultiplyUsers() {
//        val identityOne = UUID.randomUUID().toString()
//        val cardManagerOne = initCardManager(identityOne)
//        cardManagerOne.publishCard(generateRawCard(identityOne, cardManagerOne).right)
//
//        val identityTwo = UUID.randomUUID().toString()
//        val cardManagerTwo = initCardManager(identityTwo)
//        cardManagerTwo.publishCard(generateRawCard(identityTwo, cardManagerTwo).right)
//
//        eThree.startSession(listOf(identityOne, identityTwo))
//    }
//
//    @Test
//    fun encryptDecrypt() {
//        val identityOne = UUID.randomUUID().toString()
//        val cardManagerOne = initCardManager(identityOne)
//        val pair = generateRawCard(identityOne, cardManagerOne)
//        val keyPairOne = pair.left
//        val rawModelOne = pair.right
//        cardManagerOne.publishCard(rawModelOne)
//
//        eThree.initUser()
//        eThree.startSession(listOf(identityOne))
//
//        val encryptedForOne = eThree.encrypt(RAW_TEXT.toByteArray())
//
//        val decryptedByOne = VirgilCrypto().decrypt(encryptedForOne, keyPairOne.privateKey)
//        assertEquals(RAW_TEXT, String(decryptedByOne))
//
//        val sessionOwnerPublicKey = VirgilCrypto().extractPublicKey(initPrivateKeyStorage().load(identity)
//                                                                            .left as VirgilPrivateKey)
//        val encryptedForSessionOwner = VirgilCrypto().encrypt(RAW_TEXT.toByteArray(),
//                                                              listOf(keyPairOne.publicKey, sessionOwnerPublicKey))
//
//        val decryptedBySessionOwner = eThree.decrypt(encryptedForSessionOwner)
//        assertEquals(RAW_TEXT, String(decryptedBySessionOwner))
//    }
//
//    @Test
//    fun encryptDecryptWithStop() {
//        val identityOne = UUID.randomUUID().toString()
//        val cardManagerOne = initCardManager(identityOne)
//        val pair = generateRawCard(identityOne, cardManagerOne)
//        val keyPairOne = pair.left
//        val rawModelOne = pair.right
//        cardManagerOne.publishCard(rawModelOne)
//
//        eThree.initUser()
//        eThree.startSession(listOf(identityOne))
//
//        encryptDecryptWithOneUser(keyPairOne)
//
//        eThree.stopSession()
//
//        var encryptFailedWithoutSessionStarted = false
//        try {
//            eThree.encrypt(RAW_TEXT.toByteArray())
//        } catch (e: SessionException) {
//            encryptFailedWithoutSessionStarted = true
//        }
//        assertTrue(encryptFailedWithoutSessionStarted)
//
//        eThree.startSession(listOf(identityOne))
//
//        encryptDecryptWithOneUser(keyPairOne)
//
//        eThree.stopSession()
//    }
//
//    private fun encryptDecryptWithOneUser(keyPair: VirgilKeyPair) {
//        val encryptedForOne = eThree.encrypt(RAW_TEXT.toByteArray())
//
//        val decryptedByOne = VirgilCrypto().decrypt(encryptedForOne, keyPair.privateKey)
//        assertEquals(RAW_TEXT, String(decryptedByOne))
//
//        val sessionOwnerPublicKey = VirgilCrypto().extractPublicKey(PrivateKeyStorage(VirgilPrivateKeyExporter(),
//                                                                                      JsonFileKeyStorage())
//                                                                            .load(identity)
//                                                                            .left as VirgilPrivateKey)
//        val encryptedForSessionOwner = VirgilCrypto().encrypt(RAW_TEXT.toByteArray(),
//                                                              listOf(keyPair.publicKey, sessionOwnerPublicKey))
//
//        val decryptedBySessionOwner = eThree.decrypt(encryptedForSessionOwner)
//        assertEquals(RAW_TEXT, String(decryptedBySessionOwner))
//    }
//
//    @Test
//    fun backupKey() {
//        eThree.initUser()
//        eThree.backupUserKey(password)
//
//        initPrivateKeyStorage().delete(identity)
//
//        var initFailed = false
//        try {
//            eThree.initUser()
//        } catch (e: InitException) {
//            initFailed = true
//        }
//        assertTrue(initFailed)
//
//        eThree.initAndSyncUser(password)
//    }
//
//    @Test
//    fun resetKeyLocal() {
//        eThree.initUser()
//        eThree.resetKeyLocal()
//        assertThrows<InitException> {
//            eThree.initUser()
//        }
//    }
//
//    @Test
//    fun resetKeyBackup() {
//        eThree.initAndSyncUser(password)
//        eThree.resetKeyBackup(password)
//    }
//
//    @Test
//    fun resetUser() {
//        eThree.initAndSyncUser(password)
//        eThree.resetUser(password)
//        assertThrows<InitException> {
//            eThree.initAndSyncUser(password)
//        }
//    }

    companion object {
        const val MULTIPLY_TIMES = 10
        const val RAW_TEXT = "This is the best text ever made by the whole humanity."
    }
}