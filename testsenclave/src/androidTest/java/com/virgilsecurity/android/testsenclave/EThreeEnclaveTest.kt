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

package com.virgilsecurity.android.testsenclave

import android.support.test.runner.AndroidJUnit4
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.ethreeenclave.interaction.EThree
import com.virgilsecurity.android.testsenclave.utils.TestConfig
import com.virgilsecurity.sdk.androidutils.storage.AndroidKeyEntry
import com.virgilsecurity.sdk.androidutils.storage.AndroidKeyStorage
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import org.junit.Assert.assertEquals
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.util.*
import java.util.concurrent.TimeUnit


@RunWith(AndroidJUnit4::class)
class EThreeEnclaveTest {

    companion object {

        lateinit var jwtGenerator: JwtGenerator

        @BeforeClass @JvmStatic fun setup() {
            jwtGenerator = JwtGenerator(TestConfig.appId,
                                        TestConfig.apiKey,
                                        TestConfig.apiPublicKeyId,
                                        TimeSpan.fromTime(600, TimeUnit.SECONDS),
                                        VirgilAccessTokenSigner(TestConfig.virgilCrypto))
        }

        private const val KEYSTORE_NAME = "virgil.keystore"
    }

    @Test fun migration_using_default_key_storage() {
        val alias = UUID.randomUUID().toString()
        val keyStorageDefault = DefaultKeyStorage(TestConfig.context.filesDir.absolutePath,
                                                  KEYSTORE_NAME)

        val virgilCrypto = VirgilCrypto()
        for (i in 0..9) {
            val keyName = UUID.randomUUID().toString()
            val privateKeyData = virgilCrypto.exportPrivateKey(virgilCrypto.generateKeyPair().privateKey)
            keyStorageDefault.store(AndroidKeyEntry(keyName, privateKeyData))
        }

        val androidKeyStorage = AndroidKeyStorage.Builder(alias)
                .isAuthenticationRequired(false)
                .onPath(TestConfig.context.filesDir.absolutePath)
                .build()
        assertEquals(0, androidKeyStorage.names().size)

        val identity = UUID.randomUUID().toString()

        EThree.initialize(TestConfig.context, object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return generateToken(identity)
            }
        }, isAuthenticationRequired = false, alias = alias).get()

        assertEquals(10, androidKeyStorage.names().size)
    }

    @Test fun migration_using_legacy_ethree() {
        val alias = UUID.randomUUID().toString()

        val keyStorageDefault = DefaultKeyStorage(TestConfig.context.filesDir.absolutePath,
                                                  KEYSTORE_NAME)
        assertEquals(0, keyStorageDefault.names().size)

        // Register 10 users and save their keys to default keys storage
        for (i in 0..9) {
            val identity = UUID.randomUUID().toString()

            val eThreeLegacy = com.virgilsecurity.android.ethree.interaction.EThree.initialize(
                TestConfig.context, object : OnGetTokenCallback {
                    override fun onGetToken(): String {
                        return generateToken(identity)
                    }
                }
            ).get()

            eThreeLegacy.register().execute()
        }

        assertEquals(10, keyStorageDefault.names().size)

        val androidKeyStorage = AndroidKeyStorage.Builder(alias)
                .isAuthenticationRequired(false)
                .onPath(TestConfig.context.filesDir.absolutePath)
                .build()
        assertEquals(0, androidKeyStorage.names().size)

        val identity = UUID.randomUUID().toString()

        EThree.initialize(TestConfig.context, object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return generateToken(identity)
            }
        }, isAuthenticationRequired = false, alias = alias).get()

        assertEquals(0, keyStorageDefault.names().size)
        assertEquals(10, androidKeyStorage.names().size)
    }

    @Test fun migration_using_legacy_ethree_and_register_new() {
        val alias = UUID.randomUUID().toString()

        val keyStorageDefault = DefaultKeyStorage(TestConfig.context.filesDir.absolutePath,
                                                  KEYSTORE_NAME)
        assertEquals(0, keyStorageDefault.names().size)

        val identityLegacy = UUID.randomUUID().toString()

        val eThreeLegacy = com.virgilsecurity.android.ethree.interaction.EThree.initialize(
            TestConfig.context, object : OnGetTokenCallback {
                override fun onGetToken(): String {
                    return generateToken(identityLegacy)
                }
            }
        ).get()

        eThreeLegacy.register().execute()

        assertEquals(1, keyStorageDefault.names().size)

        val androidKeyStorage = AndroidKeyStorage.Builder(alias)
                .isAuthenticationRequired(false)
                .onPath(TestConfig.context.filesDir.absolutePath)
                .build()
        assertEquals(0, androidKeyStorage.names().size)

        val identity = UUID.randomUUID().toString()

        val eThreeNew = EThree.initialize(TestConfig.context, object : OnGetTokenCallback {
            override fun onGetToken(): String {
                return generateToken(identity)
            }
        }, isAuthenticationRequired = false, alias = alias).get()

        assertEquals(0, keyStorageDefault.names().size)
        assertEquals(1, androidKeyStorage.names().size)

        eThreeNew.register().execute()
        assertEquals(2, androidKeyStorage.names().size)
    }

    private fun generateToken(identity: String): String =
            jwtGenerator.generateToken(identity).stringRepresentation()
}
