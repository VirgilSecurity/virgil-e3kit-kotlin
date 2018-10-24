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

import com.virgilsecurity.e2ee.data.exception.NotBootstrappedException
import com.virgilsecurity.e2ee.data.exception.PublicKeyDuplicateException
import com.virgilsecurity.e2ee.data.exception.PublicKeyNotFoundException
import com.virgilsecurity.e2ee.interaction.EThree
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.PublicKey
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyStorage
import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assertions.*
import utils.TestConfig
import java.lang.IllegalArgumentException
import java.lang.IllegalStateException
import java.util.*
import java.util.concurrent.TimeUnit

/**
 * Created by:
 * Danylo Oliinyk
 * on
 * 10/24/18
 * at Virgil Security
 */
class EThreeNegativeTest {

    private lateinit var jwtGenerator: JwtGenerator
    private lateinit var keyStorage: KeyStorage
    private lateinit var eThree: EThree
    private val identity = UUID.randomUUID().toString()
    private val password = UUID.randomUUID().toString()


    @BeforeEach
    fun setup() {
        jwtGenerator = JwtGenerator(TestConfig.appId,
                                    TestConfig.apiKey,
                                    TestConfig.apiPublicKeyId,
                                    TimeSpan.fromTime(600, TimeUnit.SECONDS),
                                    VirgilAccessTokenSigner(TestConfig.virgilCrypto))

        keyStorage = DefaultKeyStorage()
        eThree = initEThree(identity)
    }

    private fun initEThree(identity: String): EThree {
        var eThree: EThree? = null
        EThree.initialize(object : EThree.OnGetTokenCallback {
            override fun onGetToken(): String {
                return jwtGenerator.generateToken(identity).stringRepresentation()
            }
        }, object : EThree.OnResultListener<EThree> {
            override fun onSuccess(result: EThree) {
                eThree = result
            }

            override fun onError(throwable: Throwable) {
                fail(throwable)
            }
        })

        return eThree!!
    }

    private fun bootstrapEThree(eThree: EThree): EThree {
        eThree.bootstrap(object : EThree.OnCompleteListener {

            override fun onSuccess() {
                // Good, go on
            }

            override fun onError(throwable: Throwable) {
                fail(throwable)
            }
        })

        return eThree
    }

    @Test fun cleanup_fail_without_bootstrap() {
        assertThrows<NotBootstrappedException> {
            eThree.cleanup()
        }
    }

    @Test fun backup_fail_without_bootstrap() {
        var failed = false
        eThree.backupPrivateKey(password, object : EThree.OnCompleteListener {
            override fun onSuccess() {
                fail<NotBootstrappedException>()
            }

            override fun onError(throwable: Throwable) {
                failed = true
            }
        })
        assertTrue(failed)
    }

    @Test fun reset_key_fail_without_bootstrap() {
        var failed = false
        eThree.resetPrivateKeyBackup(password, object : EThree.OnCompleteListener {
            override fun onSuccess() {
                fail<NotBootstrappedException>()
            }

            override fun onError(throwable: Throwable) {
                failed = true
            }
        })
        assertTrue(failed)
    }

    @Test fun change_pass_fail_without_bootstrap() {
        var failed = false
        eThree.changePassword(password, password + password, object : EThree.OnCompleteListener {
            override fun onSuccess() {
                fail<NotBootstrappedException>()
            }

            override fun onError(throwable: Throwable) {
                failed = true
            }
        })
        assertTrue(failed)
    }

    @Test fun encrypt_text_fail_without_bootstrap() {
        assertThrows<NotBootstrappedException> {
            eThree.encrypt("")
        }
    }

    @Test fun encrypt_data_fail_without_bootstrap() {
        assertThrows<NotBootstrappedException> {
            eThree.encrypt(ByteArray(0))
        }
    }

    @Test fun decrypt_text_fail_without_bootstrap() {
        assertThrows<NotBootstrappedException> {
            eThree.decrypt("")
        }
    }

    @Test fun decrypt_data_fail_without_bootstrap() {
        assertThrows<NotBootstrappedException> {
            eThree.decrypt(ByteArray(0))
        }
    }

    @Test fun lookup_fail_without_bootstrap() {
        var failed = false
        eThree.lookupPublicKeys(listOf(""), object : EThree.OnResultListener<List<PublicKey>> {
            override fun onSuccess(result: List<PublicKey>) {
                fail<NotBootstrappedException>()
            }

            override fun onError(throwable: Throwable) {
                failed = true
            }
        })
        assertTrue(failed)
    }

    @Test fun lookup_fail_wrong_identity() {
        bootstrapEThree(eThree)

        var failed = false
        eThree.lookupPublicKeys(listOf(identity, WRONG_IDENTITY), object : EThree.OnResultListener<List<PublicKey>> {
            override fun onSuccess(result: List<PublicKey>) {
                fail<NotBootstrappedException>()
            }

            override fun onError(throwable: Throwable) {
                if (throwable is PublicKeyNotFoundException && throwable.identity == WRONG_IDENTITY)
                    failed = true
            }
        })
        assertTrue(failed)
    }

    @Test fun init_ethree_with_empty_token() {
        var failed = false
        EThree.initialize(object : EThree.OnGetTokenCallback {
            override fun onGetToken(): String {
                return ""
            }
        }, object : EThree.OnResultListener<EThree> {
            override fun onSuccess(result: EThree) {
                fail<IllegalStateException>()
            }

            override fun onError(throwable: Throwable) {
                failed = true
            }
        })
        assertTrue(failed)
    }

    @Test fun lookup_with_duplicate_identities() {
        var failed = false
        bootstrapEThree(eThree)
        eThree.lookupPublicKeys(listOf(identity, identity, identity,
                                       WRONG_IDENTITY, WRONG_IDENTITY,
                                       WRONG_IDENTITY + identity),
                                object : EThree.OnResultListener<List<PublicKey>> {
                                    override fun onSuccess(result: List<PublicKey>) {
                                        fail<IllegalStateException>()
                                    }

                                    override fun onError(throwable: Throwable) {
                                        if (throwable is PublicKeyDuplicateException)
                                            failed = true
                                    }
                                })
        assertTrue(failed)
    }

    @Test fun change_pass_with_same_new() {
        var failed = false
        bootstrapEThree(eThree)
        eThree.changePassword(password, password, object : EThree.OnCompleteListener {
            override fun onSuccess() {
                fail<IllegalStateException>()
            }

            override fun onError(throwable: Throwable) {
                if (throwable is IllegalArgumentException)
                    failed = true
            }
        })
        assertTrue(failed)
    }

    companion object {
        const val WRONG_IDENTITY = "WRONG_IDENTITY"
    }
}