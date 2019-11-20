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

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.exception.PrivateKeyNotFoundException
import com.virgilsecurity.android.common.exception.WrongPasswordException
import com.virgilsecurity.android.common.utils.TestConfig
import com.virgilsecurity.android.common.utils.TestUtils
import com.virgilsecurity.android.ethree.interaction.EThree
import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.cloud.CloudKeyStorage
import com.virgilsecurity.keyknox.crypto.KeyknoxCrypto
import com.virgilsecurity.keyknox.storage.SyncKeyStorage
import com.virgilsecurity.pythia.brainkey.BrainKey
import com.virgilsecurity.pythia.brainkey.BrainKeyContext
import com.virgilsecurity.pythia.client.VirgilPythiaClient
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.JsonKeyEntry
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL
import java.util.*

/**
 * BackupTests
 */
@RunWith(AndroidJUnit4::class)
class BackupTests {

    private lateinit var identity: String
    private lateinit var password: String
    private lateinit var crypto: VirgilCrypto
    private lateinit var keyStorage: DefaultKeyStorage
    private lateinit var ethree: EThree

    @Before fun setup() {
        this.identity = UUID.randomUUID().toString()
        this.password = UUID.randomUUID().toString()
        this.crypto = VirgilCrypto()
        this.keyStorage = DefaultKeyStorage(TestConfig.DIRECTORY_PATH, TestConfig.KEYSTORE_NAME)
        this.ethree = EThree(identity,
                             object : OnGetTokenCallback {
                                 override fun onGetToken(): String {
                                     return TestUtils.generateTokenString(identity)
                                 }
                             },
                             TestConfig.context)

        assertNotNull(this.ethree)
    }

    private fun initSyncKeyStorage(identity: String, passwordBrainKey: String): SyncKeyStorage {
        val tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback {
            TestUtils.generateToken(identity)
        })
        val brainKeyContext = BrainKeyContext.Builder()
                .setAccessTokenProvider(tokenProvider)
                .setPythiaClient(VirgilPythiaClient(TestConfig.virgilServiceAddress))
                .setPythiaCrypto(VirgilPythiaCrypto())
                .build()
        val keyPair = BrainKey(brainKeyContext).generateKeyPair(passwordBrainKey)

        val syncKeyStorage = SyncKeyStorage(
            identity,
            keyStorage,
            CloudKeyStorage(
                KeyknoxManager(
                    KeyknoxClient(tokenProvider, URL(TestConfig.virgilServiceAddress)),
                    KeyknoxCrypto()
                ),
                listOf(keyPair.publicKey),
                keyPair.privateKey
            )
        )

        syncKeyStorage.sync()

        return syncKeyStorage
    }

    // test01 STE_15
    @Test fun backup_private_key() {
        try {
            ethree.backupPrivateKey(password).execute()
        } catch (throwable: Throwable) {
            if (throwable !is PrivateKeyNotFoundException)
                fail()
        }

        TestUtils.pause()

        val keyPair = TestConfig.virgilCrypto.generateKeyPair()
        val data = TestConfig.virgilCrypto.exportPrivateKey(keyPair.privateKey)

        keyStorage.store(JsonKeyEntry(ethree.identity, data))

        ethree.backupPrivateKey(password).execute()

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(ethree.identity, password)

        val syncEntry = syncKeyStorage.retrieve(ethree.identity)
        assertNotNull(syncEntry)
        assertArrayEquals(data, syncEntry.value)

        TestUtils.pause()

        try {
            ethree.backupPrivateKey(password).execute()
            fail()
        } catch (throwable: Throwable) {
            // We're good
        }
    }

    // test02 STE_16
    @Test fun restore_private_key() {
        val keyPair = TestConfig.virgilCrypto.generateKeyPair()
        val data = TestConfig.virgilCrypto.exportPrivateKey(keyPair.privateKey)

        TestUtils.publishCard(ethree.identity)

        val syncKeyStorage = initSyncKeyStorage(ethree.identity, password)
        syncKeyStorage.store(ethree.identity, data)

        TestUtils.pause()

        try {
            ethree.restorePrivateKey(WRONG_PASSWORD).execute()
        } catch (throwable: Throwable) {
            if (throwable !is WrongPasswordException)
                fail()
        }


        TestUtils.pause()

        ethree.restorePrivateKey(password).execute()

        val retrievedEntry = keyStorage.load(ethree.identity)
        assertNotNull(retrievedEntry)
        assertArrayEquals(data, retrievedEntry.value)

        TestUtils.pause()

        try {
            ethree.restorePrivateKey(password).execute()
            fail()
        } catch (throwable: Throwable) {
            // We're good
        }
    }

    // test03 STE_17
    @Test fun change_private_key() {
        val keyPair = TestConfig.virgilCrypto.generateKeyPair()
        val data = TestConfig.virgilCrypto.exportPrivateKey(keyPair.privateKey)

        TestUtils.publishCard(ethree.identity)

        val syncKeyStorage = initSyncKeyStorage(ethree.identity, password)
        syncKeyStorage.store(ethree.identity, data)

        TestUtils.pause()

        val passwordNew = UUID.randomUUID().toString()

        ethree.changePassword(password, passwordNew).execute()

        TestUtils.pause()

        try {
            ethree.restorePrivateKey(password).execute()
        } catch (throwable: Throwable) {
            if (throwable !is WrongPasswordException)
                fail()
        }

        TestUtils.pause()

        ethree.restorePrivateKey(passwordNew).execute()

        val retrievedEntry = keyStorage.load(ethree.identity)
        assertNotNull(retrievedEntry)
        assertArrayEquals(data, retrievedEntry.value)
    }

    // test04 STE_18
    @Test fun reset_private_key_backup() {
        try {
            ethree.resetPrivateKeyBackup(password).execute()
        } catch (throwable: Throwable) {
            if (throwable !is PrivateKeyNotFoundException)
                fail()
        }

        val keyPair = TestConfig.virgilCrypto.generateKeyPair()
        val data = TestConfig.virgilCrypto.exportPrivateKey(keyPair.privateKey)

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(ethree.identity, password)
        syncKeyStorage.store(ethree.identity, data)

        TestUtils.pause()

        ethree.resetPrivateKeyBackup(password).execute()

        syncKeyStorage.sync()

        try {
            syncKeyStorage.retrieve(ethree.identity)
            fail()
        } catch (throwable: Throwable) {
            // We're good
        }
    }

    // test05 STE_19
    @Test fun reset_private_key_backup_no_password() {
        try {
            ethree.resetPrivateKeyBackup(password).execute()
        } catch (throwable: Throwable) {
            if (throwable !is PrivateKeyNotFoundException)
                fail()
        }

        val keyPair = TestConfig.virgilCrypto.generateKeyPair()
        val data = TestConfig.virgilCrypto.exportPrivateKey(keyPair.privateKey)

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(ethree.identity, password)
        syncKeyStorage.store(ethree.identity, data)

        TestUtils.pause()

        ethree.resetPrivateKeyBackup().execute()

        syncKeyStorage.sync()

        try {
            syncKeyStorage.retrieve(ethree.identity)
            fail()
        } catch (throwable: Throwable) {
            // We're good
        }
    }

    companion object {
        private const val WRONG_PASSWORD = "WRONG_PASSWORD"
    }
}
