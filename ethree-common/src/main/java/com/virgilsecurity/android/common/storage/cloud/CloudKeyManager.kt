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

package com.virgilsecurity.android.common.storage.cloud

import com.virgilsecurity.android.common.build.VirgilInfo
import com.virgilsecurity.android.common.exception.EThreeException
import com.virgilsecurity.android.common.util.Const
import com.virgilsecurity.android.common.util.Const.VIRGIL_BASE_URL
import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.client.HttpClient
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.client.KeyknoxPullParams
import com.virgilsecurity.keyknox.client.KeyknoxPushParams
import com.virgilsecurity.keyknox.cloud.CloudEntrySerializer
import com.virgilsecurity.keyknox.cloud.CloudKeyStorage
import com.virgilsecurity.keyknox.exception.DecryptionFailedException
import com.virgilsecurity.keyknox.exception.EntrySavingException
import com.virgilsecurity.keyknox.exception.KeyknoxCryptoException
import com.virgilsecurity.keyknox.model.CloudEntries
import com.virgilsecurity.keyknox.model.CloudEntry
import com.virgilsecurity.keyknox.utils.Serializer
import com.virgilsecurity.pythia.brainkey.BrainKey
import com.virgilsecurity.pythia.brainkey.BrainKeyContext
import com.virgilsecurity.pythia.client.VirgilPythiaClient
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import com.virgilsecurity.sdk.storage.JsonKeyEntry
import com.virgilsecurity.sdk.utils.ConvertionUtils
import java.net.URL
import java.util.*

/**
 * CloudKeyManager
 */
internal class CloudKeyManager internal constructor(
        private val identity: String,
        private val crypto: VirgilCrypto,
        internal val tokenProvider: AccessTokenProvider,
        baseUrl: String = VIRGIL_BASE_URL
) {

    private val keyknoxManager: KeyknoxManager
    private val brainKey: BrainKey

    init {
        val httpClient = HttpClient(tokenProvider, Const.ETHREE_NAME, VirgilInfo.VERSION)
        val keyknoxClient = KeyknoxClient(httpClient, URL(baseUrl))
        this.keyknoxManager = KeyknoxManager(keyknoxClient)

        // TODO change VirgilPythiaClient to have tokenProvider inside
        val pythiaClient = VirgilPythiaClient(baseUrl, Const.ETHREE_NAME, Const.ETHREE_NAME,
                                              VirgilInfo.VERSION)
        val brainKeyContext = BrainKeyContext.Builder()
                .setAccessTokenProvider(tokenProvider)
                .setPythiaClient(pythiaClient)
                .setPythiaCrypto(VirgilPythiaCrypto())
                .build()

        this.brainKey = BrainKey(brainKeyContext)
    }

    internal fun exists(password: String) = setupCloudKeyStorage(password).exists(identity)

    internal fun store(key: VirgilPrivateKey, keyName: String?, password: String) {
        val exportedIdentityKey = this.crypto.exportPrivateKey(key)
        if (keyName == null) {
            // Store key in keyknox v1
            setupCloudKeyStorage(password).store(this.identity, exportedIdentityKey)
        } else {
            // Store key in keyknox v2
            val brainKeyPair = this.brainKey.generateKeyPair(password)
            val pullParams = KeyknoxPullParams(this.identity, "e3kit", "backup", keyName)
            val keyknoxValue = this.keyknoxManager.pullValue(pullParams, listOf(brainKeyPair.publicKey), brainKeyPair.privateKey)

            val params = KeyknoxPushParams(listOf(this.identity), "e3kit", "backup", keyName)
            val now = Date()
            val entry = CloudEntry(this.identity, exportedIdentityKey, now, now, mapOf())
            this.keyknoxManager.pushValue(params, ConvertionUtils.toBytes(Serializer.gson.toJson(entry)), keyknoxValue.keyknoxHash, listOf(brainKeyPair.publicKey), brainKeyPair.privateKey)
        }
    }

    internal fun retrieve(keyName: String?, password: String): CloudEntry {
        if (keyName == null) {
            // Retrieve key from keyknox v1
            return setupCloudKeyStorage(password).retrieve(keyName ?: this.identity)
        } else {
            // Retrieve key from keyknox v2
            val brainKeyPair = this.brainKey.generateKeyPair(password)
            val pullParams = KeyknoxPullParams(this.identity, "e3kit", "backup", keyName)
            val keyknoxValue = this.keyknoxManager.pullValue(pullParams, listOf(brainKeyPair.publicKey), brainKeyPair.privateKey)
            val entry = Serializer.gson.fromJson<CloudEntry>(ConvertionUtils.toString(keyknoxValue.value), CloudEntry::class.java)
            return entry
        }
    }

    internal fun delete(password: String) {
        setupCloudKeyStorage(password).delete(identity)
    }

    internal fun deleteAll() {
        this.keyknoxManager.resetValue()
    }

    internal fun changePassword(oldPassword: String, newPassword: String) {
        val cloudKeyStorage = setupCloudKeyStorage(oldPassword)

        val brainKeyPair = this.brainKey.generateKeyPair(newPassword)

        try {
            cloudKeyStorage.updateRecipients(listOf(brainKeyPair.publicKey),
                                             brainKeyPair.privateKey)
        } catch (e: KeyknoxCryptoException) {
            throw EThreeException(EThreeException.Description.WRONG_PASSWORD)
        }
    }

    /**
     * Initializes [SyncKeyStorage] with default settings, [tokenProvider] and provided
     * [password] after that returns initialized [SyncKeyStorage] object.
     */
    internal fun setupCloudKeyStorage(password: String): CloudKeyStorage {
        val brainKeyPair = this.brainKey.generateKeyPair(password)

        val cloudKeyStorage = CloudKeyStorage(this.keyknoxManager, listOf(brainKeyPair.publicKey),
                                              brainKeyPair.privateKey)

        try {
            cloudKeyStorage.retrieveCloudEntries()
        } catch (e: DecryptionFailedException) {
            throw EThreeException(EThreeException.Description.WRONG_PASSWORD)
        }

        return cloudKeyStorage
    }
}
