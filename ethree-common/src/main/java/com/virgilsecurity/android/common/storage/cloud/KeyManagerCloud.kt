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

package com.virgilsecurity.android.common.storage.cloud

import com.virgilsecurity.android.common.exception.WrongPasswordException
import com.virgilsecurity.android.common.util.Const
import com.virgilsecurity.android.common.util.Const.VIRGIL_BASE_URL
import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.client.HttpClient
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.cloud.CloudKeyStorage
import com.virgilsecurity.keyknox.crypto.KeyknoxCrypto
import com.virgilsecurity.pythia.brainkey.BrainKey
import com.virgilsecurity.pythia.brainkey.BrainKeyContext
import com.virgilsecurity.pythia.client.VirgilPythiaClient
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.crypto.exceptions.DecryptionException
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import java.net.URL

/**
 * KeyManagerCloud
 */
class KeyManagerCloud(
        private val identity: String,
        private val crypto: VirgilCrypto,
        private val tokenProvider: AccessTokenProvider,
        ethreeVersion: String
) {

    private val keyknoxClient: KeyknoxClient
    private val keyknoxManager: KeyknoxManager

    private val brainKey: BrainKey

    init {
        val httpClient = HttpClient(tokenProvider, Const.ETHREE_NAME, ethreeVersion)
        keyknoxClient = KeyknoxClient(httpClient, URL(VIRGIL_BASE_URL))
        this.keyknoxManager = KeyknoxManager(keyknoxClient)
        val pythiaClient = VirgilPythiaClient(VIRGIL_BASE_URL, // TODO change VirgilPythiaClient to have tokenProvider inside
                                              Const.ETHREE_NAME,
                                              Const.ETHREE_NAME,
                                              ethreeVersion)
        val brainKeyContext = BrainKeyContext.Builder()
                .setAccessTokenProvider(tokenProvider)
                .setPythiaClient(pythiaClient)
                .setPythiaCrypto(VirgilPythiaCrypto())
                .build()

        this.brainKey = BrainKey(brainKeyContext)
    }

    fun exists(password: String) = initCloudKeyStorage(password).exists(identity)

    fun store(password: String, data: ByteArray, meta: Map<String, String>?) =
            initCloudKeyStorage(password).store(identity, data, meta)

    fun retrieve(password: String) = initCloudKeyStorage(password).retrieve(identity)

    fun delete(password: String) = initCloudKeyStorage(password).delete(identity)

    fun deleteAll() = keyknoxClient.resetValue()

    fun updateRecipients(password: String,
                         publicKeys: List<VirgilPublicKey>,
                         privateKey: VirgilPrivateKey) =
            initCloudKeyStorage(password).updateRecipients(publicKeys, privateKey)

    /**
     * Initializes [SyncKeyStorage] with default settings, [tokenProvider] and provided
     * [password] after that returns initialized [SyncKeyStorage] object.
     */
    private fun initCloudKeyStorage(password: String): CloudKeyStorage {
        val brainKeyPair = this.brainKey.generateKeyPair(password)

        val cloudKeyStorage = CloudKeyStorage(this.keyknoxManager, listOf(brainKeyPair.publicKey), brainKeyPair.privateKey)

        try {
            cloudKeyStorage.retrieveCloudEntries()
        } catch (e: DecryptionException) {
            throw WrongPasswordException()
        }

        return  cloudKeyStorage
    }
}
