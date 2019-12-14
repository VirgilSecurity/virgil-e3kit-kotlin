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

package com.virgilsecurity.android.common.manager

import com.virgilsecurity.android.common.exception.ServiceErrorCodes
import com.virgilsecurity.android.common.exception.TemporaryChannelException
import com.virgilsecurity.android.common.model.temporary.TemporaryChannel
import com.virgilsecurity.android.common.storage.cloud.CloudTempKeysStorage
import com.virgilsecurity.android.common.storage.local.FileTempKeysStorage
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.keyknox.exception.KeyknoxServiceException
import com.virgilsecurity.ratchet.exception.ProtocolException
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider

/**
 * TempChannelManager
 */
internal class TempChannelManager(
        private val crypto: VirgilCrypto,
        accessTokenProvider: AccessTokenProvider,
        private val localKeyStorage: LocalKeyStorage,
        private val lookupManager: LookupManager,
        keyPair: VirgilKeyPair,
        rootPath: String
) {

    private val identity: String get() = localKeyStorage.identity

    internal val localStorage: FileTempKeysStorage
    internal val cloudStorage: CloudTempKeysStorage

    init {
        this.cloudStorage = CloudTempKeysStorage(identity, accessTokenProvider, crypto)
        this.localStorage = FileTempKeysStorage(identity, crypto, keyPair, rootPath)
    }

    internal fun create(identity: String): TemporaryChannel {
        val selfKeyPair = localKeyStorage.retrieveKeyPair()
        val tempKeyPair = crypto.generateKeyPair()

        try {
            cloudStorage.store(tempKeyPair.privateKey, identity)
        } catch (exception: KeyknoxServiceException) { // TODO test this case or do we need to catch other exception
            if (exception.errorCode == ServiceErrorCodes.INVALID_PREVIOUS_HASH) {
                throw TemporaryChannelException(
                    TemporaryChannelException.Description.CHANNEL_ALREADY_EXISTS
                )
            } else {
                throw exception
            }
        }

        val tempChannel = TemporaryChannel(identity,
                                           tempKeyPair.publicKey,
                                           selfKeyPair.privateKey,
                                           crypto)

        localStorage.store(tempKeyPair.publicKey, identity)

        return tempChannel
    }

    internal fun loadFromCloud(asCreator: Boolean, identity: String): TemporaryChannel {
        val selfKeyPair = localKeyStorage.retrieveKeyPair()

        val publicKey: VirgilPublicKey
        val privateKey: VirgilPrivateKey

        if (asCreator) {
            val tempKeyPair = cloudStorage.retrieve(this.identity, identity)
            localStorage.store(tempKeyPair.publicKey, identity)

            publicKey = tempKeyPair.publicKey
            privateKey = selfKeyPair.privateKey
        } else {
            val card = lookupManager.lookupCard(identity)
            val tempKeyPair = cloudStorage.retrieve(identity, this.identity)
            localStorage.store(tempKeyPair.privateKey, identity)

            publicKey = card.publicKey
            privateKey = tempKeyPair.privateKey
        }

        return TemporaryChannel(identity, publicKey, privateKey, crypto)
    }

    internal fun getLocalChannel(identity: String): TemporaryChannel? {
        val tempKey = localStorage.retrieve(identity) ?: return null

        val privateKey: VirgilPrivateKey
        val publicKey: VirgilPublicKey

        when (tempKey.type) {
            FileTempKeysStorage.KeyType.PRIVATE -> { // User is participant
                privateKey = crypto.importPrivateKey(tempKey.key.value).privateKey
                publicKey = lookupManager.lookupCachedCard(identity).publicKey
            }
            FileTempKeysStorage.KeyType.PUBLIC -> {
                privateKey = localKeyStorage.retrieveKeyPair().privateKey
                publicKey = crypto.importPublicKey(tempKey.key.value)
            }
        }

        return TemporaryChannel(identity, publicKey, privateKey, crypto)
    }

    internal fun delete(identity: String) {
        cloudStorage.delete(identity)
        localStorage.delete(identity)
    }
}
