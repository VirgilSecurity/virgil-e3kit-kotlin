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

import com.virgilsecurity.android.common.exception.EThreeRatchetException
import com.virgilsecurity.android.common.exception.ServiceErrorCodes
import com.virgilsecurity.android.common.exception.UnsafeChannelException
import com.virgilsecurity.android.common.model.unsafe.UnsafeChannel
import com.virgilsecurity.android.common.storage.cloud.CloudUnsafeStorage
import com.virgilsecurity.android.common.storage.local.FileUnsafeKeysStorage
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.ratchet.exception.ProtocolException
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.crypto.VirgilPublicKey
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider

/**
 * UnsageChannelManager
 */
internal class UnsafeChannelManager(
        private val crypto: VirgilCrypto,
        accessTokenProvider: AccessTokenProvider,
        private val localKeyStorage: LocalKeyStorage,
        private val lookupManager: LookupManager,
        keyPair: VirgilKeyPair,
        rootPath: String
) {

    private val identity: String get() = localKeyStorage.identity

    internal val localUnsafeStorage: FileUnsafeKeysStorage
    internal val cloudUnsafeStorage: CloudUnsafeStorage

    init {
        this.cloudUnsafeStorage = CloudUnsafeStorage(identity, accessTokenProvider, crypto)
        this.localUnsafeStorage = FileUnsafeKeysStorage(identity, crypto, keyPair, rootPath)
    }

    internal fun create(identity: String): UnsafeChannel {
        val selfKeyPair = localKeyStorage.retrieveKeyPair()
        val tempKeyPair = crypto.generateKeyPair()

        try {
            cloudUnsafeStorage.store(tempKeyPair.privateKey, identity)
        } catch (exception: ProtocolException) { // TODO test this case or do we need to catch other exception
            if (exception.errorCode == ServiceErrorCodes.INVALID_PREVIOUS_HASH) {
                throw UnsafeChannelException(
                    UnsafeChannelException.Description.CHANNEL_ALREADY_EXISTS
                )
            } else {
                throw exception
            }
        }

        val unsafeChannel = UnsafeChannel(identity,
                                          tempKeyPair.publicKey,
                                          selfKeyPair.privateKey,
                                          crypto)

        localUnsafeStorage.store(tempKeyPair.publicKey, identity)

        return unsafeChannel
    }

    internal fun loadFromCloud(asCreator: Boolean, identity: String): UnsafeChannel {
        val selfKeyPair = localKeyStorage.retrieveKeyPair()

        val publicKey: VirgilPublicKey
        val privateKey: VirgilPrivateKey

        if (asCreator) {
            val tempKeyPair = cloudUnsafeStorage.retrieve(this.identity, identity)
            localUnsafeStorage.store(tempKeyPair.publicKey, identity)

            publicKey = tempKeyPair.publicKey
            privateKey = selfKeyPair.privateKey
        } else {
            val card = lookupManager.lookupCard(identity)
            val tempKeyPair = cloudUnsafeStorage.retrieve(identity, this.identity)
            localUnsafeStorage.store(tempKeyPair.privateKey, identity)

            publicKey = card.publicKey
            privateKey = tempKeyPair.privateKey
        }

        return UnsafeChannel(identity, publicKey, privateKey, crypto)
    }

    internal fun getLocalChannel(identity: String): UnsafeChannel? {
        val unsafeKey = localUnsafeStorage.retrieve(identity) ?: return null

        val privateKey: VirgilPrivateKey
        val publicKey: VirgilPublicKey

        when (unsafeKey.type) {
            FileUnsafeKeysStorage.KeyType.PRIVATE -> { // User is participant
                privateKey = crypto.importPrivateKey(unsafeKey.key.value).privateKey
                publicKey = lookupManager.lookupCachedCard(identity).publicKey
            }
            FileUnsafeKeysStorage.KeyType.PUBLIC -> {
                privateKey = localKeyStorage.retrieveKeyPair().privateKey
                publicKey = crypto.importPublicKey(unsafeKey.key.value)
            }
        }

        return UnsafeChannel(identity, publicKey, privateKey, crypto)
    }

    internal fun delete(identity: String) {
        cloudUnsafeStorage.delete(identity)
        localUnsafeStorage.delete(identity)
    }
}
