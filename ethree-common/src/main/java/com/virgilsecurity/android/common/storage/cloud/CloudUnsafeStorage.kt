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

import com.virgilsecurity.android.common.exception.UnsafeChannelException
import com.virgilsecurity.android.common.util.Const
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.client.KeyknoxPullParams
import com.virgilsecurity.keyknox.client.KeyknoxPushParams
import com.virgilsecurity.keyknox.client.KeyknoxResetParams
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider

/**
 * CloudUnsafeStorage
 */
internal class CloudUnsafeStorage(
        private val identity: String,
        private val accessTokenProvider: AccessTokenProvider,
        private val crypto: VirgilCrypto
) {

    private val keyknoxClient: KeyknoxClient = KeyknoxClient(accessTokenProvider)

    internal fun store(tempKey: VirgilPrivateKey, identity: String) {
        val pushParams = KeyknoxPushParams(listOf(identity, this.identity),
                                           UNSAFE_KEYS_ROOT,
                                           identity,
                                           Const.DEFAULT_NAME)

        val data = crypto.exportPrivateKey(tempKey)
        val meta = META.toByteArray()

        keyknoxClient.pushValue(pushParams, meta, data, null)
    }

    internal fun retrieve(identity: String, path: String): VirgilKeyPair {
        val params = KeyknoxPullParams(identity,
                                       UNSAFE_KEYS_ROOT,
                                       path,
                                       Const.DEFAULT_NAME)

        val response = keyknoxClient.pullValue(params)

        if (response.value.isEmpty())
            throw UnsafeChannelException(UnsafeChannelException.Description.CHANNEL_NOT_FOUND)

        return crypto.importPrivateKey(response.value)
    }

    internal fun delete(identity: String) {
        val params = KeyknoxResetParams(UNSAFE_KEYS_ROOT,
                                        identity,
                                        Const.DEFAULT_NAME)

        keyknoxClient.resetValue(params)
    }

    companion object {
        private const val UNSAFE_KEYS_ROOT = "unsafe-keys" // TODO do we have compat tests?
        private const val META = "unencrypted"
    }
}
