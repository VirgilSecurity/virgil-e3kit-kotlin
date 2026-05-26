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

import com.google.gson.JsonObject
import com.virgilsecurity.android.common.build.VirgilInfo
import com.virgilsecurity.android.common.util.Const
import com.virgilsecurity.crypto.foundation.BrainkeyClient
import com.virgilsecurity.keyknox.client.HttpClient
import com.virgilsecurity.keyknox.client.Method
import com.virgilsecurity.keyknox.utils.Serializer
import com.virgilsecurity.sdk.crypto.KeyPairType
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.jwt.TokenContext
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import com.virgilsecurity.sdk.utils.ConvertionUtils
import java.net.URL

/**
 * HTTP client for the Virgil brainkey /pythia/v1/brainkey endpoint.
 * Provides key-pair derivation from a password via the OPRF brainkey protocol.
 * ed25519 is required because KeyknoxCrypto.encrypt signs data with the private key
 * (curve25519/X25519 is key-agreement only and cannot sign).
 */
class BrainkeyHttpClient(
    tokenProvider: AccessTokenProvider,
    private val baseUrl: String = Const.VIRGIL_BASE_URL
) {
    private val httpClient = HttpClient(tokenProvider, Const.ETHREE_NAME, VirgilInfo.VERSION)

    fun harden(blindedPoint: ByteArray): ByteArray {
        val url = URL("$baseUrl/pythia/v1/brainkey")
        val body = mapOf("blinded_password" to ConvertionUtils.toBase64String(blindedPoint))
        val response = httpClient.send(url, Method.POST, TOKEN_CONTEXT, body, null)
        val json = Serializer.gson.fromJson(response.body, JsonObject::class.java)
        return ConvertionUtils.base64ToBytes(json.get("seed").asString)
    }

    fun deriveKeyPair(password: String, crypto: VirgilCrypto): VirgilKeyPair {
        BrainkeyClient().use { brainkeyClient ->
            brainkeyClient.setupDefaults()
            val blindResult = brainkeyClient.blind(password.toByteArray())
            val hardenedPoint = harden(blindResult.blindedPoint)
            val seed = brainkeyClient.deblind(
                password.toByteArray(),
                hardenedPoint,
                blindResult.deblindFactor,
                KEY_NAME
            )
            return crypto.generateKeyPair(KeyPairType.ED25519, seed)
        }
    }

    companion object {
        private val TOKEN_CONTEXT = TokenContext("brainkey", "harden")
        private val KEY_NAME = "e3kit-backup".toByteArray()
    }
}
