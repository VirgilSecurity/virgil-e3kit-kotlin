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

package com.virgilsecurity.android.common.storage.local

import com.virgilsecurity.android.common.exception.PrivateKeyNotFoundException
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException
import com.virgilsecurity.sdk.storage.KeyStorage

/**
 * Local KeyStorage.
 */
open class KeyStorageLocal(val identity: String, private val crypto: VirgilCrypto, private val keyStorage: KeyStorage) {

    fun exists() : Boolean {
        return this.keyStorage.exists(this.identity)
    }

    fun store(privateKeyData: Data) {
        return this.keyStorage.store(this.keyStorage.createEntry(this.identity, privateKeyData.data))
    }

    /**
     * Retrieves current user's [VirgilKeyPair] with
     */
    fun load(): VirgilKeyPair {
        val keyEntry = this.keyStorage.load(this.identity)
        try {
            val keyPair = this.crypto.importPrivateKey(keyEntry.value)
            return keyPair
        }
        catch (e: CryptoException) { // TODO check whether this is the only one exception we should catch
            throw PrivateKeyNotFoundException()
        }
    }

    fun delete() {
        this.keyStorage.delete(this.identity)
    }
}
