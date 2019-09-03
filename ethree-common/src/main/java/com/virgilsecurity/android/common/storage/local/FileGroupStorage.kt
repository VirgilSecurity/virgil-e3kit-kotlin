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

import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import com.virgilsecurity.sdk.storage.FileSystemEncrypted
import com.virgilsecurity.sdk.storage.FileSystemEncryptedCredentials
import java.io.File

/**
 * FileGroupStorage
 */
class FileGroupStorage internal constructor(
        private val identity: String,
        crypto: VirgilCrypto,
        identityKeyPair: VirgilKeyPair,
        rootPath: String
) { // TODO use internal everywhere possible

    private val fileSystemEncrypted: FileSystemEncrypted

    init {
        val credentials = FileSystemEncryptedCredentials(crypto, identityKeyPair)
        val fullPath: String = rootPath +
                               File.separator +
                               identityKeyPair +
                               File.separator +
                               STORAGE_POSTFIX_E3KIT +
                               File.separator +
                               STORAGE_POSTFIX_GROUPS

        fileSystemEncrypted = FileSystemEncrypted(fullPath, credentials)
    }

    internal fun store(group: RawGroup)

    companion object {
        private const val groupInfoName = "GROUP_INFO"
        private const val ticketsSubdir = "TICKETS"
        private const val STORAGE_POSTFIX_E3KIT = "VIRGIL-E3KIT"
        private const val STORAGE_POSTFIX_GROUPS = "GROUPS"
    }
}
