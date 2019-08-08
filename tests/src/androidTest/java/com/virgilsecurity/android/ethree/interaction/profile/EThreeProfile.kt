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

package com.virgilsecurity.android.ethree.interaction.profile

import android.os.Debug
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import kotlin.random.Random

/**
 * EThreeProfile
 */
class EThreeProfile {

    private val crypto = VirgilCrypto()
    private val oneMbData = Random.nextBytes(1000 * 1000) // One Megabyte

    // To have clear tests
    private lateinit var encryptedData: ByteArray
    private lateinit var signature: ByteArray
    private lateinit var keyPair: VirgilKeyPair

    @Before fun setup() {
        keyPair = crypto.generateKeyPair()
        encryptedData = crypto.encrypt(oneMbData, keyPair.publicKey)
        signature = crypto.generateSignature(oneMbData, keyPair.privateKey)
    }

    @Ignore("Needed only to profile from time to time") @Test fun encrypt_debug_profile() {
        Debug.startMethodTracing("EThreeProfile_encrypt")
        crypto.encrypt(oneMbData, keyPair.publicKey)
        Debug.stopMethodTracing()
    }

    @Ignore("Needed only to profile from time to time") @Test fun decrypt_debug_profile() {
        Debug.startMethodTracing("EThreeProfile_decrypt")
        crypto.decrypt(encryptedData, keyPair.privateKey)
        Debug.stopMethodTracing()
    }

    @Ignore("Needed only to profile from time to time") @Test fun generate_signature_debug_profile() {
        Debug.startMethodTracing("EThreeProfile_generate_signature")
        crypto.generateSignature(oneMbData, keyPair.privateKey)
        Debug.stopMethodTracing()
    }

    @Ignore("Needed only to profile from time to time") @Test fun verify_signature_debug_profile() {
        Debug.startMethodTracing("EThreeProfile_verify_signature")
        crypto.verifySignature(signature, oneMbData, keyPair.publicKey)
        Debug.stopMethodTracing()
    }

    @Test fun encrypt() {
        val startTime = System.nanoTime()
        crypto.encrypt(oneMbData, keyPair.publicKey)
        println("Encrypt Time = " + (System.nanoTime() - startTime))
    }

    @Test fun decrypt() {
        val startTime = System.nanoTime()
        crypto.decrypt(encryptedData, keyPair.privateKey)
        println("Decrypt Time = " + (System.nanoTime() - startTime))
    }

    @Test fun generate_signature() {
        val startTime = System.nanoTime()
        crypto.generateSignature(oneMbData, keyPair.privateKey)
        println("Generate signature Time = " + (System.nanoTime() - startTime))
    }

    @Test fun verify_signature() {
        val startTime = System.nanoTime()
        crypto.verifySignature(signature, oneMbData, keyPair.publicKey)
        println("Verify signature Time = " + (System.nanoTime() - startTime))
    }
}
