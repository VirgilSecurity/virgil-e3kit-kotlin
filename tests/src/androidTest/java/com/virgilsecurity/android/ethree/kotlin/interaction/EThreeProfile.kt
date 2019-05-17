package com.virgilsecurity.android.ethree.kotlin.interaction

import android.os.Debug
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilKeyPair
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

/**
 * EThreeProfile
 */
class EThreeProfile {

    private val crypto = VirgilCrypto()
    private val oneMbData = Random.nextBytes(100 * 100 * 100) // One Megabyte

    // To have clear tests
    private lateinit var encryptedData: ByteArray
    private lateinit var signature: ByteArray
    private lateinit var keyPair: VirgilKeyPair

    @Before fun setup() {
        keyPair = crypto.generateKeyPair()
        encryptedData = crypto.encrypt(oneMbData, keyPair.publicKey)
        signature = crypto.generateSignature(oneMbData, keyPair.privateKey)
    }

    @Test fun encrypt_debug_profile() {
        Debug.startMethodTracing("EThreeProfile_encrypt")
        crypto.encrypt(oneMbData, keyPair.publicKey)
        Debug.stopMethodTracing()
    }

    @Test fun decrypt_debug_profile() {
        Debug.startMethodTracing("EThreeProfile_decrypt")
        crypto.decrypt(encryptedData, keyPair.privateKey)
        Debug.stopMethodTracing()
    }

    @Test fun generate_signature_debug_profile() {
        Debug.startMethodTracing("EThreeProfile_generate_signature")
        crypto.generateSignature(oneMbData, keyPair.privateKey)
        Debug.stopMethodTracing()
    }

    @Test fun verify_signature_debug_profile() {
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
