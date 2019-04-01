package com.virgilsecurity.android.common.data.remote

import com.virgilsecurity.android.common.data.Const
import com.virgilsecurity.android.common.data.Const.VIRGIL_BASE_URL
import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.cloud.CloudKeyStorage
import com.virgilsecurity.keyknox.crypto.KeyknoxCrypto
import com.virgilsecurity.pythia.brainkey.BrainKey
import com.virgilsecurity.pythia.brainkey.BrainKeyContext
import com.virgilsecurity.pythia.client.VirgilPythiaClient
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto
import com.virgilsecurity.sdk.crypto.PrivateKey
import com.virgilsecurity.sdk.crypto.PublicKey
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import java.net.URL
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

/**
 * KeyManagerCloud
 */
class KeyManagerCloud(
        private val identity: String,
        private val tokenProvider: AccessTokenProvider
) {

    private val keyknoxClient: KeyknoxClient = KeyknoxClient(URL(VIRGIL_BASE_URL))
    private val brainKeyContext: BrainKeyContext = BrainKeyContext.Builder()
            .setAccessTokenProvider(tokenProvider)
            .setPythiaClient(VirgilPythiaClient(VIRGIL_BASE_URL))
            .setPythiaCrypto(VirgilPythiaCrypto())
            .build()

    suspend fun exists(password: String) = initCloudKeyStorage(password).exists(identity)

    suspend fun store(password: String, data: ByteArray, meta: Map<String, String>? = null) =
            initCloudKeyStorage(password).store(identity, data, meta)

    suspend fun retrieve(password: String) = initCloudKeyStorage(password).retrieve(identity)

    suspend fun delete(password: String) = initCloudKeyStorage(password).delete(identity)

    suspend fun deleteAll() =
            suspendCoroutine<Unit> {
                keyknoxClient.resetValue(tokenProvider.getToken(Const.NO_CONTEXT).stringRepresentation())
                it.resume(Unit)
            }

    suspend fun updateRecipients(password: String,
                                 publicKeys: List<PublicKey>,
                                 privateKey: PrivateKey) =
            initCloudKeyStorage(password).updateRecipients(publicKeys, privateKey)

    /**
     * Initializes [SyncKeyStorage] with default settings, [tokenProvider] and provided
     * [password] after that returns initialized [SyncKeyStorage] object.
     */
    private suspend fun initCloudKeyStorage(password: String): CloudKeyStorage =
            suspendCoroutine {
                BrainKey(brainKeyContext).generateKeyPair(password)
                        .let { keyPair ->
                            val keyknoxManager = KeyknoxManager(tokenProvider,
                                                                keyknoxClient,
                                                                listOf(keyPair.publicKey),
                                                                keyPair.privateKey,
                                                                KeyknoxCrypto())
                            val cloudKeyStorage = CloudKeyStorage(keyknoxManager).also { cloudKeyStorage ->
                                cloudKeyStorage.retrieveCloudEntries()
                            }
                            it.resume(cloudKeyStorage)
                        }
            }
}
