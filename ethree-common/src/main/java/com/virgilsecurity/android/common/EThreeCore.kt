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

package com.virgilsecurity.android.common

import android.content.Context
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.callback.OnKeyChangedCallback
import com.virgilsecurity.android.common.exception.*
import com.virgilsecurity.android.common.manager.GroupManager
import com.virgilsecurity.android.common.manager.LookupManager
import com.virgilsecurity.android.common.model.FindUsersResult
import com.virgilsecurity.android.common.model.Group
import com.virgilsecurity.android.common.model.LookupResult
import com.virgilsecurity.android.common.storage.cloud.CloudKeyManager
import com.virgilsecurity.android.common.storage.cloud.CloudTicketStorage
import com.virgilsecurity.android.common.storage.local.GroupStorageFile
import com.virgilsecurity.android.common.storage.local.KeyStorageLocal
import com.virgilsecurity.android.common.storage.sql.SQLCardStorage
import com.virgilsecurity.android.common.util.Const
import com.virgilsecurity.android.common.util.Const.VIRGIL_BASE_URL
import com.virgilsecurity.android.common.util.Const.VIRGIL_CARDS_SERVICE_PATH
import com.virgilsecurity.android.common.worker.*
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.common.model.Result
import com.virgilsecurity.keyknox.build.VersionVirgilAgent
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.HttpClient
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.jwt.Jwt
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyStorage
import java.io.InputStream
import java.io.OutputStream
import java.util.*

/**
 * [EThreeCore] class simplifies work with Virgil Services to easily implement End to End Encrypted
 * communication.
 */
abstract class EThreeCore
/**
 * @constructor Initializing [CardManager] with provided in [EThreeCore.initialize] callback
 * [onGetTokenCallback] using [CachingJwtProvider] also initializing [DefaultKeyStorage] with
 * default settings.
 */
constructor(identity: String,
            getTokenCallback: OnGetTokenCallback,
            keyChangedCallback: OnKeyChangedCallback?,
            context: Context) {

    private var accessTokenProvider: AccessTokenProvider
    private val rootPath: String

    private val cloudKeyManager: CloudKeyManager
    val lookupManager: LookupManager
    lateinit var keyStorageLocal: KeyStorageLocal
        private set
    private lateinit var authorizationWorker: AuthorizationWorker
    private lateinit var backupWorker: BackupWorker
    private lateinit var groupWorker: GroupWorker
    private lateinit var p2pWorker: PeerToPeerWorker
    private lateinit var searchWorker: SearchWorker

    var groupManager: GroupManager? = null
        private set

    protected val crypto: VirgilCrypto = VirgilCrypto()

    protected abstract val keyStorage: KeyStorage

    val cardManager: CardManager
    val identity: String

    init {
        this.identity = identity
        val cardCrypto = VirgilCardCrypto(crypto)
        val virgilCardVerifier = VirgilCardVerifier(cardCrypto)
        val httpClient = HttpClient(Const.ETHREE_NAME, VersionVirgilAgent.VERSION) // FIXME wrong VersionVirgilAgent - from keyknox
        this.accessTokenProvider = CachingJwtProvider { Jwt(getTokenCallback.onGetToken()) }

        cardManager = CardManager(cardCrypto,
                                  accessTokenProvider,
                                  VirgilCardVerifier(cardCrypto, false, false),
                                  VirgilCardClient(VIRGIL_BASE_URL + VIRGIL_CARDS_SERVICE_PATH,
                                                   httpClient))

        cloudKeyManager = CloudKeyManager(identity,
                                          crypto,
                                          accessTokenProvider)

        val cardStorageSqlite = SQLCardStorage(context, this.identity, crypto, virgilCardVerifier)

        this.lookupManager = LookupManager(cardStorageSqlite, cardManager, keyChangedCallback)
        this.rootPath = context.filesDir.absolutePath
    }

    /**
     * Should be called on each new instance of `EThreeCore` child objects. Is up to developer.
     *
     * Initialization of workers not in constructor, because they depend on `keyStorageLocal` that
     * is available only after child object of `EThreeCore` is constructed.
     */
    protected fun initializeCore() {
        this.keyStorageLocal = KeyStorageLocal(identity, keyStorage, crypto)
        this.authorizationWorker = AuthorizationWorker(cardManager,
                                                       keyStorageLocal,
                                                       identity,
                                                       ::publishCardThenSaveLocal,
                                                       ::privateKeyDeleted)
        this.backupWorker = BackupWorker(keyStorageLocal, cloudKeyManager, ::privateKeyChanged)
        this.groupWorker = GroupWorker(identity, crypto, ::getGroupManager, ::computeSessionId)
        this.p2pWorker = PeerToPeerWorker(keyStorageLocal, crypto)
        this.searchWorker = SearchWorker(lookupManager)

        if (keyStorageLocal.exists()) {
            privateKeyChanged()
        }

        lookupManager.startUpdateCachedCards()
    }

    internal fun getGroupManager(): GroupManager =
            groupManager ?: throw EThreeException("No private key on device. You should call " +
                                                  "register() of retrievePrivateKey()")

    /**
     * Publishes the public key in Virgil's Cards Service in case no public key for current
     * identity is published yet. Otherwise [RegistrationException] will be thrown.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws RegistrationException
     * @throws CryptoException
     */
    @Synchronized
    @JvmOverloads
    fun register(keyPair: VirgilKeyPair? = null) = authorizationWorker.register(keyPair)

    /**
     * Revokes the public key for current *identity* in Virgil's Cards Service. After this operation
     * you can call [EThreeCore.register] again.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws UnRegistrationException if there's no public key published yet, or if there's more
     * than one public key is published.
     */
    @Synchronized fun unregister() = authorizationWorker.unregister()

    /**
     * Generates new key pair, publishes new public key for current identity and deprecating old
     * public key, saves private key to the local storage. All data that was encrypted earlier
     * will become undecryptable.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws PrivateKeyExistsException
     * @throws CardNotFoundException
     * @throws CryptoException
     */
    @Synchronized fun rotatePrivateKey() = authorizationWorker.rotatePrivateKey()

    /**
     * Checks whether the private key is present in the local storage of current device.
     * Returns *true* if the key is present in the local key storage otherwise *false*.
     */
    fun hasLocalPrivateKey() = authorizationWorker.hasLocalPrivateKey()

    /**
     * ! *WARNING* ! If you call this function after [register] without using [backupPrivateKey]
     * then you loose private key permanently, as well you won't be able to use identity that
     * was used with that private key no more.
     *
     * Cleans up user's private key from a device - call this function when you want to log your
     * user out of the device.
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * @throws PrivateKeyNotFoundException
     */
    fun cleanup() = authorizationWorker.cleanup()

    /**
     * Returns cards from local storage for given [identities]. // TODO add Result/Completable reference in all fun's descriptions
     *
     * @param identities Identities.
     *
     * @return [FindUsersResult] with found users.
     */
    fun findCachedUsers(identities: List<String>): Result<FindUsersResult> =
            searchWorker.findCachedUsers(identities)

    /**
     * Returns card from local storage for given [identity].
     *
     * @param identity Identity.
     *
     * @return [Card] if it exists, *null* otherwise.
     */
    fun findCachedUser(identity: String): Result<Card?> =
            searchWorker.findCachedUser(identity)

    /**
     * Retrieves users Cards from the Virgil Cloud or local storage if exists.
     *
     * @param identities Array of identities to find.
     * @param forceReload Will not use local cached cards if *true*.
     *
     * @return [FindUsersResult] with found users.
     */
    fun findUsers(identities: List<String>, forceReload: Boolean = false): Result<FindUsersResult> =
            searchWorker.findUsers(identities, forceReload)

    /**
     * Retrieves user Card from the Virgil Cloud or local storage if exists.
     *
     * @param identity Identity to find.
     * @param forceReload Will not use local cached card if *true*.
     *
     * @return [Card] that corresponds to provided [identity].
     */
    fun findUser(identity: String, forceReload: Boolean = false): Result<Card> =
            searchWorker.findUser(identity, forceReload)

    /**
     * Retrieves user public key from the cloud for encryption/verification operations.
     *
     * Searches for public key with specified [identity] and returns map of [String] ->
     * [PublicKey] in [onResultListener] callback or [Throwable] if something went wrong.
     *
     * [PublicKeyNotFoundException] will be thrown if public key wasn't found.
     *
     * Can be called only if private key is on the device, otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * @throws PrivateKeyNotFoundException
     * @throws PublicKeyDuplicateException
     */
    @Deprecated("Use findUser instead.") // TODO add replaceWith
    fun lookupPublicKeys(identity: String): Result<LookupResult> =
            searchWorker.lookupPublicKey(identity)

    /**
     * Retrieves user public keys from the cloud for encryption/verification operations.
     *
     * Searches for public keys with specified [identities] and returns map of [String] ->
     * [PublicKey] in [onResultListener] callback or [Throwable] if something went wrong.
     *
     * [PublicKeyNotFoundException] will be thrown for the first not found public key.
     * [EThreeCore.register]
     *
     * Can be called only if private key is on the device, otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @throws PrivateKeyNotFoundException
     * @throws PublicKeyDuplicateException
     */
    @Deprecated("Use findUsers instead.") // TODO add replaceWith
    fun lookupPublicKeys(identities: List<String>): Result<LookupResult> =
            searchWorker.lookupPublicKeys(identities)

    /**
     * Encrypts the user's private key using the user's [password] and backs up the encrypted
     * private key to Virgil's cloud. This enables users to log in from other devices and have
     * access to their private key to decrypt data.
     *
     * Encrypts loaded from private keys local storage user's *Private key* using *Public key*
     * that is generated based on provided [password] after that backs up encrypted user's
     * *Private key* to the Virgil's cloud storage.
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws PrivateKeyNotFoundException
     * @throws BackupKeyException
     */
    fun backupPrivateKey(password: String): Completable =
            backupWorker.backupPrivateKey(password)

    /**
     * Pulls user's private key from the Virgil's cloud, decrypts it with *Private key* that
     * is generated based on provided [password] and saves it to the current private keys
     * local storage.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws WrongPasswordException
     * @throws RestoreKeyException
     */
    fun restorePrivateKey(password: String): Completable =
            backupWorker.restorePrivateKey(password)

    /**
     * Changes the password on a backed-up private key.
     *
     * Pulls user's private key from the Virgil's cloud storage, decrypts it with *Private key*
     * that is generated based on provided [oldPassword] after that encrypts user's *Private key*
     * using *Public key* that is generated based on provided [newPassword] and pushes encrypted
     * user's *Private key* to the Virgil's cloud storage.
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws PrivateKeyNotFoundException
     */
    fun changePassword(oldPassword: String,
                       newPassword: String): Completable =
            backupWorker.changePassword(oldPassword, newPassword)

    /**
     * Deletes Private Key stored on Virgil's cloud. This will disable user to log in from
     * other devices.
     *
     * Deletes private key backup using specified [password] and provides [onCompleteListener]
     * callback that will notify you with successful completion or with a [Throwable] if
     * something went wrong.
     *
     * Can be called only if private key is on the device otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws PrivateKeyNotFoundException
     * @throws WrongPasswordException
     */
    @JvmOverloads
    fun resetPrivateKeyBackup(password: String? = null): Completable =
            backupWorker.resetPrivateKeyBackup(password)

    /**
     * Creates group, saves in cloud and locally.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     * @param users Cards of participants. Result of findUsers call.
     *
     * @return New [Group].
     */
    fun createGroup(identifier: Data, users: FindUsersResult): Result<Group> =
            groupWorker.createGroup(identifier, users)

    /**
     * Returns cached local group.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     *
     * @return [Group] if exists, null otherwise.
     */
    fun getGroup(identifier: Data): Group? = groupWorker.getGroup(identifier)

    /**
     * Loads group from cloud, saves locally.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     * @param card Card of group initiator.
     *
     * @return Loaded [Group].
     */
    fun loadGroup(identifier: Data, card: Card): Result<Group> =
            groupWorker.loadGroup(identifier, card)

    /**
     * Deletes group from cloud and local storage.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     */
    fun deleteGroup(identifier: Data): Completable = groupWorker.deleteGroup(identifier)

    /**
     * Creates group, saves in cloud and locally.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     * @param users Cards of participants. Result of findUsers call.
     *
     * @return New [Group].
     */
    fun createGroup(identifier: String, users: FindUsersResult): Result<Group> =
            groupWorker.createGroup(identifier, users)

    /**
     * Returns cached local group.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     *
     * @return [Group] if exists, null otherwise.
     */
    internal fun getGroup(identifier: String): Group? = groupWorker.getGroup(identifier)

    /**
     * Loads group from cloud, saves locally.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     * @param card Card of group initiator.
     *
     * @return Loaded [Group].
     */
    fun loadGroup(identifier: String, card: Card): Result<Group> =
            groupWorker.loadGroup(identifier, card)

    /**
     * Deletes group from cloud and local storage.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     */
    fun deleteGroup(identifier: String): Completable = groupWorker.deleteGroup(identifier)

    /**
     * Signs then encrypts data for group of users.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param data Data to encrypt.
     * @param users Result of findUsers call recipient Cards with Public Keys to sign and encrypt
     * with. Use null to sign and encrypt for self.
     *
     * @return Encrypted Data.
     */
    @JvmOverloads fun encrypt(data: Data, users: FindUsersResult? = null): Data =
            p2pWorker.encrypt(data, users)

    /**
     * Decrypts and verifies data from users.
     *
     * *Important* Requires private key in local storage.
     *
     * @param data Data to decrypt.
     * @param user Sender Card with Public Key to verify with. Use null to decrypt and verify.
     * from self.
     *
     * @return Decrypted Data.
     */
    @JvmOverloads fun decrypt(data: Data, user: Card? = null): Data =
            p2pWorker.decrypt(data, user)

    /**
     * Decrypts and verifies data from users.
     *
     * *Important* Requires private key in local storage.
     *
     * @param data Data to decrypt.
     * @param user Sender Card with Public Key to verify with.
     * @param date Date of encryption to use proper card version.
     *
     * @return Decrypted Data.
     */
    fun decrypt(data: Data, user: Card, date: Date): Data = p2pWorker.decrypt(data, user, date)

    /**
     * Encrypts data stream.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param inputStream Data stream to be encrypted.
     * @param outputStream Stream with encrypted data.
     * @param users Result of findUsers call recipient Cards with Public Keys to sign and encrypt
     * with. Use null to sign and encrypt for self.
     */
    @JvmOverloads fun encrypt(inputStream: InputStream,
                              outputStream: OutputStream,
                              users: FindUsersResult? = null) =
            p2pWorker.encrypt(inputStream, outputStream, users)

    /**
     * Decrypts encrypted stream.
     *
     * *Important* Requires private key in local storage.
     *
     * @param inputStream Stream with encrypted data.
     * @param outputStream Stream with decrypted data.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    fun decrypt(inputStream: InputStream, outputStream: OutputStream) =
            p2pWorker.decrypt(inputStream, outputStream)

    /**
     * Signs then encrypts string for group of users.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param text String to encrypt. String should be *UTF-8* encoded.
     * @param users Result of findUsers call recipient Cards with Public Keys to sign and encrypt
     * with. Use null to sign and encrypt for self.
     *
     * @return Encrypted base64String.
     */
    @JvmOverloads fun encrypt(text: String, users: FindUsersResult? = null): String =
            p2pWorker.encrypt(text, users)

    /**
     * Decrypts and verifies base64 string from users.
     *
     * *Important* Requires private key in local storage.
     *
     * @param text Encrypted String.
     * @param user Sender Card with Public Key to verify with. Use null to decrypt and verify
     * from self.
     *
     * @return Decrypted String.
     */
    @JvmOverloads fun decrypt(text: String, user: Card? = null): String =
            p2pWorker.decrypt(text, user)

    /**
     * Decrypts and verifies base64 string from users.
     *
     * *Important* Requires private key in local storage.
     *
     * @param text Encrypted String.
     * @param user Sender Card with Public Key to verify with.
     * @param date Date of encryption to use proper card version.
     *
     * @return Decrypted String.
     */
    fun decrypt(text: String, user: Card, date: Date): String = p2pWorker.decrypt(text, user, date)

    /**
     * Signs and encrypts data for user.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * @param data Data to encrypt.
     * @param user User Card to encrypt for.
     *
     * @return Encrypted data.
     */
    fun encrypt(data: Data, user: Card): Data = p2pWorker.encrypt(data, user)

    /**
     * Signs and encrypts string for user.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * @param text String to encrypt.
     * @param user User Card to encrypt for.
     *
     * @return Encrypted String.
     */
    fun encrypt(text: String, user: Card): String = p2pWorker.encrypt(text, user)

    /**
     * Encrypts data stream.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * @param inputStream Data stream to be encrypted.
     * @param outputStream Stream with encrypted data.
     * @param user User Card to encrypt for.
     */
    fun encrypt(inputStream: InputStream, outputStream: OutputStream, user: Card) =
            p2pWorker.encrypt(inputStream, outputStream, user)

    // Backward compatibility deprecated methods --------------------------------------------------

    /**
     * Signs then encrypts data for a group of users.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param text String to encrypt.
     * @param lookupResult Result of lookupPublicKeys call recipient PublicKeys to sign and
     * encrypt with.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Use encryptForUsers method instead.") // TODO change to actual fun name
    fun encrypt(text: String, lookupResult: LookupResult): String =
            p2pWorker.encrypt(text, lookupResult)

    /**
     * Signs then encrypts data for a group of users.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param data Data to encrypt
     * @param lookupResult Result of lookupPublicKeys call recipient PublicKeys to sign and
     * encrypt with.
     *
     * @return Encrypted Data.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Use encryptForUsers method instead.")
    @JvmOverloads fun encrypt(data: ByteArray, lookupResult: LookupResult? = null): ByteArray =
            p2pWorker.encrypt(data, lookupResult)

    /**
     * Encrypts data stream for a group of users.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param inputStream Data stream to be encrypted.
     * @param outputStream Stream with encrypted data.
     * @param lookupResult Result of lookupPublicKeys call recipient PublicKeys to sign and
     * encrypt with.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Use encryptForUsers method instead.") // TODO change to actual methods signature
    fun encrypt(inputStream: InputStream,
                outputStream: OutputStream,
                lookupResult: LookupResult) =
            p2pWorker.encrypt(inputStream, outputStream, lookupResult)

    /**
     * Decrypts and verifies encrypted text that is in base64 [String] format.
     *
     * *Important* Automatically includes self key to recipientsKeys.
     *
     * *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param base64String Encrypted String.
     * @param sendersKey Sender PublicKey to verify with.
     *
     * @return Decrypted String.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Use decryptFromUser method instead.")
    fun decrypt(base64String: String, sendersKey: VirgilPublicKey): String =
            p2pWorker.decrypt(base64String, sendersKey)

    /**
     * Decrypts and verifies encrypted data.
     *
     * *Important* Requires private key in local storage.
     *
     * @param data Data to decrypt.
     * @param sendersKey Sender PublicKey to verify with.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Use decryptFromUser method instead.")
    @JvmOverloads fun decrypt(data: ByteArray, sendersKey: VirgilPublicKey? = null): ByteArray =
            p2pWorker.decrypt(data, sendersKey)

    internal fun privateKeyChanged(newCard: Card? = null) {
        val selfKeyPair = keyStorageLocal.load()

        val localGroupStorage = GroupStorageFile(identity, crypto, selfKeyPair, rootPath)
        val ticketStorageCloud = CloudTicketStorage(accessTokenProvider, keyStorageLocal)

        this.groupManager = GroupManager(localGroupStorage,
                                         ticketStorageCloud,
                                         this.keyStorageLocal,
                                         this.lookupManager,
                                         this.crypto)

        if (newCard != null) {
            this.lookupManager.cardStorage.storeCard(newCard)
        }
    }

    internal fun privateKeyDeleted() {
        groupManager?.localGroupStorage?.reset()
        groupManager = null

        lookupManager.cardStorage.reset()
    }

    internal fun computeSessionId(identifier: Data): Data {
        require(identifier.data.size > 10) { "Group Id length should be > 10" }

        val hash = crypto.computeHash(identifier.data, HashAlgorithm.SHA512)
                .sliceArray(IntRange(0, 31))

        return Data(hash)
    }

    internal fun publishCardThenSaveLocal(keyPair: VirgilKeyPair? = null,
                                          previousCardId: String? = null) {
        val virgilKeyPair = keyPair ?: crypto.generateKeyPair()

        val card = if (previousCardId != null) {
            cardManager.publishCard(virgilKeyPair.privateKey,
                                    virgilKeyPair.publicKey,
                                    this.identity,
                                    previousCardId)
        } else {
            cardManager.publishCard(virgilKeyPair.privateKey,
                                    virgilKeyPair.publicKey,
                                    this.identity)
        }

        val privateKeyData = Data(crypto.exportPrivateKey(virgilKeyPair.privateKey))

        keyStorageLocal.store(privateKeyData)
        privateKeyChanged(card)
    }

    companion object {
        private const val THROTTLE_TIMEOUT = 2 * 1000L // 2 seconds
    }
}
