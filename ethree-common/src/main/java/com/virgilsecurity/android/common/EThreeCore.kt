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
import com.google.gson.Gson
import com.virgilsecurity.android.common.build.VersionVirgilAgent
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.callback.OnKeyChangedCallback
import com.virgilsecurity.android.common.exception.*
import com.virgilsecurity.android.common.manager.GroupManager
import com.virgilsecurity.android.common.manager.LookupManager
import com.virgilsecurity.android.common.manager.TempChannelManager
import com.virgilsecurity.android.common.model.*
import com.virgilsecurity.android.common.model.ratchet.RatchetChannel
import com.virgilsecurity.android.common.model.temporary.TemporaryChannel
import com.virgilsecurity.android.common.storage.cloud.CloudKeyManager
import com.virgilsecurity.android.common.storage.cloud.CloudRatchetStorage
import com.virgilsecurity.android.common.storage.cloud.CloudTicketStorage
import com.virgilsecurity.android.common.storage.local.FileGroupStorage
import com.virgilsecurity.android.common.storage.local.LocalKeyStorage
import com.virgilsecurity.android.common.storage.sql.SQLCardStorage
import com.virgilsecurity.android.common.util.Const
import com.virgilsecurity.android.common.util.Const.VIRGIL_BASE_URL
import com.virgilsecurity.android.common.util.Const.VIRGIL_CARDS_SERVICE_PATH
import com.virgilsecurity.android.common.util.RepeatingTimer
import com.virgilsecurity.android.common.worker.*
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.common.model.Result
import com.virgilsecurity.keyknox.utils.unwrapCompanionClass
import com.virgilsecurity.ratchet.exception.ProtocolException
import com.virgilsecurity.ratchet.securechat.SecureChat
import com.virgilsecurity.ratchet.securechat.SecureChatContext
import com.virgilsecurity.ratchet.securechat.SecureSession
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.HttpClient
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.jwt.Jwt
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyStorage
import java.io.InputStream
import java.io.OutputStream
import java.util.*
import java.util.logging.Logger

/**
 * [EThreeCore] class simplifies work with Virgil Services to easily implement End to End Encrypted
 * communication.
 */
abstract class EThreeCore {

    private val rootPath: String

    private var accessTokenProvider: AccessTokenProvider
    private var groupManager: GroupManager? = null
    private var tempChannelManager: TempChannelManager? = null
    private var secureChat: SecureChat? = null

    private lateinit var authorizationWorker: AuthorizationWorker
    private lateinit var backupWorker: BackupWorker
    private lateinit var groupWorker: GroupWorker
    private lateinit var p2pWorker: PeerToPeerWorker
    private lateinit var searchWorker: SearchWorker
    private lateinit var ratchetWorker: RatchetWorker
    private lateinit var authEncryptWorker: AuthEncryptWorker
    private lateinit var streamsEncryptWorker: StreamsEncryptWorker
    private lateinit var tempChannelWorker: TempChannelWorker

    internal lateinit var localKeyStorage: LocalKeyStorage
    internal lateinit var cloudRatchetStorage: CloudRatchetStorage

    internal val lookupManager: LookupManager
    internal val cloudKeyManager: CloudKeyManager

    internal val enableRatchet: Boolean
    internal val keyRotationInterval: TimeSpan
    internal var timer: RepeatingTimer? = null

    protected val crypto: VirgilCrypto = VirgilCrypto()

    protected abstract val keyStorage: KeyStorage

    val cardManager: CardManager
    val identity: String

    protected constructor(params: EThreeParams) : this(params.identity,
                                                       params.tokenCallback,
                                                       params.changedKeyDelegate,
                                                       params.enableRatchet,
                                                       params.keyRotationInterval,
                                                       params.context)

    /**
     * Initializes [CardManager] with provided in [EThreeCore.initialize] callback
     * [onGetTokenCallback] using [CachingJwtProvider] also initializing [DefaultKeyStorage] with
     * default settings.
     */
    protected constructor(identity: String,
                          getTokenCallback: OnGetTokenCallback,
                          keyChangedCallback: OnKeyChangedCallback?,
                          enableRatchet: Boolean,
                          keyRotationInterval: TimeSpan,
                          context: Context) {

        this.identity = identity

        val cardCrypto = VirgilCardCrypto(crypto)
        val virgilCardVerifier = VirgilCardVerifier(cardCrypto)
        val httpClient = HttpClient(Const.ETHREE_NAME, VersionVirgilAgent.VERSION)
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

        this.enableRatchet = enableRatchet
        this.keyRotationInterval = keyRotationInterval
    }

    /**
     * Should be called on each new instance of `EThreeCore` child objects. Is up to developer.
     *
     * Initialization of workers not in constructor, because they depend on `localKeyStorage` that
     * is available only after child object of `EThreeCore` is constructed.
     */
    protected fun initializeCore() {
        this.localKeyStorage = LocalKeyStorage(identity, keyStorage, crypto)
        this.cloudRatchetStorage = CloudRatchetStorage(accessTokenProvider, localKeyStorage)

        this.authorizationWorker = AuthorizationWorker(cardManager,
                                                       localKeyStorage,
                                                       identity,
                                                       ::publishCardThenSaveLocal,
                                                       ::privateKeyDeleted)
        this.backupWorker = BackupWorker(localKeyStorage,
                                         cloudKeyManager,
                                         ::privateKeyChanged,
                                         lookupManager,
                                         identity)
        this.groupWorker = GroupWorker(identity, crypto, ::getGroupManager, ::computeSessionId)
        this.p2pWorker = PeerToPeerWorker(localKeyStorage, crypto)
        this.searchWorker = SearchWorker(lookupManager)
        this.ratchetWorker = RatchetWorker(identity,
                                           cloudRatchetStorage,
                                           ::getSecureChat,
                                           ::startRatchetSessionAsSender)
        this.authEncryptWorker = AuthEncryptWorker(localKeyStorage, crypto)
        this.streamsEncryptWorker = StreamsEncryptWorker(localKeyStorage, crypto)
        this.tempChannelWorker = TempChannelWorker(identity, lookupManager, ::getTempChannelManager)

        if (localKeyStorage.exists()) {
            privateKeyChanged()
        }

        lookupManager.startUpdateCachedCards()
    }

    internal fun getGroupManager(): GroupManager =
            groupManager ?: throw EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)

    internal fun getTempChannelManager(): TempChannelManager =
            tempChannelManager
            ?: throw EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)

    protected fun getSecureChat(): SecureChat {
        if (!enableRatchet)
            throw EThreeRatchetException(EThreeRatchetException.Description.RATCHET_IS_DISABLED)

        return this.secureChat
               ?: throw EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
    }

    /**
     * Publishes the public key in Virgil's Cards Service in case no public key for current
     * identity is published yet.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws PrivateKeyPresentException
     * @throws AlreadyRegisteredException
     * @throws CryptoException
     */
    @Synchronized
    @JvmOverloads
    fun register(keyPair: VirgilKeyPair? = null): Completable = authorizationWorker.register(keyPair)

    /**
     * Revokes the public key for current *identity* in Virgil's Cards Service. After this operation
     * you can call [EThreeCore.register] again.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws UserNotRegisteredException if there's no public key published yet.
     */
    @Synchronized fun unregister(): Completable = authorizationWorker.unregister()

    /**
     * Generates new key pair, publishes new public key for current identity and deprecating old
     * public key, saves private key to the local storage. All data that was encrypted earlier
     * will become undecryptable.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws PrivateKeyPresentException
     * @throws UserNotRegisteredException
     * @throws CryptoException
     */
    @Synchronized fun rotatePrivateKey(): Completable = authorizationWorker.rotatePrivateKey()

    /**
     * Checks whether the private key is present in the local storage of current device.
     * Returns *true* if the key is present in the local key storage otherwise *false*.
     */
    fun hasLocalPrivateKey(): Boolean = authorizationWorker.hasLocalPrivateKey()

    /**
     * - ! *WARNING* ! If you call this function after [register] without using [backupPrivateKey]
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
     * Retrieves cards from local storage for given [identities].
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @param identities Identities of cards to retrieve.
     * @param checkResult Checks that cards for all identities were found if true.
     *
     * @return [FindUsersResult] with found users.
     *
     * @throws FindUsersException If no cached user was found.
     */
    @JvmOverloads fun findCachedUsers(identities: List<String>,
                                      checkResult: Boolean = true): Result<FindUsersResult> =
            searchWorker.findCachedUsers(identities, checkResult)

    /**
     * Retrieves card from local storage for given [identity].
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @param identity Identity.
     *
     * @return [Card] if it exists, *null* otherwise.
     *
     * @throws FindUsersException If card duplicates was found or card was not found at all.
     */
    fun findCachedUser(identity: String): Result<Card?> =
            searchWorker.findCachedUser(identity)

    /**
     * Retrieves users Cards from the Virgil Cloud or local storage if exists.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @param identities Array of identities to find.
     * @param forceReload Will not use local cached cards if *true*.
     * @param checkResult Checks that cards for all identities were found if true.
     *
     * @return [FindUsersResult] with found users.
     *
     * @throws FindUsersException If card duplicates was found or at least one card was not found.
     */
    fun findUsers(identities: List<String>,
                  forceReload: Boolean = false,
                  checkResult: Boolean = true): Result<FindUsersResult> =
            searchWorker.findUsers(identities, forceReload, checkResult)

    /**
     * Retrieves user Card from the Virgil Cloud or local storage if exists.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @param identity Identity to find.
     * @param forceReload Will not use local cached card if *true*.
     *
     * @return [Card] that corresponds to provided [identity].
     *
     * @throws FindUsersException If card duplicates was found or at least one card was not found.
     */
    fun findUser(identity: String, forceReload: Boolean = false): Result<Card> =
            searchWorker.findUser(identity, forceReload)

    /**
     * Updates local cached cards.
     */
    fun updateCachedUsers(): Completable = searchWorker.updateCachedUsers()

    /**
     * Retrieves user public key from the cloud for encryption/verification operations.
     *
     * Searches for public key with specified [identity] and returns map of [String] ->
     * [PublicKey] in [onResultListener] callback or [Throwable] if something went wrong.
     *
     * [FindUsersException] will be thrown if public key wasn't found.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @throws FindUsersException
     */
    @Deprecated("Check 'replace with' section.",
                ReplaceWith("findUser(String)"))
    fun lookupPublicKeys(identity: String): Result<LookupResult> =
            searchWorker.lookupPublicKey(identity)

    /**
     * Retrieves user public keys from the cloud for encryption/verification operations.
     *
     * Searches for public keys with specified [identities] and returns map of [String] ->
     * [PublicKey] in [onResultListener] callback or [Throwable] if something went wrong.
     *
     * [FindUsersException] will be thrown if public key wasn't found.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @throws FindUsersException
     */
    @Deprecated("Check 'replace with' section.",
                ReplaceWith("findUsers(List<String>)"))
    fun lookupPublicKeys(identities: List<String>): Result<LookupResult> =
            searchWorker.lookupPublicKeys(identities)

    /**
     * Derives different passwords for login and for backup from the one provided.
     *
     * @param password Password to derive from.
     */
    fun derivePasswords(password: String): DerivedPasswords =
            backupWorker.derivePasswords(password)

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
     * @throws BackupKeyException If private key with current user's identity is already present
     * in Virgil cloud.
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
     * @throws NoPrivateKeyBackupException If private key backup was not found.
     * @throws WrongPasswordException If [password] is wrong.
     * @throws PrivateKeyPresentException If private key already present on the device locally.
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
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws WrongPasswordException If [oldPassword] is wrong.
     * @throws ChangePasswordException If [newPassword] is the same as [oldPassword].
     */
    fun changePassword(oldPassword: String,
                       newPassword: String): Completable =
            backupWorker.changePassword(oldPassword, newPassword)

    /**
     * Deletes Private Key stored on Virgil's cloud. This will disable user to log in from
     * other devices.
     *
     * To start execution of the current function, please see [Completable] description. // TODO add this to new func descriptions
     *
     * @throws WrongPasswordException If [password] is wrong.
     * @throws PrivateKeyNotFoundException
     */
    fun resetPrivateKeyBackup(): Completable =
            backupWorker.resetPrivateKeyBackup()

    /**
     * Deletes Private Key stored on Virgil's cloud. This will disable user to log in from
     * other devices.
     *
     * Deletes private key backup using specified [password] and provides [onCompleteListener]
     * callback that will notify you with successful completion or with a [Throwable] if
     * something went wrong.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws WrongPasswordException If [password] is wrong.
     * @throws PrivateKeyNotFoundException
     */
    @Deprecated("Check 'replace with' section.",
                ReplaceWith("Please, use resetPrivateKeyBackup without password instead."))
    fun resetPrivateKeyBackup(password: String): Completable =
            backupWorker.resetPrivateKeyBackup(password)

    /**
     * Creates group, saves in cloud and locally.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     * @param users Cards of participants. Result of findUsers call.
     *
     * @return New [Group].
     *
     * @throws InvalidParticipantsCountGroupException If participants count is out of
     * [Group.VALID_PARTICIPANTS_COUNT_RANGE] range.
     */
    fun createGroup(identifier: Data, users: FindUsersResult? = null): Result<Group> =
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
     * To start execution of the current function, please see [Result] description.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     * @param card Card of group initiator.
     *
     * @return Loaded [Group].
     */
    fun loadGroup(identifier: Data, card: Card): Result<Group> =
            groupWorker.loadGroup(identifier, card)

    /**
     * Deletes group from cloud (if the user is an initiator) and local storage.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     *
     * @throws GroupNotFoundException If group was not found.
     */
    fun deleteGroup(identifier: Data): Completable = groupWorker.deleteGroup(identifier)

    /**
     * Creates group, saves in cloud and locally.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     * @param users Cards of participants. Result of findUsers call.
     *
     * @return New [Group].
     */
    fun createGroup(identifier: String, users: FindUsersResult? = null): Result<Group> =
            groupWorker.createGroup(identifier, users)

    /**
     * Returns cached local group.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     *
     * @return [Group] if exists, null otherwise.
     */
    fun getGroup(identifier: String): Group? = groupWorker.getGroup(identifier)

    /**
     * Loads group from cloud, saves locally.
     *
     * To start execution of the current function, please see [Result] description.
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
     * To start execution of the current function, please see [Completable] description.
     *
     * @param identifier Identifier of group. Should be *> 10* length.
     */
    fun deleteGroup(identifier: String): Completable = groupWorker.deleteGroup(identifier)

    /**
     * Signs then encrypts data for group of users.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * *Note* Avoid key duplication.
     *
     * @param data Data to encrypt.
     * @param users Result of findUsers call recipient Cards with Public Keys to sign and encrypt
     * with. Use null to sign and encrypt for self (Or overloaded method with one param).
     *
     * @return Encrypted Data.
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    @JvmOverloads
    fun encrypt(data: Data, users: FindUsersResult? = null): Data = p2pWorker.encrypt(data, users)

    /**
     * Decrypts and verifies data from users.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param data Data to decrypt.
     * @param user Sender Card with Public Key to verify with. Use null to decrypt and verify.
     * from self (Or overloaded method with one param).
     *
     * @return Decrypted Data.
     *
     * @throws SignatureVerificationException If verification of message failed.
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    @JvmOverloads
    fun decrypt(data: Data, user: Card? = null): Data = p2pWorker.decrypt(data, user)

    /**
     * Decrypts and verifies data from users.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param data Data to decrypt.
     * @param user Sender Card with Public Key to verify with.
     * @param date Date of encryption to use proper card version.
     *
     * @return Decrypted Data.
     *
     * @throws SignatureVerificationException If verification of message failed.
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    fun decrypt(data: Data, user: Card, date: Date): Data = p2pWorker.decrypt(data, user, date)

    /**
     * Encrypts data stream.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * - *Note* Avoid key duplication.
     *
     * @param inputStream Data stream to be encrypted.
     * @param outputStream Stream with encrypted data.
     * @param users Result of findUsers call recipient Cards with Public Keys to sign and encrypt
     * with. Use null to sign and encrypt for self (Or overloaded method with one param).
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    @JvmOverloads
    fun encrypt(inputStream: InputStream,
                outputStream: OutputStream,
                users: FindUsersResult? = null) =
            p2pWorker.encrypt(inputStream, outputStream, users)

    /**
     * Decrypts encrypted stream.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param inputStream Stream with encrypted data.
     * @param outputStream Stream with decrypted data.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    fun decrypt(inputStream: InputStream, outputStream: OutputStream) =
            p2pWorker.decrypt(inputStream, outputStream)

    /**
     * Signs then encrypts string for group of users.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * - *Note* Avoid key duplication.
     *
     * @param text String to encrypt. String should be *UTF-8* encoded.
     * @param users Result of findUsers call recipient Cards with Public Keys to sign and encrypt
     * with. Use null to sign and encrypt for self (Or overloaded method with one param).
     *
     * @return Encrypted base64String.
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    @JvmOverloads
    fun encrypt(text: String, users: FindUsersResult? = null): String =
            p2pWorker.encrypt(text, users)

    /**
     * Decrypts and verifies base64 string from users.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param text Encrypted String.
     * @param user Sender Card with Public Key to verify with. Use null to decrypt and verify
     * from self (Or overloaded method with one param).
     *
     * @return Decrypted String.
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    @JvmOverloads
    fun decrypt(text: String, user: Card? = null): String = p2pWorker.decrypt(text, user)

    /**
     * Decrypts and verifies base64 string from users.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param text Encrypted String.
     * @param user Sender Card with Public Key to verify with.
     * @param date Date of encryption to use proper card version.
     *
     * @return Decrypted String.
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    fun decrypt(text: String, user: Card, date: Date): String = p2pWorker.decrypt(text, user, date)

    /**
     * Signs and encrypts data for user.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param data Data to encrypt.
     * @param user User Card to encrypt for.
     *
     * @return Encrypted data.
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    fun encrypt(data: Data, user: Card): Data = p2pWorker.encrypt(data, user)

    /**
     * Signs and encrypts string for user.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param text String to encrypt.
     * @param user User Card to encrypt for.
     *
     * @return Encrypted String.
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    fun encrypt(text: String, user: Card): String = p2pWorker.encrypt(text, user)

    /**
     * Encrypts data stream.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param inputStream Data stream to be encrypted.
     * @param outputStream Stream with encrypted data.
     * @param user User Card to encrypt for.
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    fun encrypt(inputStream: InputStream, outputStream: OutputStream, user: Card) =
            p2pWorker.encrypt(inputStream, outputStream, user)

    /**
     * Signs then encrypts data (and signature) for user.
     *
     * - *Important* Deprecated decrypt method is unable to decrypt result of this method.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param data Data to encrypt.
     * @param card User Card to encrypt for.
     *
     * @return Encrypted data.
     */
    fun authEncrypt(data: Data, user: Card): Data =
            authEncryptWorker.authEncrypt(data, user)

    /**
     * Signs then encrypts string (and signature) for user.
     *
     * - *Important* Deprecated decrypt method is unable to decrypt result of this method.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param data String to encrypt.
     * @param card User Card to encrypt for.
     *
     * @return Encrypted string.
     */
    fun authEncrypt(text: String, user: Card): String =
            authEncryptWorker.authEncrypt(text, user)

    /**
     * Decrypts data and signature and verifies signature of sender.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param data Data to decrypt.
     * @param user Sender Card with Public Key to verify with.
     * Use null to decrypt and verify from self.
     *
     * @return Decrypted Data.
     */
    @JvmOverloads fun authDecrypt(data: Data, user: Card? = null): Data =
            authEncryptWorker.authDecrypt(data, user)

    /**
     * Decrypts data and signature and verifies signature of sender.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param data Data to decrypt.
     * @param user Sender Card with Public Key to verify with.
     * @param date Date of encryption to use proper card version.
     *
     * @return Decrypted Data.
     */
    fun authDecrypt(data: Data, user: Card, date: Date): Data =
            authEncryptWorker.authDecrypt(data, user, date)

    /**
     * Decrypts base64 string and signature and verifies signature of sender.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param text Encrypted String.
     * @param user Sender Card with Public Key to verify with.
     * Use null to decrypt and verify from self.
     *
     * @return Decrypted String.
     */
    @JvmOverloads fun authDecrypt(text: String, user: Card? = null): String =
            authEncryptWorker.authDecrypt(text, user)

    /**
     * Decrypts base64 string and signature and verifies signature of sender.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param text Encrypted String.
     * @param user Sender Card with Public Key to verify with.
     * @param date Date of encryption to use proper card version.
     *
     * @return Decrypted String.
     */
    fun authDecrypt(text: String, user: Card, date: Date): String =
            authEncryptWorker.authDecrypt(text, user, date)

    /**
     * Signs then encrypts string (and signature) for group of users.
     *
     * - *Important* Deprecated decrypt method is unable to decrypt result of this method.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * - *Note* Avoid key duplication.
     *
     * @param text String to encrypt.
     * @param users Result of findUsers call recipient Cards with Public Keys to sign and
     * encrypt with. Use null to sign and encrypt for self.
     *
     * @return Encrypted base64String.
     */
    @JvmOverloads fun authEncrypt(text: String, users: FindUsersResult? = null): String =
            authEncryptWorker.authEncrypt(text, users)

    /**
     * Signs then encrypts string (and signature) for group of users.
     *
     * - *Important* Deprecated decrypt method is unable to decrypt result of this method.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * - *Note* Avoid key duplication.
     *
     * @param text Data to encrypt.
     * @param users Result of findUsers call recipient Cards with Public Keys to sign and
     * encrypt with. Use null to sign and encrypt for self.
     *
     * @return Encrypted data.
     */
    @JvmOverloads fun authEncrypt(data: Data, users: FindUsersResult? = null): Data =
            authEncryptWorker.authEncrypt(data, users)

    /**
     * Signs then encrypts stream and signature for user.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param inputStream Data stream to be encrypted.
     * @param streamSize
     * @param outputStream Stream with encrypted data
     * @param user User Card to encrypt for.
     */
    fun authEncrypt(inputStream: InputStream,
                    streamSize: Int,
                    outputStream: OutputStream,
                    user: Card) =
            streamsEncryptWorker.authEncrypt(inputStream, streamSize, outputStream, user)

    /**
     * Signs then encrypts stream and signature for users.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * - *Note* Avoid key duplication.
     *
     * @param inputStream Data stream to be encrypted.
     * @param streamSize
     * @param outputStream Stream with encrypted data
     * @param users User Card to encrypt for.
     */
    @JvmOverloads fun authEncrypt(inputStream: InputStream,
                                  streamSize: Int,
                                  outputStream: OutputStream,
                                  users: FindUsersResult? = null) =
            streamsEncryptWorker.authEncrypt(inputStream, streamSize, outputStream, users)

    /**
     * Decrypts stream and signature and verifies signature of sender.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param inputStream Stream with encrypted data.
     * @param outputStream Stream with decrypted data.
     * @param user Sender Card with Public Key to verify with. Use null to decrypt and verify
     * from self.
     */
    fun authDecrypt(inputStream: InputStream, outputStream: OutputStream, user: Card? = null) =
            streamsEncryptWorker.authDecrypt(inputStream, outputStream, user)

    /**
     * Decrypts stream and signature and verifies signature of sender.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param inputStream Stream with encrypted data.
     * @param outputStream Stream with decrypted data.
     * @param user Sender Card with Public Key to verify with. Use null to decrypt and verify
     * from self.
     * @param date Date of encryption to use proper card version.
     */
    fun authDecrypt(inputStream: InputStream,
                    outputStream: OutputStream,
                    user: Card,
                    date: Date) =
            streamsEncryptWorker.authDecrypt(inputStream, outputStream, user, date)

    /**
     * Creates double ratchet channel with user, saves it locally. // TODO add throws to ratchet methods
     *
     * @param card Card of participant.
     * @param name Name of channel.
     */
    @JvmOverloads fun createRatchetChannel(card: Card,
                                           name: String? = null): Result<RatchetChannel> =
            ratchetWorker.createRatchetChannel(card, name)

    /**
     * Joins double ratchet channel with user, saves it locally.
     *
     * @param card Card of initiator.
     * @param name Name of channel.
     */
    @JvmOverloads fun joinRatchetChannel(card: Card, name: String? = null): Result<RatchetChannel> =
            ratchetWorker.joinRatchetChannel(card, name)

    /**
     * Retrieves a double ratchet channel from the local storage.
     */
    @JvmOverloads fun getRatchetChannel(card: Card, name: String? = null): RatchetChannel? =
            ratchetWorker.getRatchetChannel(card, name)

    /**
     * Deletes double ratchet channel.
     *
     * @param card Card of participant.
     * @param name Name of channel.
     */
    @JvmOverloads fun deleteRatchetChannel(card: Card, name: String? = null): Completable =
            ratchetWorker.deleteRatchetChannel(card, name)

    /**
     * Creates channel with unregistered user.
     *
     * - *Important* Temporary key for unregistered user is stored unencrypted on Cloud.
     *
     * @param identity Identity of unregistered user.
     */
    fun createTemporaryChannel(identity: String): Result<TemporaryChannel> =
            tempChannelWorker.createTemporaryChannel(identity)

    /**
     * Loads temporary channel by fetching temporary key form Cloud.
     *
     * @param asCreator Specifies whether caller is creator of channel or not.
     * @param identity Identity of participant.
     */
    fun loadTemporaryChannel(asCreator: Boolean, identity: String): Result<TemporaryChannel> =
            tempChannelWorker.loadTemporaryChannel(asCreator, identity)

    /**
     * Returns cached temporary channel.
     *
     * @param identity Identity of participant.
     */
    fun getTemporaryChannel(identity: String): TemporaryChannel? =
            tempChannelWorker.getTemporaryChannel(identity)

    /**
     * Deletes temporary channel from the cloud (if the user is a creator) and from the
     * local storage.
     *
     * @param identity Identity of participant.
     */
    fun deleteTemporaryChannel(identity: String): Completable =
            tempChannelWorker.deleteTemporaryChannel(identity)

    // Backward compatibility deprecated methods --------------------------------------------------

    /**
     * Signs then encrypts data for a group of users.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * - *Note* Avoid key duplication.
     *
     * @param text String to encrypt.
     * @param lookupResult Result of lookupPublicKeys call recipient PublicKeys to sign and
     * encrypt with.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    fun encrypt(text: String, lookupResult: LookupResult): String =
            p2pWorker.encrypt(text, lookupResult)

    /**
     * Signs then encrypts data for a group of users.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * - *Note* Avoid key duplication.
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
    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    @JvmOverloads fun encrypt(data: ByteArray, lookupResult: LookupResult? = null): ByteArray =
            p2pWorker.encrypt(data, lookupResult)

    /**
     * Encrypts data stream for a group of users.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * - *Note* Avoid key duplication.
     *
     * @param inputStream Data stream to be encrypted.
     * @param outputStream Stream with encrypted data.
     * @param lookupResult Result of lookupPublicKeys call recipient PublicKeys to sign and
     * encrypt with.
     *
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    fun encrypt(inputStream: InputStream,
                outputStream: OutputStream,
                lookupResult: LookupResult) =
            p2pWorker.encrypt(inputStream, outputStream, lookupResult)

    /**
     * Decrypts and verifies encrypted text that is in base64 [String] format.
     *
     * - *Important* Automatically includes self key to recipientsKeys.
     *
     * - *Important* Requires private key in local storage.
     *
     * - *Note* Avoid key duplication.
     *
     * @param base64String Encrypted String.
     * @param sendersKey Sender PublicKey to verify with.
     *
     * @return Decrypted String.
     *
     * @throws SignatureVerificationException If verification of message failed.
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    fun decrypt(base64String: String, sendersKey: VirgilPublicKey): String =
            p2pWorker.decrypt(base64String, sendersKey)

    /**
     * Decrypts and verifies encrypted data.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param data Data to decrypt.
     * @param sendersKey Sender PublicKey to verify with.
     *
     * @throws SignatureVerificationException If verification of message failed.
     * @throws PrivateKeyNotFoundException
     * @throws CryptoException
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    @JvmOverloads fun decrypt(data: ByteArray, sendersKey: VirgilPublicKey? = null): ByteArray =
            p2pWorker.decrypt(data, sendersKey)

    data class PrivateKeyChangedParams(val card: Card, val isNew: Boolean)

    internal fun privateKeyChanged(params: PrivateKeyChangedParams? = null) {
        if (params != null) {
            lookupManager.cardStorage.storeCard(params.card)
        }

        val selfKeyPair = localKeyStorage.retrieveKeyPair()

        setupGroupManager(selfKeyPair)
        setupTempChannelManager(selfKeyPair)

        if (this.enableRatchet) {
            setupRatchet(params, selfKeyPair)
        }
    }

    internal fun privateKeyDeleted() {
        lookupManager.cardStorage.reset()
        groupManager?.localGroupStorage?.reset()
        tempChannelManager?.localStorage?.reset()

        groupManager = null
        tempChannelManager = null
        secureChat = null
        timer = null
    }

    internal fun computeSessionId(identifier: Data): Data {
        if (identifier.value.size <= 10) {
            throw GroupIdTooShortException("Group Id length should be > 10")
        }

        val hash = crypto.computeHash(identifier.value, HashAlgorithm.SHA512)
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

        localKeyStorage.store(privateKeyData)
        privateKeyChanged(PrivateKeyChangedParams(card, isNew = true))
    }

    internal fun startRatchetSessionAsSender(secureChat: SecureChat,
                                             card: Card,
                                             name: String?): SecureSession {
        return try {
            secureChat.startNewSessionAsSender(card, name).get()
        } catch (exception: ProtocolException) {
            if (exception.errorCode == ServiceErrorCodes.NO_KEY_DATA_FOR_USER) {
                throw EThreeRatchetException(
                    EThreeRatchetException.Description.USER_IS_NOT_USING_RATCHET
                )
            } else {
                throw exception
            }
        }
    }

    private fun setupGroupManager(keyPair: VirgilKeyPair) {
        val localGroupStorage = FileGroupStorage(identity, crypto, keyPair, rootPath)
        val ticketStorageCloud = CloudTicketStorage(accessTokenProvider, localKeyStorage)

        this.groupManager = GroupManager(localGroupStorage,
                                         ticketStorageCloud,
                                         this.localKeyStorage,
                                         this.lookupManager)
    }

    private fun setupTempChannelManager(keyPair: VirgilKeyPair) {
        tempChannelManager = TempChannelManager(crypto,
                                                accessTokenProvider,
                                                localKeyStorage,
                                                lookupManager,
                                                keyPair,
                                                rootPath)
    }

    private fun setupRatchet(params: PrivateKeyChangedParams? = null, keyPair: VirgilKeyPair) {
        if (!enableRatchet) throw EThreeRatchetException(EThreeRatchetException.Description.RATCHET_IS_DISABLED)

        if (params != null) {
            val chat = setupSecureChat(keyPair, params.card)

            if (params.isNew) {
                try {
                    chat.reset().execute()
                } catch (exception: ProtocolException) {
                    if (exception.errorCode == ServiceErrorCodes.NO_KEY_DATA_FOR_USER) {
                        // When there're no keys on cloud. Should be fixed on server side.
                        logger.info("No key data found for user. " +
                                    "Should be fixed on server side.")
                    } else {
                        throw exception
                    }
                }

                cloudRatchetStorage.reset()
            }

            logger.info("Key rotation started")
            val logs = chat.rotateKeys().get()
            val logsDescription = Gson().toJson(logs)
            logger.info("Key rotation succeed: $logsDescription")

            scheduleKeysRotation(chat, false)
        } else {
            val card = findCachedUser(this.identity).get() ?: throw EThreeRatchetException(
                EThreeRatchetException.Description.NO_SELF_CARD_LOCALLY
            ) // FIXME should Card be nullable?

            val chat = setupSecureChat(keyPair, card)

            scheduleKeysRotation(chat, startFromNow = true)
        }
    }

    private fun setupSecureChat(keyPair: VirgilKeyPair, card: Card): SecureChat {
        val context = SecureChatContext(card,
                                        keyPair,
                                        this.accessTokenProvider,
                                        rootPath)

        val chat = SecureChat(context)
        this.secureChat = chat

        return chat
    }

    private fun scheduleKeysRotation(chat: SecureChat, startFromNow: Boolean) {
        val secureChat = getSecureChat()

        this.timer = RepeatingTimer(this.keyRotationInterval, startFromNow, object : TimerTask() {
            override fun run() {
                logger.info("\"Key rotation started\"")

                try {
                    val logs = secureChat.rotateKeys().get()
                    val logsDescription = Gson().toJson(logs)
                    logger.info("Key rotation succeed: $logsDescription)")
                } catch (throwable: Throwable) {
                    logger.severe("Key rotation failed: ${throwable.localizedMessage}")
                }
            }
        })

        this.timer?.resume()
    }

    companion object {
        private val logger = Logger.getLogger(unwrapCompanionClass(this.javaClass).name)
    }
}
