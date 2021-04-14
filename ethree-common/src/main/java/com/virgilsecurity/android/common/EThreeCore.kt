/*
 * Copyright (c) 2015-2021, Virgil Security, Inc.
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
import com.virgilsecurity.android.common.build.VirgilInfo
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.callback.OnKeyChangedCallback
import com.virgilsecurity.android.common.exception.*
import com.virgilsecurity.android.common.manager.GroupManager
import com.virgilsecurity.android.common.manager.LookupManager
import com.virgilsecurity.android.common.manager.TempChannelManager
import com.virgilsecurity.android.common.model.DerivedPasswords
import com.virgilsecurity.android.common.model.FindUsersResult
import com.virgilsecurity.android.common.model.Group
import com.virgilsecurity.android.common.model.LookupResult
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
import com.virgilsecurity.common.extension.toData
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.common.model.Data
import com.virgilsecurity.common.model.Result
import com.virgilsecurity.keyknox.utils.unwrapCompanionClass
import com.virgilsecurity.ratchet.client.RatchetClient
import com.virgilsecurity.ratchet.exception.ProtocolException
import com.virgilsecurity.ratchet.exception.SecureChatException
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
    internal val keyPairType: KeyPairType

    protected val crypto: VirgilCrypto = VirgilCrypto()

    protected abstract val keyStorage: KeyStorage

    val cardManager: CardManager
    val identity: String

    protected constructor(identity: String,
                          getTokenCallback: OnGetTokenCallback,
                          keyChangedCallback: OnKeyChangedCallback?,
                          keyPairType: KeyPairType,
                          enableRatchet: Boolean,
                          keyRotationInterval: TimeSpan,
                          context: Context) {
        logger.fine("Create new EThree instance for $identity")

        this.identity = identity

        val cardCrypto = VirgilCardCrypto(crypto)
        val virgilCardVerifier = VirgilCardVerifier(cardCrypto)
        val httpClient = HttpClient(Const.ETHREE_NAME, VirgilInfo.VERSION)
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

        this.keyPairType = keyPairType
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
        logger.finer("Initialize EThree core")

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
     * @throws EThreeException(EThreeException.Description.PRIVATE_KEY_EXISTS)
     * @throws EThreeException(EThreeException.Description.USER_IS_ALREADY_REGISTERED)
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
     * @throws EThreeException(EThreeException.Description.USER_IS_NOT_REGISTERED) if there's no
     * public key published yet.
     */
    @Synchronized fun unregister(): Completable = authorizationWorker.unregister()

    /**
     * Generates new key pair, publishes new public key for current identity and deprecating old
     * public key, saves private key to the local storage. All data that was encrypted earlier
     * will become undecryptable.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws EThreeException(EThreeException.Description.PRIVATE_KEY_EXISTS)
     * @throws EThreeException(EThreeException.Description.USER_IS_NOT_REGISTERED)
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
     * Can be called only if private key is on the device otherwise
     * [EThreeException.Description.MISSING_PRIVATE_KEY] exception will be thrown.
     *
     * @throws EThreeException.Description.MISSING_PRIVATE_KEY
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
     * @throws FindUsersException(FindUsersException.Description.CARD_WAS_NOT_FOUND) If no cached
     * user was found.
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
     * @throws FindUsersException(FindUsersException.Description.CARD_WAS_NOT_FOUND) If card
     * duplicates was found or card was not found at all.
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
     * @throws FindUsersException(FindUsersException.Description.CARD_WAS_NOT_FOUND) If card
     * duplicates was found or at least one card was not found.
     */
    @JvmOverloads fun findUsers(identities: List<String>,
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
     * @throws FindUsersException(FindUsersException.Description.CARD_WAS_NOT_FOUND) If card
     * duplicates was found or at least one card was not found.
     */
    @JvmOverloads fun findUser(identity: String, forceReload: Boolean = false): Result<Card> =
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
     * [FindUsersException(FindUsersException.Description.CARD_WAS_NOT_FOUND)] will be thrown if
     * public key wasn't found.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @throws FindUsersException(FindUsersException.Description.CARD_WAS_NOT_FOUND)
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
     * [FindUsersException(FindUsersException.Description.CARD_WAS_NOT_FOUND)] will be thrown if
     * public key wasn't found.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @throws FindUsersException(FindUsersException.Description.CARD_WAS_NOT_FOUND)
     */
    @Deprecated("Check 'replace with' section.",
                ReplaceWith("findUsers(List<String>)"))
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
     * Can be called only if private key is on the device otherwise
     * [EThreeException.Description.MISSING_PRIVATE_KEY] exception will be thrown.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws EThreeException.Description.MISSING_PRIVATE_KEY
     * @throws EThreeException.Description.PRIVATE_KEY_BACKUP_EXISTS If private key with current
     * user's identity is already present in Virgil cloud.
     */
    fun backupPrivateKey(password: String): Completable =
            backupWorker.backupPrivateKey(null, password)

    /**
     * Encrypts the user's private key using the user's [password] and backs up the encrypted
     * private key to Virgil's cloud. This enables users to log in from other devices and have
     * access to their private key to decrypt data.
     *
     * Encrypts loaded from private keys local storage user's *Private key* using *Public key*
     * that is generated based on provided [password] after that backs up encrypted user's
     * *Private key* to the Virgil's cloud storage.
     *
     * Can be called only if private key is on the device otherwise
     * [EThreeException.Description.MISSING_PRIVATE_KEY] exception will be thrown.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @param keyName Is a name that would be used to store backup in the cloud.
     *
     * @throws EThreeException.Description.MISSING_PRIVATE_KEY
     * @throws EThreeException.Description.PRIVATE_KEY_BACKUP_EXISTS If private key with current
     * user's identity is already present in Virgil cloud.
     */
    fun backupPrivateKey(keyName: String, password: String): Completable =
            backupWorker.backupPrivateKey(keyName, password)

    /**
     * Pulls user's private key from the Virgil's cloud, decrypts it with *Private key* that
     * is generated based on provided [password] and saves it to the current private keys
     * local storage.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws EThreeException.Description.NO_PRIVATE_KEY_BACKUP If private key backup was not
     * found.
     * @throws EThreeException(EThreeException.Description.WRONG_PASSWORD) If [password] is wrong.
     * @throws EThreeException(EThreeException.Description.PRIVATE_KEY_EXISTS) If private key
     * already present on the device locally.
     */
    fun restorePrivateKey(password: String): Completable =
            backupWorker.restorePrivateKey(null, password)

    /**
     * Pulls user's private key from the Virgil's cloud, decrypts it with *Private key* that
     * is generated based on provided [password] and saves it to the current private keys
     * local storage.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @param keyName Is a name that been used to store backup in the cloud.
     *
     * @throws EThreeException.Description.NO_PRIVATE_KEY_BACKUP If private key backup was not
     * found.
     * @throws EThreeException(EThreeException.Description.WRONG_PASSWORD) If [password] is wrong.
     * @throws EThreeException(EThreeException.Description.PRIVATE_KEY_EXISTS) If private key
     * already present on the device locally.
     */
    fun restorePrivateKey(keyName: String, password: String): Completable =
            backupWorker.restorePrivateKey(keyName, password)

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
     * @throws EThreeException(EThreeException.Description.WRONG_PASSWORD) If [oldPassword] is
     * wrong.
     * @throws EThreeException(EThreeException.Description.SAME_PASSWORD) If [newPassword] is the
     * same as [oldPassword].
     */
    fun changePassword(oldPassword: String,
                       newPassword: String): Completable =
            backupWorker.changePassword(oldPassword, newPassword)

    /**
     * Deletes Private Key stored on Virgil's cloud. This will disable user to log in from
     * other devices.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @throws EThreeException(EThreeException.Description.WRONG_PASSWORD) If [password] is wrong.
     * @throws EThreeException.Description.MISSING_PRIVATE_KEY
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
     * @throws EThreeException(EThreeException.Description.WRONG_PASSWORD) If [password] is wrong.
     * @throws EThreeException.Description.MISSING_PRIVATE_KEY
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
     * @throws GroupException.Description.INVALID_PARTICIPANTS_COUNT If participants count is out
     * of [Group.VALID_PARTICIPANTS_COUNT_RANGE] range.
     */
    @JvmOverloads fun createGroup(identifier: Data, users: FindUsersResult? = null): Result<Group> =
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
     * @throws GroupException.Description.GROUP_WAS_NOT_FOUND If group was not found.
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
    @JvmOverloads
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
     * @throws EThreeException(EThreeException.Description.VERIFICATION_FAILED) If verification
     * of message failed.
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
     * @throws EThreeException(EThreeException.Description.VERIFICATION_FAILED) If verification
     * of message failed.
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
     * @throws EThreeException.Description.MISSING_PRIVATE_KEY
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
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws EThreeException(EThreeException.Description.MISSING_PUBLIC_KEY)
     * @throws rethrows [VirgilCrypto.authEncrypt]
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
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws EThreeException(EThreeException.Description.MISSING_PUBLIC_KEY)
     * @throws EThreeException(EThreeException.Description.STR_TO_DATA_FAILED)
     * @throws rethrows [VirgilCrypto.authEncrypt]
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
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws EThreeException(EThreeException.Description.VERIFICATION_FAILED)
     * @throws rethrows [VirgilCrypto.authDecrypt]
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
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws EThreeException(EThreeException.Description.VERIFICATION_FAILED)
     * @throws rethrows [VirgilCrypto.authDecrypt]
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
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws EThreeException(EThreeException.Description.VERIFICATION_FAILED)
     * @throws EThreeException(EThreeException.Description.STR_TO_DATA_FAILED)
     * @throws rethrows [VirgilCrypto.authDecrypt]
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
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws EThreeException(EThreeException.Description.VERIFICATION_FAILED)
     * @throws EThreeException(EThreeException.Description.STR_TO_DATA_FAILED)
     * @throws rethrows [VirgilCrypto.authDecrypt]
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
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws EThreeException(EThreeException.Description.MISSING_PUBLIC_KEY)
     * @throws EThreeException(EThreeException.Description.STR_TO_DATA_FAILED)
     * @throws rethrows [VirgilCrypto.authEncrypt]
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
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws EThreeException(EThreeException.Description.MISSING_PUBLIC_KEY)
     * @throws rethrows [VirgilCrypto.authEncrypt]
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
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws EThreeException(EThreeException.Description.MISSING_PUBLIC_KEY)
     * @throws rethrows [VirgilCrypto.authEncrypt]
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
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws EThreeException(EThreeException.Description.MISSING_PUBLIC_KEY)
     * @throws rethrows [VirgilCrypto.authEncrypt]
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
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws EThreeException(EThreeException.Description.VERIFICATION_FAILED)
     * @throws rethrows [VirgilCrypto.authDecrypt]
     */
    @JvmOverloads
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
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws EThreeException(EThreeException.Description.VERIFICATION_FAILED)
     * @throws rethrows [VirgilCrypto.authDecrypt]
     */
    fun authDecrypt(inputStream: InputStream,
                    outputStream: OutputStream,
                    user: Card,
                    date: Date) =
            streamsEncryptWorker.authDecrypt(inputStream, outputStream, user, date)

    /**
     * Creates double ratchet channel with user, saves it locally.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @param card Card of participant.
     * @param name Name of channel.
     *
     * @throws EThreeRatchetException(EThreeRatchetException.Description.CHANNEL_ALREADY_EXISTS)
     * @throws EThreeRatchetException(EThreeRatchetException.Description.SELF_CHANNEL_IS_FORBIDDEN)
     * @throws EThreeRatchetException(EThreeRatchetException.Description.RATCHET_IS_DISABLED)
     * @throws EThreeRatchetException(EThreeRatchetException.Description.USER_IS_NOT_USING_RATCHET)
     */
    @JvmOverloads fun createRatchetChannel(card: Card,
                                           name: String? = null): Result<RatchetChannel> =
            ratchetWorker.createRatchetChannel(card, name)

    /**
     * Joins double ratchet channel with user, saves it locally.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @param card Card of initiator.
     * @param name Name of channel.
     *
     * @throws EThreeRatchetException(EThreeRatchetException.Description.CHANNEL_ALREADY_EXISTS)
     * @throws EThreeRatchetException(EThreeRatchetException.Description.SELF_CHANNEL_IS_FORBIDDEN)
     * @throws EThreeRatchetException(EThreeRatchetException.Description.RATCHET_IS_DISABLED)
     * @throws EThreeRatchetException(EThreeRatchetException.Description.NO_INVITE)
     * @throws SecureChatException rethrows [SecureChat.startNewSessionAsReceiver]
     */
    @JvmOverloads fun joinRatchetChannel(card: Card, name: String? = null): Result<RatchetChannel> =
            ratchetWorker.joinRatchetChannel(card, name)

    /**
     * Retrieves a double ratchet channel from the local storage.
     *
     * @throws EThreeRatchetException(EThreeRatchetException.Description.RATCHET_IS_DISABLED)
     */
    @JvmOverloads fun getRatchetChannel(card: Card, name: String? = null): RatchetChannel? =
            ratchetWorker.getRatchetChannel(card, name)

    /**
     * Deletes double ratchet channel.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @param card Card of participant.
     * @param name Name of channel.
     *
     * @throws EThreeRatchetException(EThreeRatchetException.Description.RATCHET_IS_DISABLED)
     */
    @JvmOverloads fun deleteRatchetChannel(card: Card, name: String? = null): Completable =
            ratchetWorker.deleteRatchetChannel(card, name)

    /**
     * Creates channel with unregistered user.
     *
     * - *Important* Temporary key for unregistered user is stored unencrypted on Cloud.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @param identity Identity of unregistered user.
     *
     * @throws TemporaryChannelException(TemporaryChannelException.Description
     * .SELF_CHANNEL_IS_FORBIDDEN)
     * @throws TemporaryChannelException(TemporaryChannelException.Description.USER_IS_REGISTERED)
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws EThreeException(EThreeException.Description.CHANNEL_ALREADY_EXISTS)
     * @throws rethrows [VirgilCrypto.generateKeyPair]
     */
    fun createTemporaryChannel(identity: String): Result<TemporaryChannel> =
            tempChannelWorker.createTemporaryChannel(identity)

    /**
     * Loads temporary channel by fetching temporary key form Cloud.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @param asCreator Specifies whether caller is creator of channel or not.
     * @param identity Identity of participant.
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws TemporaryChannelException(TemporaryChannelException.Description
     * .SELF_CHANNEL_IS_FORBIDDEN)
     * @throws TemporaryChannelException(TemporaryChannelException.Description.CHANNEL_NOT_FOUND)
     * @throws rethrows [VirgilCrypto.importPrivateKey]
     * @throws FindUsersException(FindUsersException.Description.CARD_WAS_NOT_FOUND)
     */
    fun loadTemporaryChannel(asCreator: Boolean, identity: String): Result<TemporaryChannel> =
            tempChannelWorker.loadTemporaryChannel(asCreator, identity)

    /**
     * Returns cached temporary channel.
     *
     * @param identity Identity of participant.
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
     * @throws rethrows [VirgilCrypto.importPrivateKey], [VirgilCrypto.importPublicKey]
     * @throws FindUsersException(FindUsersException.Description.DUPLICATE_CARDS)
     * @throws FindUsersException(FindUsersException.Description.MISSING_CACHED_CARD)
     */
    fun getTemporaryChannel(identity: String): TemporaryChannel? =
            tempChannelWorker.getTemporaryChannel(identity)

    /**
     * Deletes temporary channel from the cloud (if the user is a creator) and from the
     * local storage.
     *
     * To start execution of the current function, please see [Completable] description.
     *
     * @param identity Identity of participant.
     *
     * @throws EThreeException(EThreeException.Description.MISSING_PRIVATE_KEY)
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
     * @throws EThreeException.Description.MISSING_PRIVATE_KEY
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
     * @throws EThreeException.Description.MISSING_PRIVATE_KEY
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
     * @throws EThreeException.Description.MISSING_PRIVATE_KEY
     * @throws CryptoException
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authEncrypt"))
    fun encrypt(inputStream: InputStream,
                outputStream: OutputStream,
                lookupResult: LookupResult) =
            p2pWorker.encrypt(inputStream, outputStream, lookupResult)

    /**
     * Encrypts data stream with a generated key.
     *
     * @param inputStream Data stream to be encrypted.
     * @param inputStreamSize: Int,
     * @param outputStream Stream with encrypted data.
     *
     * @throws CryptoException
     */
    fun encryptShared(inputStream: InputStream,
                      inputStreamSize: Int,
                      outputStream: OutputStream): ByteArray =
            streamsEncryptWorker.encryptShared(inputStream, inputStreamSize, outputStream)

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
     * @throws EThreeException(EThreeException.Description.VERIFICATION_FAILED) If verification
     * of message failed.
     * @throws EThreeException.Description.MISSING_PRIVATE_KEY
     * @throws CryptoException
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    fun decrypt(base64String: String, sendersKey: VirgilPublicKey): String =
            p2pWorker.decrypt(base64String, sendersKey)

    /**
     * Decrypts data stream.
     *
     * *Important* Requires private key in local storage, if senderPublicKey is not given
     *
     * @param inputStream Stream to be decrypted.
     * @param outputStream Stream with decrypted data.
     * @param privateKeyData Serialized private key to decrypt stream.
     * @param senderPublicKey Sender Public Key to verify with, if null then self public key is used.
     *
     * @throws CryptoException
     */
    fun decryptShared(inputStream: InputStream,
                      outputStream: OutputStream,
                      privateKeyData: ByteArray,
                      senderPublicKey: VirgilPublicKey?) =
            streamsEncryptWorker.decryptShared(inputStream, outputStream, privateKeyData, senderPublicKey)

    /**
     * Decrypts data stream.
     *
     * @param inputStream Stream to be decrypted.
     * @param outputStream Stream with decrypted data.
     * @param privateKeyData Serialized private key to decrypt stream.
     * @param senderCard Sender Card with Public Key to verify with.
     *
     * @throws CryptoException
     */
    fun decryptShared(inputStream: InputStream,
                      outputStream: OutputStream,
                      privateKeyData: ByteArray,
                      senderCard: Card) =
            streamsEncryptWorker.decryptShared(inputStream, outputStream, privateKeyData, senderCard.publicKey)

    /**
     * Decrypts and verifies encrypted data.
     *
     * - *Important* Requires private key in local storage.
     *
     * @param data Data to decrypt.
     * @param sendersKey Sender PublicKey to verify with.
     *
     * @throws EThreeException(EThreeException.Description.VERIFICATION_FAILED) If verification
     * of message failed.
     * @throws EThreeException.Description.MISSING_PRIVATE_KEY
     * @throws CryptoException
     */
    @Deprecated("Check 'replace with' section.", ReplaceWith("authDecrypt"))
    @JvmOverloads fun decrypt(data: ByteArray, sendersKey: VirgilPublicKey? = null): ByteArray =
            p2pWorker.decrypt(data, sendersKey)

    data class PrivateKeyChangedParams(val card: Card, val isNew: Boolean)

    internal fun privateKeyChanged(params: PrivateKeyChangedParams? = null) {
        logger.finer("Private key changed")
        if (params != null) {
            logger.finest("Store card in card storage")
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
        logger.finer("Private key deleted")
        lookupManager.cardStorage.reset()
        groupManager?.localGroupStorage?.reset()
        tempChannelManager?.localStorage?.reset()

        groupManager = null
        tempChannelManager = null
        secureChat = null
        timer = null
    }

    internal fun computeSessionId(identifier: Data): Data {
        if (identifier.value.size <= 10)
            throw GroupException(GroupException.Description.SHORT_GROUP_ID)

        val hash = crypto.computeHash(identifier.value, HashAlgorithm.SHA512)
                .sliceArray(IntRange(0, 31)).toData()

        return hash
    }

    internal fun publishCardThenSaveLocal(keyPair: VirgilKeyPair? = null,
                                          previousCardId: String? = null) {
        val virgilKeyPair = keyPair ?: crypto.generateKeyPair(this.keyPairType)

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

        val privateKeyData = crypto.exportPrivateKey(virgilKeyPair.privateKey).toData()

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
                                                this.keyPairType,
                                                accessTokenProvider,
                                                localKeyStorage,
                                                lookupManager,
                                                keyPair,
                                                rootPath)
    }

    private fun setupRatchet(params: PrivateKeyChangedParams? = null, keyPair: VirgilKeyPair) {
        logger.fine("Setup Ratchet")
        if (!enableRatchet) throw EThreeRatchetException(EThreeRatchetException.Description.RATCHET_IS_DISABLED)

        if (params != null) {
            logger.finer("Setup Ratchet with params. isNew = ${params.isNew}")
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
            logger.finer("Setup Ratchet without params")
            val card = findCachedUser(this.identity).get() ?: throw EThreeRatchetException(
                EThreeRatchetException.Description.NO_SELF_CARD_LOCALLY
            )

            val chat = setupSecureChat(keyPair, card)

            scheduleKeysRotation(chat, startFromNow = true)
        }
    }

    private fun setupSecureChat(keyPair: VirgilKeyPair, card: Card): SecureChat {
        val ratchetClient = RatchetClient(product = Const.ETHREE_NAME, version = VirgilInfo.VERSION)
        val context = SecureChatContext(card,
                                        keyPair,
                                        this.accessTokenProvider,
                                        rootPath,
                                        ratchetClient = ratchetClient)

        val chat = SecureChat(context)
        this.secureChat = chat

        return chat
    }

    private fun scheduleKeysRotation(chat: SecureChat, startFromNow: Boolean) {
        logger.finer("Schedule keys rotation. Start from now = $startFromNow")
        val secureChat = getSecureChat()

        this.timer = RepeatingTimer(this.keyRotationInterval, startFromNow, object : TimerTask() {
            override fun run() {
                logger.info("Key rotation started")

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

        /**
         * Derives different passwords for login and for backup from the one provided.
         *
         * @param password Password to derive from.
         */
        @JvmStatic fun derivePasswordsInternal(password: String): DerivedPasswords {
            val passwordData = password.toByteArray(Charsets.UTF_8)
            val crypto = VirgilCrypto()

            val hash1 = crypto.computeHash(passwordData, HashAlgorithm.SHA256)
            val hash2 = crypto.computeHash(hash1, HashAlgorithm.SHA512)

            val loginPassword = hash2.sliceArray(0 until 32).toData().toBase64String()
            val backupPassword = hash2.sliceArray(32 until 64).toData().toBase64String()

            return DerivedPasswords(loginPassword, backupPassword)
        }
    }
}
