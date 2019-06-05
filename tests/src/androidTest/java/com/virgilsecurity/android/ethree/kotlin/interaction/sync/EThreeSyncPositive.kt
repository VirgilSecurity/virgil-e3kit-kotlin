package com.virgilsecurity.android.ethree.kotlin.interaction.sync

import com.virgilsecurity.android.common.data.model.LookupResult
import com.virgilsecurity.android.common.exceptions.BackupKeyException
import com.virgilsecurity.android.common.exceptions.RestoreKeyException
import com.virgilsecurity.android.common.exceptions.WrongPasswordException
import com.virgilsecurity.android.ethree.kotlin.callback.OnCompleteListener
import com.virgilsecurity.android.ethree.kotlin.callback.OnGetTokenCallback
import com.virgilsecurity.android.ethree.kotlin.callback.OnResultListener
import com.virgilsecurity.android.ethree.kotlin.interaction.EThree
import com.virgilsecurity.android.ethree.utils.TestConfig
import com.virgilsecurity.android.ethree.utils.TestUtils
import com.virgilsecurity.keyknox.KeyknoxManager
import com.virgilsecurity.keyknox.client.KeyknoxClient
import com.virgilsecurity.keyknox.cloud.CloudKeyStorage
import com.virgilsecurity.keyknox.crypto.KeyknoxCrypto
import com.virgilsecurity.keyknox.storage.SyncKeyStorage
import com.virgilsecurity.pythia.brainkey.BrainKey
import com.virgilsecurity.pythia.brainkey.BrainKeyContext
import com.virgilsecurity.pythia.client.VirgilPythiaClient
import com.virgilsecurity.pythia.crypto.VirgilPythiaCrypto
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier
import com.virgilsecurity.sdk.client.VirgilCardClient
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto
import com.virgilsecurity.sdk.jwt.JwtGenerator
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyStorage
import org.hamcrest.core.IsEqual
import org.hamcrest.core.IsNot
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.net.URL
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * EThreeSyncPositive
 */
class EThreeSyncPositive {

    private lateinit var identity: String
    private lateinit var jwtGenerator: JwtGenerator
    private lateinit var keyStorage: KeyStorage

    @Before fun setup() {
        TestUtils.pause()

        jwtGenerator = JwtGenerator(
            TestConfig.appId,
            TestConfig.apiKey,
            TestConfig.apiPublicKeyId,
            TimeSpan.fromTime(600, TimeUnit.SECONDS),
            VirgilAccessTokenSigner(TestConfig.virgilCrypto)
        )

        keyStorage = DefaultKeyStorage(TestConfig.DIRECTORY_PATH, TestConfig.KEYSTORE_NAME)
        identity = UUID.randomUUID().toString()
    }

    private fun initAndRegisterEThree(identity: String): EThree {
        val eThree = initEThree(identity)
        eThree.register().execute()
        return eThree
    }

    private fun initEThree(identity: String): EThree {
        return EThree.initialize(TestConfig.context,
                          object : OnGetTokenCallback {
                              override fun onGetToken(): String {
                                  return jwtGenerator.generateToken(
                                      identity)
                                          .stringRepresentation()
                              }
                          }).get()
    }

    private fun initCardManager(identity: String): CardManager {
        val cardCrypto = VirgilCardCrypto()
        return CardManager(
            cardCrypto,
            GeneratorJwtProvider(jwtGenerator, identity),
            VirgilCardVerifier(cardCrypto, false, false),
            VirgilCardClient(TestConfig.virgilBaseUrl + TestConfig.VIRGIL_CARDS_SERVICE_PATH)
        )
    }

    private fun initSyncKeyStorage(identity: String, passwordBrainKey: String): SyncKeyStorage {
        val tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback {
            jwtGenerator.generateToken(identity)
        })
        val brainKeyContext = BrainKeyContext.Builder()
                .setAccessTokenProvider(tokenProvider)
                .setPythiaClient(VirgilPythiaClient(TestConfig.virgilBaseUrl))
                .setPythiaCrypto(VirgilPythiaCrypto())
                .build()
        val keyPair = BrainKey(brainKeyContext).generateKeyPair(passwordBrainKey)

        val syncKeyStorage =
                SyncKeyStorage(
                    identity, keyStorage, CloudKeyStorage(
                        KeyknoxManager(
                            tokenProvider,
                            KeyknoxClient(URL(TestConfig.virgilBaseUrl)),
                            listOf(keyPair.publicKey),
                            keyPair.privateKey,
                            KeyknoxCrypto()
                        )
                    )
                )

        syncKeyStorage.sync()

        return syncKeyStorage
    }

    @Test fun init_and_register() {
        initAndRegisterEThree(identity)
        Assert.assertTrue(keyStorage.exists(identity))

        val card = initCardManager(identity).searchCards(identity)
        Assert.assertNotNull(card)
    }

    @Test fun unregister_with_local_key() {
        val eThree = initAndRegisterEThree(identity)
        Assert.assertTrue(keyStorage.exists(identity))

        val cards = initCardManager(identity).searchCards(identity)
        Assert.assertNotNull(cards)
        Assert.assertEquals(1, cards.size)

        eThree.unregister().execute()
        Assert.assertFalse(keyStorage.exists(identity))

        val cardsUnregistered = initCardManager(identity).searchCards(identity)
        Assert.assertEquals(0, cardsUnregistered.size)
    }

    // STE-15_2-4
    @Test fun backup_key_after_register() {
        val password = UUID.randomUUID().toString()
        val eThree = initAndRegisterEThree(identity)

        TestUtils.pause()

        eThree.backupPrivateKey(password).execute()

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        Assert.assertTrue(syncKeyStorage.exists(identity))
        val retrievedKey = syncKeyStorage.retrieve(identity)
        Assert.assertEquals(TestConfig.virgilCrypto.importPrivateKey(keyStorage.load(identity).value),
                            TestConfig.virgilCrypto.importPrivateKey(retrievedKey.value))

        TestUtils.pause()

        val waiterTwo = CountDownLatch(1)
        var failedToBackup = false
        eThree.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Assert.fail("Illegal State")
            }

            override fun onError(throwable: Throwable) {
                if (throwable is BackupKeyException)
                    failedToBackup = true

                waiterTwo.countDown()
            }
        })
        waiterTwo.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        Assert.assertTrue(failedToBackup)
    }

    // STE-18_2
    @Test fun reset_key_backup_after_backup() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val eThreeWithPass = initAndRegisterEThree(identity)

        TestUtils.pause()

        val waiter = CountDownLatch(1)
        eThreeWithPass.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                Assert.fail(throwable.message)
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

        TestUtils.pause()

        val waiterTwo = CountDownLatch(1)
        var successfulKeyReset = false
        eThreeWithPass.resetPrivateKeyBackup(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                successfulKeyReset = true
                waiterTwo.countDown()
            }

            override fun onError(throwable: Throwable) {
                Assert.fail(throwable.message)
            }
        })
        waiterTwo.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        Assert.assertTrue(successfulKeyReset)

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        Assert.assertFalse(syncKeyStorage.exists(identity))
    }

    // STE-16
    @Test fun restore_private_key() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()

        val eThreeWithPass = initAndRegisterEThree(identity)

        TestUtils.pause()

        val waiter = CountDownLatch(1)
        eThreeWithPass.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                Assert.fail(throwable.message)
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

        TestUtils.pause()

        eThreeWithPass.cleanup()
        val waiterTwo = CountDownLatch(1)
        var restoreSuccessful = false
        eThreeWithPass.restorePrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                restoreSuccessful = true
                waiterTwo.countDown()
            }

            override fun onError(throwable: Throwable) {
                Assert.fail(throwable.message)
            }
        })
        waiterTwo.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        Assert.assertTrue(restoreSuccessful)

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        Assert.assertTrue(syncKeyStorage.exists(identity))
        val retrievedKey = syncKeyStorage.retrieve(identity)
        Assert.assertEquals(TestConfig.virgilCrypto.importPrivateKey(keyStorage.load(identity).value),
                            TestConfig.virgilCrypto.importPrivateKey(retrievedKey.value))

        TestUtils.pause()

        val waiterThree = CountDownLatch(1)
        var failedToRestore = false
        eThreeWithPass.restorePrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Assert.fail("Illegal state")
            }

            override fun onError(throwable: Throwable) {
                if (throwable is RestoreKeyException)
                    failedToRestore = true

                waiterThree.countDown()
            }
        })
        waiterThree.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        Assert.assertTrue(failedToRestore)
    }

    // STE-Auth-14
    @Test fun rotate_keys() {
        val cardManager = initCardManager(identity)
        val publishPair = generateRawCard(identity, cardManager)
        cardManager.publishCard(publishPair.right)
        val eThree = initEThree(identity)

        val waiterTwo = CountDownLatch(1)
        eThree.rotatePrivateKey().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                waiterTwo.countDown()
            }

            override fun onError(throwable: Throwable) {
                Assert.fail(throwable.message)
            }
        })
        waiterTwo.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

        Assert.assertTrue(cardManager.searchCards(identity).last().previousCardId != null)

        val newKeyData = keyStorage.load(identity).value
        val oldKeyData = publishPair.left.privateKey.privateKey.exportPrivateKey()
        Assert.assertThat(oldKeyData, IsNot.not(IsEqual.equalTo(newKeyData)))
    }

    // STE-17
    @Test fun change_password() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val passwordNew = UUID.randomUUID().toString()

        val eThreeWithPass = initAndRegisterEThree(identity)

        TestUtils.pause()

        val waiter = CountDownLatch(1)
        eThreeWithPass.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                waiter.countDown()
            }

            override fun onError(throwable: Throwable) {
                Assert.fail(throwable.message)
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)

        TestUtils.pause()

        val waiterOne = CountDownLatch(1)
        var passwordChanged = false
        eThreeWithPass.changePassword(password, passwordNew)
                .addCallback(object : OnCompleteListener {
                    override fun onSuccess() {
                        passwordChanged = true
                        waiterOne.countDown()
                    }

                    override fun onError(throwable: Throwable) {
                        Assert.fail(throwable.message)
                    }
                })
        waiterOne.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        Assert.assertTrue(passwordChanged)

        TestUtils.pause()

        eThreeWithPass.cleanup()
        val waiterTwo = CountDownLatch(1)
        var failedWithOldPassword = false
        eThreeWithPass.restorePrivateKey(password).addCallback(object : OnCompleteListener {

            override fun onSuccess() {
                Assert.fail("Illegal State")
            }

            override fun onError(throwable: Throwable) {
                if (throwable is WrongPasswordException)
                    failedWithOldPassword = true

                waiterTwo.countDown()
            }
        })
        waiterTwo.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        Assert.assertTrue(failedWithOldPassword)

        TestUtils.pause()

        val waiterThree = CountDownLatch(1)
        var successWithNewPassword = false
        eThreeWithPass.restorePrivateKey(passwordNew).addCallback(object : OnCompleteListener {

            override fun onSuccess() {
                successWithNewPassword = true
                waiterThree.countDown()
            }

            override fun onError(throwable: Throwable) {
                Assert.fail(throwable.message)
            }
        })
        waiterThree.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        Assert.assertTrue(successWithNewPassword)
    }

    @Test fun lookup_one_user() {
        val identityOne = UUID.randomUUID().toString()
        val cardManagerOne = initCardManager(identityOne)
        val publishedCardOne = cardManagerOne.publishCard(generateRawCard(identityOne,
                                                                          cardManagerOne).right)

        eThree.lookupPublicKeys(identityOne)
                .addCallback(object : OnResultListener<LookupResult> {
                    override fun onSuccess(result: LookupResult) {
                        Assert.assertTrue(result.isNotEmpty() && result.size == 1)
                        Assert.assertEquals(publishedCardOne.publicKey,
                                            result[identityOne])
                    }

                    override fun onError(throwable: Throwable) {
                        Assert.fail(throwable.message)
                    }
                })
    }

    // STE-1
    @Test fun lookup_multiply_users() {
        var foundCards = false

        // Card one
        val identityOne = UUID.randomUUID().toString()
        val cardManagerOne = initCardManager(identityOne)
        val publishedCardOne = cardManagerOne.publishCard(generateRawCard(identityOne,
                                                                          cardManagerOne).right)
        // Card two
        val identityTwo = UUID.randomUUID().toString()
        val cardManagerTwo = initCardManager(identityTwo)
        val publishedCardTwo = cardManagerTwo.publishCard(generateRawCard(identityTwo,
                                                                          cardManagerTwo).right)
        // Card three
        val identityThree = UUID.randomUUID().toString()
        val cardManagerThree = initCardManager(identityThree)
        val publishedCardThree = cardManagerThree.publishCard(generateRawCard(identityThree,
                                                                              cardManagerThree).right)

        eThree.lookupPublicKeys(listOf(identityOne, identityTwo, identityThree))
                .addCallback(object : OnResultListener<LookupResult> {

                    override fun onSuccess(result: LookupResult) {
                        Assert.assertTrue(result.isNotEmpty() && result.size == 3)
                        if (result[identityOne] == publishedCardOne.publicKey
                            && result[identityTwo] == publishedCardTwo.publicKey
                            && result[identityThree] == publishedCardThree.publicKey) {
                            foundCards = true
                        }

                        Assert.assertTrue(foundCards)
                    }

                    override fun onError(throwable: Throwable) {
                        Assert.fail(throwable.message)
                    }
                })
    }
}
