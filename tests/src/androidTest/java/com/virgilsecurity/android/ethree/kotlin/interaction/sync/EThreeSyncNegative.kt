package com.virgilsecurity.android.ethree.kotlin.interaction.sync

import com.virgilsecurity.android.common.data.model.LookupResult
import com.virgilsecurity.android.common.exceptions.CardNotFoundException
import com.virgilsecurity.android.common.exceptions.PrivateKeyNotFoundException
import com.virgilsecurity.android.common.exceptions.RegistrationException
import com.virgilsecurity.android.common.exceptions.UnRegistrationException
import com.virgilsecurity.android.ethree.kotlin.callback.OnCompleteListener
import com.virgilsecurity.android.ethree.kotlin.callback.OnResultListener
import com.virgilsecurity.android.ethree.utils.TestUtils
import com.virgilsecurity.sdk.exception.EmptyArgumentException
import org.junit.Assert
import org.junit.Test
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * EThreeSyncPositive
 */
class EThreeSyncNegative {

    @Test fun register_existing_identity() {
        val cardManager = initCardManager(identity)
        cardManager.publishCard(generateRawCard(identity, cardManager).right)
        val eThree = initEThree(identity)

        val waiter = CountDownLatch(1)
        eThree.register().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Assert.fail("Illegal state")
            }

            override fun onError(throwable: Throwable) {
                Assert.assertTrue(throwable is RegistrationException)
                waiter.countDown()
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
    }

    @Test fun unregister_without_card() {
        var failed = false
        val waiter = CountDownLatch(1)
        eThree.unregister().addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Assert.fail("Unregister should fail when there are no cards published for identity.")
            }

            override fun onError(throwable: Throwable) {
                if (throwable is UnRegistrationException)
                    failed = true

                waiter.countDown()
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        Assert.assertTrue(failed)
    }

    // STE-15_1
    @Test fun backup_key_before_register() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()

        val eThree = initEThree(identity)

        val waiter = CountDownLatch(1)
        var failedToBackup = false
        eThree.backupPrivateKey(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Assert.fail("Illegal State")
            }

            override fun onError(throwable: Throwable) {
                if (throwable is PrivateKeyNotFoundException)
                    failedToBackup = true

                waiter.countDown()
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        Assert.assertTrue(failedToBackup)
    }

    // STE-18_1
    @Test fun reset_key_backup_before_backup() {
        val identity = UUID.randomUUID().toString()
        val password = UUID.randomUUID().toString()
        val eThreeWithPass = initEThree(identity)

        TestUtils.pause()

        val waiter = CountDownLatch(1)
        var failedToReset = false
        eThreeWithPass.resetPrivateKeyBackup(password).addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                Assert.fail("Illegal state")
            }

            override fun onError(throwable: Throwable) {
                if (throwable is PrivateKeyNotFoundException)
                    failedToReset = true

                waiter.countDown()
            }
        })
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
        Assert.assertTrue(failedToReset)

        TestUtils.pause()

        val syncKeyStorage = initSyncKeyStorage(identity, password)
        Assert.assertFalse(syncKeyStorage.exists(identity))
    }

    @Test fun restore_private_key_before_backup() {

    }

    // STE-Auth-12
    @Test fun rotate_without_published_card() {
        val eThree = initEThree(identity)

        val waiter = CountDownLatch(1)
        eThree.rotatePrivateKey().addCallback(
            object : OnCompleteListener {
                override fun onSuccess() {
                    Assert.fail("Illegal state")
                }

                override fun onError(throwable: Throwable) {
                    Assert.assertTrue(throwable is CardNotFoundException)
                    waiter.countDown()
                }
            }
        )
        waiter.await(TestUtils.THROTTLE_TIMEOUT, TimeUnit.SECONDS)
    }

    @Test fun change_password_without_backup() {

    }

    //STE-2
    @Test fun lookup_zero_users() {
        eThree.lookupPublicKeys(listOf())
                .addCallback(object : OnResultListener<LookupResult> {
                    override fun onSuccess(result: LookupResult) {
                        Assert.fail("Illegal State")
                    }

                    override fun onError(throwable: Throwable) {
                        Assert.assertTrue(throwable is EmptyArgumentException)
                    }
                })
    }
}
