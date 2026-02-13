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

package com.virgilsecurity.android.common.snippet;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.virgilsecurity.android.common.callback.OnGetTokenCallback;
import com.virgilsecurity.android.common.model.DerivedPasswords;
import com.virgilsecurity.android.common.model.java.EThreeParams;
import com.virgilsecurity.android.common.utils.TestConfig;
import com.virgilsecurity.android.common.utils.TestUtils;
import com.virgilsecurity.android.ethree.interaction.EThree;
import com.virgilsecurity.common.callback.OnCompleteListener;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;

import org.jetbrains.annotations.NotNull;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.UUID;

import static org.junit.Assert.assertNotNull;

/**
 * This test covers snippets that used in documentation.
 */
@RunWith(AndroidJUnit4.class)
public class SnippetsJavaTest {
    private String aliceIdentity;
    private String bobIdentity;
    private EThree aliceEthree;
    private EThree bobEthree;

    @Before
    public void setup() {
        this.aliceIdentity = UUID.randomUUID().toString();
        OnGetTokenCallback aliceCallback = new OnGetTokenCallback() {

            @NotNull
            @Override
            public String onGetToken() {
                return TestUtils.Companion.generateTokenString(aliceIdentity);
            }
        };
        this.aliceEthree = new EThree(aliceIdentity, aliceCallback, TestConfig.Companion.getContext());
        assertNotNull(this.aliceEthree);
        this.aliceEthree.register().execute();

        this.bobIdentity = UUID.randomUUID().toString();
        OnGetTokenCallback bobCallback = new OnGetTokenCallback() {

            @NotNull
            @Override
            public String onGetToken() {
                return TestUtils.Companion.generateTokenString(bobIdentity);
            }
        };
        this.bobEthree = new EThree(bobIdentity, bobCallback, TestConfig.Companion.getContext());
        assertNotNull(this.bobEthree);
        this.bobEthree.register().execute();
    }

    @Test
    public void backup_restore_key() {
        String identity = UUID.randomUUID().toString();
        String keyPassword = UUID.randomUUID().toString();
        String userPassword = UUID.randomUUID().toString();
        OnGetTokenCallback getTokenCallback = new OnGetTokenCallback() {

            @NotNull
            @Override
            public String onGetToken() {
                return TestUtils.Companion.generateTokenString(bobIdentity);
            }
        };
        EThreeParams params = new EThreeParams(identity, getTokenCallback, TestConfig.Companion.getContext());
        EThree eThree = new EThree(params);


        // Java (Back up key) >>

        OnCompleteListener backupListener = new OnCompleteListener() {
            @Override public void onSuccess() {
                // private key backup success
            }

            @Override public void onError(@NotNull Throwable throwable) {
                // Error handling
            }
        };

        // Backup user's private key to the cloud (encrypted using her password).
        // This will enable your user to log in from another device and have access
        // to the same private key there.
        eThree.backupPrivateKey(keyPassword).addCallback(backupListener);

        // << Java (Back up key)


        // Java (Make user's password the backup password) >>

        DerivedPasswords derivedPasswords = EThree.derivePasswords(userPassword);

        // This password should be used for backup/restore PrivateKey
        String backupPassword = derivedPasswords.getBackupPassword();

        // This password should be used for other purposes, e.g user authorization
        String loginPassword = derivedPasswords.getLoginPassword();

        // << Java (Make user's password the backup password)


        assertNotNull(backupPassword);
        assertNotNull(loginPassword);


        // Java (Restore key) >>

        OnCompleteListener restoreListener = new OnCompleteListener() {
            @Override public void onSuccess() {
                // You're done
            }

            @Override public void onError(@NotNull Throwable throwable) {
                // Error handling
            }
        };

        // If user wants to restore her private key from backup in Virgil Cloud.
        // While user in session - key can be removed and restore multiply times (via cleanup/restorePrivateKey functions).
        // To know whether private key is present on device now use hasLocalPrivateKey() function:
        if (!eThree.hasLocalPrivateKey()) {
            eThree.restorePrivateKey(keyPassword).addCallback(restoreListener);
        }

        // << Java (Restore key)


        String oldPassword = keyPassword;
        String newPassword = UUID.randomUUID().toString();


        // Java (Change backup password) >>

        OnCompleteListener changeListener = new OnCompleteListener() {
            @Override public void onSuccess() {
                // You're done
            }

            @Override public void onError(@NotNull Throwable throwable) {
                // Error handling
            }
        };

        // If the user wants to change his password for private key backup
        eThree.changePassword(oldPassword, newPassword).addCallback(changeListener);

        // << Java (Change backup password)


        // Java (Delete backup) >>

        OnCompleteListener resetListener = new OnCompleteListener() {
            @Override public void onSuccess() {
                // You're done
            }

            @Override public void onError(@NotNull Throwable throwable) {
                // Error handling
            }
        };

        // If user wants to delete their account, use the following function
        // to delete their private key
        eThree.resetPrivateKeyBackup().addCallback(resetListener);

        // << Java (Delete backup)
    }

    @Test
    public void backup_restore_key_with_keyName() {
        String identity = UUID.randomUUID().toString();
        String keyName = UUID.randomUUID().toString();
        String keyPassword = UUID.randomUUID().toString();
        String userPassword = UUID.randomUUID().toString();
        OnGetTokenCallback getTokenCallback = new OnGetTokenCallback() {

            @NotNull
            @Override
            public String onGetToken() {
                return TestUtils.Companion.generateTokenString(bobIdentity);
            }
        };
        EThreeParams params = new EThreeParams(identity, getTokenCallback, TestConfig.Companion.getContext());
        EThree eThree = new EThree(params);


        // Java (Back up key) >>

        OnCompleteListener backupListener = new OnCompleteListener() {
            @Override public void onSuccess() {
                // private key backup success
            }

            @Override public void onError(@NotNull Throwable throwable) {
                // Error handling
            }
        };

        // Backup user's private key to the cloud (encrypted using her password).
        // This will enable your user to log in from another device and have access
        // to the same private key there.
        eThree.backupPrivateKey(keyName, keyPassword).addCallback(backupListener);

        // << Java (Back up key)


        // Java (Restore key) >>

        OnCompleteListener restoreListener = new OnCompleteListener() {
            @Override public void onSuccess() {
                // You're done
            }

            @Override public void onError(@NotNull Throwable throwable) {
                // Error handling
            }
        };

        // If user wants to restore her private key from backup in Virgil Cloud.
        // While user in session - key can be removed and restore multiply times (via cleanup/restorePrivateKey functions).
        // To know whether private key is present on device now use hasLocalPrivateKey() function:
        if (!eThree.hasLocalPrivateKey()) {
            eThree.restorePrivateKey(keyName, keyPassword).addCallback(restoreListener);
        }

        // << Java (Restore key)


        String oldPassword = keyPassword;
        String newPassword = UUID.randomUUID().toString();


        // Java (Change backup password) >>

        OnCompleteListener changeListener = new OnCompleteListener() {
            @Override public void onSuccess() {
                // You're done
            }

            @Override public void onError(@NotNull Throwable throwable) {
                // Error handling
            }
        };

        // If the user wants to change his password for private key backup
        eThree.changePassword(keyName, oldPassword, newPassword).addCallback(changeListener);

        // << Java (Change backup password)


        // Java (Delete backup) >>

        OnCompleteListener resetListener = new OnCompleteListener() {
            @Override public void onSuccess() {
                // You're done
            }

            @Override public void onError(@NotNull Throwable throwable) {
                // Error handling
            }
        };

        // If user wants to delete their account, use the following function
        // to delete their private key
        eThree.resetPrivateKeyBackupWithKeyName(keyName).addCallback(resetListener);

        // << Java (Delete backup)
    }

}
