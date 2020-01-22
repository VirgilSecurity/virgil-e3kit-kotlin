/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
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

package com.virgilsecurity.android.ethreeenclave.interaction

import android.content.Context
import com.virgilsecurity.android.common.EThreeCore
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.callback.OnKeyChangedCallback
import com.virgilsecurity.android.common.model.DerivedPasswords
import com.virgilsecurity.android.common.util.Const.NO_CONTEXT
import com.virgilsecurity.android.common.util.Defaults
import com.virgilsecurity.android.ethreeenclave.interaction.model.EThreeParamsEnclave
import com.virgilsecurity.common.model.Result
import com.virgilsecurity.sdk.androidutils.storage.AndroidKeyEntry
import com.virgilsecurity.sdk.androidutils.storage.AndroidKeyStorage
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.KeyPairType
import com.virgilsecurity.sdk.crypto.exceptions.KeyStorageException
import com.virgilsecurity.sdk.jwt.Jwt
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.storage.DefaultKeyStorage
import com.virgilsecurity.sdk.storage.KeyStorage

/**
 * [EThree] class simplifies work with Virgil Services to easily implement End to End Encrypted
 * communication.
 */
class EThree
@JvmOverloads constructor(
        identity: String,
        tokenCallback: OnGetTokenCallback,
        context: Context,
        alias: String = "VirgilAndroidKeyStorage",
        isAuthenticationRequired: Boolean = true,
        keyValidityDuration: Int = 60 * 5, // 5 min
        keyChangedCallback: OnKeyChangedCallback? = null,
        keyPairType: KeyPairType = Defaults.keyPairType,
        enableRatchet: Boolean = Defaults.enableRatchet,
        keyRotationInterval: TimeSpan = Defaults.keyRotationInterval
) : EThreeCore(identity,
               tokenCallback,
               keyChangedCallback,
               keyPairType,
               enableRatchet,
               keyRotationInterval,
               context) {

    override val keyStorage: KeyStorage

    init {
        synchronized(this@EThree) {
            keyStorage = AndroidKeyStorage.Builder(alias)
                    .isAuthenticationRequired(isAuthenticationRequired)
                    .withKeyValidityDuration(keyValidityDuration)
                    .onPath(context.filesDir.absolutePath)
                    .build()

            // Migration from old storage to new
            val keyStorageDefault = DefaultKeyStorage(context.filesDir.absolutePath, KEYSTORE_NAME)
            keyStorageDefault.names().forEach { name ->
                val keyEntry = keyStorageDefault.load(name)

                if (keyEntry.meta.isEmpty()) {
                    val keyEntryAndroid = AndroidKeyEntry(name, keyEntry.value).apply {
                        meta = mapOf("Migrated" to "true")
                    }

                    // If any error happens - restore state of storages.
                    try {
                        keyStorage.store(keyEntryAndroid)
                    } catch (throwable: Throwable) {
                        keyStorage.names().forEach { keyStorage.delete(it) }

                        throw KeyStorageException("Error while migrating keys from legacy key "
                                                  + "storage to the new one. All keys are restored in legacy key storage.")
                    }
                }
            }

            // If migration was successful - remove keys from old storage.
            keyStorageDefault.names().forEach { keyStorageDefault.delete(it) }
        }

        initializeCore()
    }

    constructor(params: EThreeParamsEnclave) : this(params.identity,
                                                    params.tokenCallback,
                                                    params.context,
                                                    params.alias,
                                                    params.isAuthenticationRequired,
                                                    params.keyValidityDuration,
                                                    params.keyChangedCallback,
                                                    params.keyPairType,
                                                    params.enableRatchet,
                                                    params.keyRotationInterval)

    @JvmOverloads constructor(
            identity: String,
            tokenCallback: () -> String,
            context: Context,
            alias: String = "VirgilAndroidKeyStorage",
            isAuthenticationRequired: Boolean = true,
            keyValidityDuration: Int = 60 * 5, // 5 min
            keyChangedCallback: OnKeyChangedCallback? = null,
            keyPairType: KeyPairType = Defaults.keyPairType,
            enableRatchet: Boolean = Defaults.enableRatchet,
            keyRotationInterval: TimeSpan = Defaults.keyRotationInterval
    ) : this(identity,
             object : OnGetTokenCallback {
                 override fun onGetToken(): String {
                     return tokenCallback()
                 }

             },
             context,
             alias,
             isAuthenticationRequired,
             keyValidityDuration,
             keyChangedCallback,
             keyPairType,
             enableRatchet,
             keyRotationInterval)

    companion object {
        /**
         * Current method allows you to initialize EThree helper class. To do this you
         * should provide [onGetTokenCallback] that must return Json Web Token string
         * representation with identity of the user which will use this class.
         * In [onResultListener] you will receive instance of [EThreeCore] class or an [Throwable]
         * if something went wrong.
         *
         * To start execution of the current function, please see [Result] description.
         *
         * May throw [KeyStorageException] if error occurred while initializing Android Key Storage
         * or on keys migration failure.
         */
        @Throws(KeyStorageException::class)
        @JvmOverloads
        @JvmStatic
        @Deprecated("Use constructor instead")
        fun initialize(context: Context,
                       onGetTokenCallback: OnGetTokenCallback,
                       alias: String = "VirgilAndroidKeyStorage",
                       isAuthenticationRequired: Boolean = true,
                       keyValidityDuration: Int = 60 * 5, // 5 min
                       keyChangedCallback: OnKeyChangedCallback? = null
        ) = object : Result<EThree> {
            override fun get(): EThree {
                val tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback {
                    Jwt(onGetTokenCallback.onGetToken())
                })

                // Just check whether we can get token, otherwise there's no reasons to
                // initialize EThree. We have caching JWT provider, so sequential calls
                // won't take much time, as token will be cached after first call.
                val token = tokenProvider.getToken(NO_CONTEXT)

                val eThree = EThree(token.identity,
                                    onGetTokenCallback,
                                    context,
                                    alias,
                                    isAuthenticationRequired,
                                    keyValidityDuration,
                                    keyChangedCallback)
                eThree.initializeCore()

                return eThree
            }
        }

        @JvmStatic
        fun derivePasswords(password: String) = derivePasswordsInternal(password)

        private const val KEYSTORE_NAME = "virgil.keystore"
    }
}
