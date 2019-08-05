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

package com.virgilsecurity.android.ethree.interaction

import android.content.Context
import com.virgilsecurity.android.common.Const.NO_CONTEXT
import com.virgilsecurity.android.common.callback.OnGetTokenCallback
import com.virgilsecurity.android.common.interaction.EThreeCore
import com.virgilsecurity.android.common.interaction.KeyManagerLocal
import com.virgilsecurity.android.common.model.Result
import com.virgilsecurity.sdk.jwt.Jwt
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider

/**
 * [EThree] class simplifies work with Virgil Services to easily implement End to End Encrypted
 * communication.
 */
class EThree
private constructor(
        context: Context,
        tokenProvider: AccessTokenProvider
) : EThreeCore(tokenProvider) {

    override val keyManagerLocal: KeyManagerLocal

    init {
        keyManagerLocal =
                KeyManagerLocalDefault(tokenProvider.getToken(NO_CONTEXT).identity, context)
    }

    companion object {
        /**
         * Current method allows you to initialize EThree helper class. To do this you
         * should provide [onGetTokenCallback] that must return Json Web Token string
         * representation with identity of the user which will use this class.
         * In [onResultListener] you will receive instance of [EThreeCore] class or an [Throwable]
         * if something went wrong.
         *
         * To start execution of the current function, please see [Result] description.
         */
        @JvmStatic fun initialize(context: Context,
                                  onGetTokenCallback: OnGetTokenCallback) = object : Result<EThree> {
            override fun get(): EThree {
                val tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback {
                    Jwt(onGetTokenCallback.onGetToken())
                })

                // Just check whether we can get token, otherwise there's no reasons to
                // initialize EThree. We have caching JWT provider, so sequential calls
                // won't take much time, as token will be cached after first call.
                tokenProvider.getToken(NO_CONTEXT)
                return EThree(context, tokenProvider)
            }
        }
    }
}
