/*
 *
 *  * Copyright (c) 2015-2019, Virgil Security, Inc.
 *  *
 *  * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *  *
 *  * All rights reserved.
 *  *
 *  * Redistribution and use in source and binary forms, with or without
 *  * modification, are permitted provided that the following conditions are met:
 *  *
 *  *     (1) Redistributions of source code must retain the above copyright notice, this
 *  *     list of conditions and the following disclaimer.
 *  *
 *  *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *  *     this list of conditions and the following disclaimer in the documentation
 *  *     and/or other materials provided with the distribution.
 *  *
 *  *     (3) Neither the name of virgil nor the names of its
 *  *     contributors may be used to endorse or promote products derived from
 *  *     this software without specific prior written permission.
 *  *
 *  * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 *  * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *  * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

package com.virgilsecurity.android.ethreeenclave

import android.content.Context
import com.virgilsecurity.android.common.Const.NO_CONTEXT
import com.virgilsecurity.android.common.interaction.EThreeCore
import com.virgilsecurity.android.common.interaction.IKeyManagerCloud
import com.virgilsecurity.android.common.interaction.IKeyManagerLocal
import com.virgilsecurity.android.ethree.build.VersionVirgilAgent
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider

/**
 * [EThree] class simplifies work with Virgil Services to easily implement End to End Encrypted
 * communication.
 */
class EThree(
        context: Context,
        private val tokenProvider: AccessTokenProvider
) : EThreeCore(context, tokenProvider) {
    override val keyManagerLocal: IKeyManagerLocal
    override val keyManagerCloud: IKeyManagerCloud

    init {
        keyManagerLocal = KeyManagerLocal(
            tokenProvider.getToken(NO_CONTEXT).identity,
            context)
        keyManagerCloud = KeyManagerCloud(
            currentIdentity(),
            tokenProvider,
            VersionVirgilAgent.VERSION)
    }
}
