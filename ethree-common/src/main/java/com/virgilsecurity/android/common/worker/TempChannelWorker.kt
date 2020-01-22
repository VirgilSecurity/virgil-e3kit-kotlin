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

package com.virgilsecurity.android.common.worker

import com.virgilsecurity.android.common.exception.TemporaryChannelException
import com.virgilsecurity.android.common.manager.LookupManager
import com.virgilsecurity.android.common.manager.TempChannelManager
import com.virgilsecurity.android.common.model.temporary.TemporaryChannel
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.common.model.Result

/**
 * TempChannelWorker
 */
internal class TempChannelWorker(
        private val identity: String,
        private val lookupManager: LookupManager,
        private val getTempChannelManager: () -> TempChannelManager
) {

    internal fun createTemporaryChannel(identity: String): Result<TemporaryChannel> =
            object : Result<TemporaryChannel> {
                override fun get(): TemporaryChannel {
                    if (identity == this@TempChannelWorker.identity) {
                        throw TemporaryChannelException(
                            TemporaryChannelException.Description.SELF_CHANNEL_IS_FORBIDDEN
                        )
                    }

                    val result = lookupManager.lookupCards(listOf(identity), checkResult = false)
                    if (result.isNotEmpty()) {
                        throw TemporaryChannelException(
                            TemporaryChannelException.Description.USER_IS_REGISTERED
                        )
                    }

                    return getTempChannelManager().create(identity)
                }
            }

    internal fun loadTemporaryChannel(asCreator: Boolean, identity: String): Result<TemporaryChannel> =
            object : Result<TemporaryChannel> {
                override fun get(): TemporaryChannel {
                    val manager = getTempChannelManager()
                    if (identity == this@TempChannelWorker.identity) {
                        throw TemporaryChannelException(
                            TemporaryChannelException.Description.SELF_CHANNEL_IS_FORBIDDEN
                        )
                    }

                    return manager.loadFromCloud(asCreator, identity)
                }
            }

    internal fun getTemporaryChannel(identity: String): TemporaryChannel? {
        val manager = getTempChannelManager()

        return manager.getLocalChannel(identity)
    }

    internal fun deleteTemporaryChannel(identity: String): Completable = object : Completable {
        override fun execute() {
            getTempChannelManager().delete(identity)
        }
    }
}
