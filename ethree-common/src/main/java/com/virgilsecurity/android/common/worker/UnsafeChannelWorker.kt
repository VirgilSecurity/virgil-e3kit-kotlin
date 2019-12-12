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

package com.virgilsecurity.android.common.worker

import com.virgilsecurity.android.common.exception.UnsafeChannelException
import com.virgilsecurity.android.common.manager.LookupManager
import com.virgilsecurity.android.common.manager.UnsafeChannelManager
import com.virgilsecurity.android.common.model.unsafe.UnsafeChannel
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.common.model.Result

/**
 * UnsafeWorker
 */
internal class UnsafeChannelWorker(
        private val identity: String,
        private val lookupManager: LookupManager,
        private val getUnsafeManager: () -> UnsafeChannelManager
) {

    internal fun createUnsafeChannel(identity: String): Result<UnsafeChannel> =
            object : Result<UnsafeChannel> {
                override fun get(): UnsafeChannel {
                    if (identity == this@UnsafeChannelWorker.identity) {
                        throw UnsafeChannelException(
                            UnsafeChannelException.Description.SELF_CHANNEL_IS_FORBIDDEN
                        )
                    }

                    val result = lookupManager.lookupCards(listOf(identity), checkResult = false)
                    if (result.isNotEmpty()) {
                        throw UnsafeChannelException(
                            UnsafeChannelException.Description.USER_IS_REGISTERED
                        )
                    }

                    return getUnsafeManager().create(identity)
                }
            }

    internal fun loadUnsafeChannel(asCreator: Boolean, identity: String): Result<UnsafeChannel> =
            object : Result<UnsafeChannel> {
                override fun get(): UnsafeChannel {
                    val unsafeManager = getUnsafeManager()
                    if (identity == this@UnsafeChannelWorker.identity) {
                        throw UnsafeChannelException(
                            UnsafeChannelException.Description.SELF_CHANNEL_IS_FORBIDDEN
                        )
                    }

                    return unsafeManager.loadFromCloud(asCreator, identity)
                }
            }

    internal fun getUnsafeChannel(identity: String): UnsafeChannel? {
        val unsafeManager = getUnsafeManager()

        return unsafeManager.getLocalChannel(identity)
    }

    internal fun deleteUnsafeChannel(identity: String): Completable = object : Completable {
        override fun execute() {
            getUnsafeManager().delete(identity)
        }
    }
}
