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

import com.virgilsecurity.android.common.exception.EThreeRatchetException
import com.virgilsecurity.android.common.model.ratchet.RatchetChannel
import com.virgilsecurity.android.common.storage.cloud.CloudRatchetStorage
import com.virgilsecurity.common.model.Completable
import com.virgilsecurity.common.model.Result
import com.virgilsecurity.keyknox.utils.unwrapCompanionClass
import com.virgilsecurity.ratchet.exception.FileDeletionException
import com.virgilsecurity.ratchet.securechat.SecureChat
import com.virgilsecurity.ratchet.securechat.SecureSession
import com.virgilsecurity.sdk.cards.Card
import java.util.*
import java.util.logging.Logger

/**
 * RatchetWorker
 */
internal class RatchetWorker internal constructor(
        private val identity: String,
        private val cloudRatchetStorage: CloudRatchetStorage,
        private val getSecureChat: () -> SecureChat,
        private val startRatchetSessionAsSender: (SecureChat, Card, String?) -> SecureSession
) {

    @JvmOverloads internal fun createRatchetChannel(card: Card,
                                                    name: String? = null): Result<RatchetChannel> =
            object : Result<RatchetChannel> {
                override fun get(): RatchetChannel {
                    val secureChat = getSecureChat()

                    if (secureChat.existingSession(card.identity, name) != null) {
                        throw EThreeRatchetException(
                            EThreeRatchetException.Description.CHANNEL_ALREADY_EXISTS
                        )
                    }

                    if (card.identity == this@RatchetWorker.identity) {
                        throw EThreeRatchetException(
                            EThreeRatchetException.Description.SELF_CHANNEL_IS_FORBIDDEN
                        )
                    }

                    val session = startRatchetSessionAsSender(secureChat, card, name)
                    val ticket = session.encrypt(UUID.randomUUID().toString())
                    cloudRatchetStorage.store(ticket, card, name)

                    secureChat.storeSession(session)

                    return RatchetChannel(session, secureChat.sessionStorage)
                }
            }

    @JvmOverloads internal fun joinRatchetChannel(card: Card,
                                                  name: String? = null): Result<RatchetChannel> =
            object : Result<RatchetChannel> {
                override fun get(): RatchetChannel {
                    val secureChat = getSecureChat()

                    if (secureChat.existingSession(card.identity, name) != null) {
                        throw EThreeRatchetException(
                            EThreeRatchetException.Description.CHANNEL_ALREADY_EXISTS
                        )
                    }

                    if (card.identity == this@RatchetWorker.identity) {
                        throw EThreeRatchetException(
                            EThreeRatchetException.Description.SELF_CHANNEL_IS_FORBIDDEN
                        )
                    }

                    val ticket = cloudRatchetStorage.retrieve(card, name)
                    val session = secureChat.startNewSessionAsReceiver(card, ticket)
                    session.decryptData(ticket)

                    secureChat.storeSession(session)

                    return RatchetChannel(session, secureChat.sessionStorage)
                }
            }

    @JvmOverloads internal fun getRatchetChannel(card: Card,
                                                 name: String? = null): RatchetChannel? {
        val secureChat = getSecureChat()

        val session = secureChat.existingSession(card.identity, name) ?: return null

        return RatchetChannel(session, secureChat.sessionStorage)
    }

    @JvmOverloads internal fun deleteRatchetChannel(card: Card,
                                                    name: String? = null): Completable =
            object : Completable {
                override fun execute() {
                    val secureChat = getSecureChat()

                    cloudRatchetStorage.delete(card, name)

                    try {
                        secureChat.deleteSession(card.identity, name)
                    } catch (exception: FileDeletionException) {
                        logger.fine("Delete session failed: ${exception.localizedMessage}")
                    }
                }
            }

    companion object {
        private val logger = Logger.getLogger(unwrapCompanionClass(this.javaClass).name)
    }
}
