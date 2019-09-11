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

import com.virgilsecurity.android.common.EThreeCore
import com.virgilsecurity.android.common.exception.PrivateKeyNotFoundException
import com.virgilsecurity.android.common.exception.PublicKeyDuplicateException
import com.virgilsecurity.android.common.exception.PublicKeyNotFoundException
import com.virgilsecurity.android.common.manager.LookupManager
import com.virgilsecurity.android.common.model.FindUsersResult
import com.virgilsecurity.android.common.model.LookupResult
import com.virgilsecurity.common.model.Result
import com.virgilsecurity.sdk.cards.Card

/**
 * SearchWorker
 */
internal class SearchWorker(
        private val lookupManager: LookupManager
) {

    /**
     * Returns cards from local storage for given [identities].
     */
    internal fun findCachedUsers(identities: List<String>): Result<FindUsersResult> =
            object : Result<FindUsersResult> {
                override fun get(): FindUsersResult {
                    return lookupManager.lookupCachedCards(identities)
                }
            }

    /**
     * Returns card from local storage for given [identity].
     */
    internal fun findCachedUser(identity: String): Result<Card?> = object : Result<Card?> {
        override fun get(): Card? {
            return lookupManager.lookupCachedCard(identity)
        }
    }

    /**
     * Retrieves users Cards from the Virgil Cloud or local storage if exists for [identities].
     * If [forceReload] is *true* local cached cards won't be used.
     */
    internal fun findUsers(identities: List<String>,
                           forceReload: Boolean): Result<FindUsersResult> =
            object : Result<FindUsersResult> {
                override fun get(): FindUsersResult {
                    return lookupManager.lookupCards(identities, forceReload)
                }
            }

    /**
     * Retrieves users Card from the Virgil Cloud or local storage if exists for [identity].
     * If [forceReload] is *true* local cached card won't be used.
     */
    internal fun findUser(identity: String,
                          forceReload: Boolean): Result<Card> = object : Result<Card> {
        override fun get(): Card {
            return lookupManager.lookupCard(identity, forceReload)
        }
    }

    /**
     * Retrieves user public key from the cloud for encryption/verification operations.
     *
     * Searches for public key with specified [identity] and returns map of [String] ->
     * [PublicKey] in [onResultListener] callback or [Throwable] if something went wrong.
     *
     * [PublicKeyNotFoundException] will be thrown if public key wasn't found.
     *
     * Can be called only if private key is on the device, otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * @throws PrivateKeyNotFoundException
     * @throws PublicKeyDuplicateException
     */
    internal fun lookupPublicKey(identity: String): Result<LookupResult> =
            lookupPublicKeys(listOf(identity))

    /**
     * Retrieves user public keys from the cloud for encryption/verification operations.
     *
     * Searches for public keys with specified [identities] and returns map of [String] ->
     * [PublicKey] in [onResultListener] callback or [Throwable] if something went wrong.
     *
     * [PublicKeyNotFoundException] will be thrown for the first not found public key.
     * [EThreeCore.register]
     *
     * Can be called only if private key is on the device, otherwise [PrivateKeyNotFoundException]
     * exception will be thrown.
     *
     * To start execution of the current function, please see [Result] description.
     *
     * @throws PrivateKeyNotFoundException
     * @throws PublicKeyDuplicateException
     */
    internal fun lookupPublicKeys(identities: List<String>) =
            object : Result<LookupResult> {
                override fun get(): LookupResult {
                    require(identities.isEmpty()) { "\'identities\' should not be empty" }

                    val cards = findUsers(identities, true).get()
                    return cards.mapValues { it.component2().publicKey }
                }
            }
}
