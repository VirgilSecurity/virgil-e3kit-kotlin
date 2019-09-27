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

package com.virgilsecurity.android.common.storage.sql

import android.content.Context
import androidx.room.Room
import com.virgilsecurity.android.common.exception.EmptyIdentitiesStorageException
import com.virgilsecurity.android.common.exception.InconsistentCardStorageException
import com.virgilsecurity.android.common.storage.CardStorage
import com.virgilsecurity.android.common.storage.sql.model.CardEntity
import com.virgilsecurity.sdk.cards.Card
import com.virgilsecurity.sdk.cards.CardManager
import com.virgilsecurity.sdk.cards.validation.CardVerifier
import com.virgilsecurity.sdk.crypto.VirgilCardCrypto
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.jwt.accessProviders.CachingJwtProvider

/**
 * SQL-based Virgil Cards storage.
 */
internal class SQLCardStorage internal constructor(
        context: Context,
        userIdentifier: String,
        crypto: VirgilCrypto,
        verifier: CardVerifier,
        database: ETheeDatabase? = null
) : CardStorage {

    private val db: ETheeDatabase
    private val cardManager: CardManager

    init {

        if (database == null) {
            val dbName = String.format("ethree-database-%s", userIdentifier)
            this.db = Room.databaseBuilder(
                context,
                ETheeDatabase::class.java, dbName
            ).build()
        } else {
            db = database
        }

        val tokenProvider = CachingJwtProvider(CachingJwtProvider.RenewJwtCallback(function = {
            return@RenewJwtCallback null
        }))
        cardManager = CardManager(VirgilCardCrypto(crypto), tokenProvider, verifier)
    }

    override fun storeCard(card: Card) {
        var currentCard: Card? = card
        var previousCardId: String? = null
        var isOutdated = card.isOutdated
        while (currentCard != null) {
            val cardEntity = CardEntity(currentCard.identifier,
                                        currentCard.identity,
                                        isOutdated,
                                        CardManager.exportCardAsJson(currentCard))
            db.cardDao().insert(cardEntity)

            previousCardId = currentCard.previousCardId
            currentCard = currentCard.previousCard
            isOutdated = true
        }
        if (previousCardId != null) {
            db.cardDao().markOutdatedById(previousCardId)
        }
    }

    override fun getCard(cardId: String): Card? {
        val cardEntity = db.cardDao().load(cardId) ?: return null

        val card = cardManager.importCardAsJson(cardEntity.card)
        card.isOutdated = cardEntity.isOutdated

        if (cardId != card.identifier) {
            throw InconsistentCardStorageException()
        }

        return card
    }

    override fun searchCards(identities: List<String>): List<Card> {
        if (identities.isEmpty()) {
            throw EmptyIdentitiesStorageException()
        }

        val cards = mutableListOf<Card>()
        val entities = db.cardDao().loadAllByIdentity(identities)

        for (entity in entities) {
            val card = cardManager.importCardAsJson(entity.card)
            cards.add(card)
        }

        val result = mutableListOf<Card>()
        for (card in cards) {
            if (card.identity !in identities) {
                throw InconsistentCardStorageException("Got wrong card from SQL storage")
            }
            val nextCard = cards.firstOrNull { it.previousCardId == card.identifier }
            if (nextCard != null) {
                nextCard.previousCard = card
                card.isOutdated = true
                continue
            }
            result.add(card)
        }
        return result
    }

    override fun getNewestCardIds(): List<String> {
        return db.cardDao().getNewestCardIds()
    }

    override fun reset() {
        db.cardDao().deleteAll()
    }

}
