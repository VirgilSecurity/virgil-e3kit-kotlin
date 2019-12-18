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

package com.virgilsecurity.android.common.exception

/**
 * RatchetException
 */
class EThreeRatchetException @JvmOverloads constructor(
        val description: Description,
        throwable: Throwable? = null
) : EThreeBaseException("${description.errorCode}: ${description.errorMessage}",
                        throwable) {

    enum class Description(val errorCode: Int, val errorMessage: String) {
        ENCRYPT_EMPTY_ARRAY(ErrorCode.RATCHET + 1, "Trying to encrypt empty array."),
        DECRYPT_EMPTY_ARRAY(ErrorCode.RATCHET + 2, "Trying to decrypt empty array."),
        CHANNEL_ALREADY_EXISTS(ErrorCode.RATCHET + 4,
                               "Channel with provided user and name already exists."),
        SELF_CHANNEL_IS_FORBIDDEN(ErrorCode.RATCHET + 5,
                                  "Channel with self is forbidden. Use regular encryption for this " +
                                  "purpose."),
        RATCHET_IS_DISABLED(ErrorCode.RATCHET + 6, "enableRatchet parameter is set to false."),
        USER_IS_NOT_USING_RATCHET(ErrorCode.RATCHET + 7,
                                  "Provided user has been never initialized with ratchet enabled."),
        NO_INVITE(ErrorCode.RATCHET + 8, "There is no invitation from provided user."),
        NO_SELF_CARD_LOCALLY(ErrorCode.RATCHET + 9, "There is no self card in local storage.")
    }
}
