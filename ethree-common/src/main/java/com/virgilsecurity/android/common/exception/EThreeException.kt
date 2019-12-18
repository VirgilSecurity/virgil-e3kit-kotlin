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
 * Exceptions
 */
open class EThreeException
@JvmOverloads
constructor(
        val description: Description,
        throwable: Throwable? = null
) : EThreeBaseException("${description.errorCode}: ${description.errorMessage}",
                        throwable) {

    enum class Description(val errorCode: Int, val errorMessage: String) {
        VERIFIER_INIT_FAILED(ErrorCode.BASE + 1,
                             "Initialization of VirgilCardVerifier failed."),
        STR_TO_DATA_FAILED(ErrorCode.BASE + 2, "String to Data failed."),
        STR_FROM_DATA_FAILED(ErrorCode.BASE + 3, "Data to String failed."),
        MISSING_PRIVATE_KEY(ErrorCode.BASE + 4,
                            "No private key on device. You should call register() of " +
                            "retrievePrivateKey()."),
        MISSING_PUBLIC_KEY(ErrorCode.BASE + 5, "Passed empty FindUsersResult."),
        MISSING_IDENTITIES(ErrorCode.BASE + 6,
                           "Passed empty array of identities to findUsers."),
        USER_IS_ALREADY_REGISTERED(ErrorCode.BASE + 7, "User is already registered."),
        USER_IS_NOT_REGISTERED(ErrorCode.BASE + 8, "User is not registered."),
        PRIVATE_KEY_EXISTS(ErrorCode.BASE + 9,
                           "Private key already exists in local key storage."),
        VERIFICATION_FAILED(ErrorCode.BASE + 10,
                            "Verification of message failed. This may be caused by rotating " +
                            "sender key. Try finding new one."),
        WRONG_PASSWORD(ErrorCode.BASE + 11, "Wrong password."),
        SAME_PASSWORD(ErrorCode.BASE + 12, "To change the password, please provide a new " +
                                           "password that differs from the old one."),
        NO_PRIVATE_KEY_BACKUP(ErrorCode.BASE + 13, "Can't restore private key: private key " +
                                                   "backup has not been found."),
        PRIVATE_KEY_BACKUP_EXISTS(ErrorCode.BASE + 14, "Can't backup private key as it's " +
                                                       "already backed up."),

    }
}
