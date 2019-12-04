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
 */               // TODO re-think exceptions type
open class EThreeException
@JvmOverloads
@Deprecated("This constructor will be removed after 0.8.0 version",
            replaceWith = ReplaceWith("EThreeException(Description, Throwable?)"))
constructor(
        override val message: String? = null,
        throwable: Throwable? = null
) : RuntimeException(message, throwable) {

    var description: Description? = null
        protected set

    @JvmOverloads constructor(
            description: Description,
            throwable: Throwable? = null
    ) : this(description.errorMessage, throwable) {

        this.description = description
    }

    enum class Description(val errorCode: Int, val errorMessage: String) {
        VERIFIER_INIT_FAILED(70101, "Initialization of VirgilCardVerifier failed."),
        STR_TO_DATA_FAILED(70102, "String to Data failed."),
        STR_FROM_DATA_FAILED(70103, "Data to String failed."),
        MISSING_PRIVATE_KEY(70104,
                            "No private key on device. You should call register() of " +
                            "retrievePrivateKey()."),
        MISSING_PUBLIC_KEY(70105, "Passed empty FindUsersResult."),
        MISSING_IDENTITIES(70106, "Passed empty array of identities to findUsers."),
        USER_IS_ALREADY_REGISTERED(70107, "User is already registered."),
        USER_IS_NOT_REGISTERED(70108, "User is not registered."),
        PRIVATE_KEY_EXISTS(70109, "Private key already exists in local key storage."),
        VERIFICATION_FAILED(70110,
                            "Verification of message failed. This may be caused by rotating " +
                            "sender key. Try finding new one."),
        WRONG_PASSWORD(70111, "Wrong password."),
    }
}
