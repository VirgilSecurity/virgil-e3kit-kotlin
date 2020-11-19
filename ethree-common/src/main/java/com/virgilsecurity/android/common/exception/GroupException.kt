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

package com.virgilsecurity.android.common.exception

/**
 * GroupException
 */
class GroupException @JvmOverloads constructor(
        val description: Description,
        throwable: Throwable? = null
) : EThreeBaseException("${description.errorCode}: ${description.errorMessage}",
                        throwable) {

    enum class Description(val errorCode: Int, val errorMessage: String) {
        MISSING_CACHED_GROUP(ErrorCode.GROUP + 1, "Group with provided id not found locally. Try to call loadGroup first."),
        GROUP_PERMISSION_DENIED(ErrorCode.GROUP + 2, "Only group initiator can do changed on group."),
        GROUP_WAS_NOT_FOUND(ErrorCode.GROUP + 3, "Group with provided id was not found."),
        INVALID_GROUP(ErrorCode.GROUP + 4, "Group is invalid."),
        INVALID_CHANGE_PARTICIPANTS(ErrorCode.GROUP + 5, "Invalid change of group participants. e.g. Add smb who is already in group or remove smb who is not."),
        INVALID_PARTICIPANTS_COUNT(ErrorCode.GROUP + 6, "Please check valid participants count range in Group.ValidParticipatnsCountRange."),
        VERIFICATION_FAILED(ErrorCode.GROUP + 7, "Verification of message failed. This may be caused by rotating sender key. Try finding new one."),
        SHORT_GROUP_ID(ErrorCode.GROUP + 8, "Group Id length should be > 10."),
        MESSAGE_NOT_FROM_THIS_GROUP(ErrorCode.GROUP + 9, "Message was encrypted in group with different identifier."),
        GROUP_IS_OUTDATED(ErrorCode.GROUP + 10, "Group is not up to date. Call update or loadGroup."),
        INCONSISTENT_STATE(ErrorCode.GROUP + 11, "Inconsistent state."),
        INITIATOR_REMOVAL_FAILED(ErrorCode.GROUP + 12, "Group initiator is not able to remove himself from a group."),
        GROUP_ALREADY_EXISTS(ErrorCode.GROUP + 13, "Group with the same ID is already exists."),
    }
}
