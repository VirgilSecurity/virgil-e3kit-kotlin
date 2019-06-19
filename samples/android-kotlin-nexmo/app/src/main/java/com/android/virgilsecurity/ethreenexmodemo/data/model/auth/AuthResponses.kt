package com.android.virgilsecurity.ethreenexmodemo.data.model.auth

/**
 * AuthResponses
 */

data class AuthenticateResponse(val authToken: String)

data class VirgilJwtResponse(val virgilToken: String)

data class NexmoJwtResponse(val nexmoToken: String)