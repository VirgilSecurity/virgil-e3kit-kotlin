package com.virgilsecurity.android.ethree.kotlin.extension

import com.virgilsecurity.android.ethree.kotlin.interaction.LookupResult
import com.virgilsecurity.sdk.crypto.VirgilPublicKey

/**
 * LookupResult Extension to easily work with it
 */

fun LookupResult.publicKeys() = this.values.toList()

fun LookupResult.keyById(identity: String): VirgilPublicKey? = this[identity]
