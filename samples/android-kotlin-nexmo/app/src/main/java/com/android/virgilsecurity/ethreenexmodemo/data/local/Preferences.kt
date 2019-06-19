package com.android.virgilsecurity.ethreenexmodemo.data.local

import android.content.Context
import android.content.SharedPreferences

/**
 * Preferences
 */
class Preferences(context: Context) {

    private val sharedPreferences: SharedPreferences

    init {
        sharedPreferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
    }

    fun setAuthToken(authToken: String) {
        with(sharedPreferences.edit()) {
            putString(KEY_AUTH_TOKEN, authToken)
            apply()
        }
    }

    fun authToken(): String? {
        with(sharedPreferences) {
            return getString(KEY_AUTH_TOKEN, null)
        }
    }

    fun clearAuthToken() {
        with(sharedPreferences.edit()) {
            remove(KEY_AUTH_TOKEN)
            apply()
        }
    }

    fun setVirgilToken(virgilToken: String) {
        with(sharedPreferences.edit()) {
            putString(KEY_VIRGIL_TOKEN, virgilToken)
            apply()
        }
    }

    fun virgilToken(): String? {
        with(sharedPreferences) {
            return getString(KEY_VIRGIL_TOKEN, null)
        }
    }

    fun clearVirgilToken() {
        with(sharedPreferences.edit()) {
            remove(KEY_VIRGIL_TOKEN)
            apply()
        }
    }

    fun setNexmoToken(nexmoToken: String) {
        with(sharedPreferences.edit()) {
            putString(KEY_NEXMO_TOKEN, nexmoToken)
            apply()
        }
    }

    fun nexmoToken(): String? {
        with(sharedPreferences) {
            return getString(KEY_NEXMO_TOKEN, null)
        }
    }

    fun clearNexmoToken() {
        with(sharedPreferences.edit()) {
            remove(KEY_NEXMO_TOKEN)
            apply()
        }
    }

    fun setUsername(username: String) {
        with(sharedPreferences.edit()) {
            putString(KEY_USERNAME, username)
            apply()
        }
    }

    fun username(): String? {
        with(sharedPreferences) {
            return getString(KEY_USERNAME, null)
        }
    }

    fun clearUsername() {
        with(sharedPreferences.edit()) {
            remove(KEY_USERNAME)
            apply()
        }
    }

    companion object {
        private const val PREFERENCES_NAME = "ethree_nexmo_prefs"

        private const val KEY_AUTH_TOKEN = "KEY_AUTH_TOKEN"
        private const val KEY_VIRGIL_TOKEN = "KEY_VIRGIL_TOKEN"
        private const val KEY_NEXMO_TOKEN = "KEY_NEXMO_TOKEN"
        private const val KEY_USERNAME = "KEY_USERNAME"

        @Volatile
        private var INSTANCE: Preferences? = null

        fun instance(context: Context): Preferences = INSTANCE ?: synchronized(this) {
            INSTANCE ?: Preferences(context).also { INSTANCE = it }
        }
    }
}