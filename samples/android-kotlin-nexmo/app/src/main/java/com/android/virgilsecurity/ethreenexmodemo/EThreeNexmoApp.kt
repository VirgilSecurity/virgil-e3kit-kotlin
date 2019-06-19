package com.android.virgilsecurity.ethreenexmodemo

import android.app.Application
import com.virgilsecurity.android.ethree.kotlin.interaction.EThree

/**
 * EThreeNexmoApp
 */
class EThreeNexmoApp : Application() {

    companion object {
        lateinit var eThree: EThree
    }
}