package com.android.virgilsecurity.ethreenexmodemo.ui.signUp

import android.content.Intent
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import com.android.virgilsecurity.ethreenexmodemo.R
import com.android.virgilsecurity.ethreenexmodemo.data.local.Preferences
import com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.ChatControlActivity

class SignUpActivity : AppCompatActivity() {

    private val preferences: Preferences by lazy { Preferences(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_sign_up)

        if (preferences.username() != null) {
            ChatControlActivity.start(this)
        } else {
            supportFragmentManager.beginTransaction()
                .replace(R.id.flContainer, SignUpFragment.instance())
                .commit()
        }
    }

    companion object {
        fun start(activity: AppCompatActivity) {
            activity.startActivity(Intent(activity, SignUpActivity::class.java))
            activity.finish()
        }
    }
}
