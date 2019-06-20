package com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.thread

import android.support.v7.widget.RecyclerView
import android.view.View
import kotlinx.android.extensions.LayoutContainer
import kotlinx.android.synthetic.main.item_message_you.*

/**
 * YouMessageHolder
 */
class YouMessageHolder(override val containerView: View) : RecyclerView.ViewHolder(containerView), LayoutContainer {

    fun bind(text: String) {
        tvMessage.text = text
    }
}