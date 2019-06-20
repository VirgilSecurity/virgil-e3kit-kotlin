package com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.threadsList

import android.support.v7.widget.RecyclerView
import android.view.View
import com.nexmo.client.NexmoConversation
import kotlinx.android.extensions.LayoutContainer
import kotlinx.android.synthetic.main.item_threads_list.*

/**
 * ThreadHolder
 */
class ThreadHolder(override val containerView: View) : RecyclerView.ViewHolder(containerView), LayoutContainer {

    fun bind(thread: NexmoConversation, clickListener: (NexmoConversation) -> Unit) {
        itemThreadsListThreadName.text = thread.displayName
        itemThreadsListRoot.setOnClickListener { clickListener(thread) }
    }
}