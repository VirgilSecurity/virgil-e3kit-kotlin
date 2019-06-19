package com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.threadsList

import android.support.v7.widget.RecyclerView
import android.view.LayoutInflater
import android.view.ViewGroup
import com.android.virgilsecurity.ethreenexmodemo.R
import com.nexmo.client.NexmoConversation
import java.util.*

/**
 * ThreadsListRVAdapter
 */
class ThreadsListRVAdapter : RecyclerView.Adapter<ThreadHolder>() {

    private var items: MutableList<NexmoConversation> = Collections.emptyList()
    private lateinit var clickListener: (NexmoConversation) -> Unit

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ThreadHolder =
        with(LayoutInflater.from(parent.context).inflate(R.layout.item_threads_list, parent, false)) {
            ThreadHolder(this)
        }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: ThreadHolder, position: Int) {
        holder.bind(items[position], clickListener)
    }

    fun setItems(items: Collection<NexmoConversation>) {
        if (this.items.isEmpty()) {
            this.items = mutableListOf()
            this.items.addAll(items)
        } else {
            this.items.clear()
            this.items.addAll(items)
        }
        notifyDataSetChanged()
    }

    fun addItem(item: NexmoConversation) {
        if (this.items.isEmpty()) {
            this.items = mutableListOf()
            this.items.add(item)
        } else {
            this.items.add(item)
        }
        notifyDataSetChanged()
    }

    fun setOnClickListener(clickListener: (NexmoConversation) -> Unit) {
        this.clickListener = clickListener
    }
}