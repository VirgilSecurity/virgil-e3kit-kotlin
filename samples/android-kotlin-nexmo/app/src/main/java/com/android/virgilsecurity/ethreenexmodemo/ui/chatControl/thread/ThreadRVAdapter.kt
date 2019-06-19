package com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.thread

import android.content.Context
import android.support.v7.widget.RecyclerView
import android.view.LayoutInflater
import android.view.ViewGroup
import com.android.virgilsecurity.ethreenexmodemo.EThreeNexmoApp
import com.android.virgilsecurity.ethreenexmodemo.R
import com.android.virgilsecurity.ethreenexmodemo.data.local.Preferences
import com.android.virgilsecurity.ethreenexmodemo.data.model.chat.NexmoMessage
import com.virgilsecurity.sdk.crypto.PublicKey
import java.util.*

/**
 * ThreadsListRVAdapter
 */
class ThreadRVAdapter(context: Context) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

    private var items: MutableList<NexmoMessage> = Collections.emptyList()
    private val preferences = Preferences.instance(context)
    private lateinit var interlocutorsPublicKey: PublicKey

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder =
        if (viewType == HolderType.YOU.type) {
            val view = LayoutInflater.from(parent.context).inflate(R.layout.item_message_you, parent, false)
            YouMessageHolder(view)
        } else {
            val view = LayoutInflater.from(parent.context).inflate(R.layout.item_message_me, parent, false)
            MeMessageHolder(view)
        }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) =
        when (holder) {
            is YouMessageHolder -> {
                val decryptedText = EThreeNexmoApp.eThree.decrypt(
                    items[position].text,
                    interlocutorsPublicKey
                )
                holder.bind(decryptedText)
            }
            is MeMessageHolder -> {
                val decryptedText = EThreeNexmoApp.eThree.decrypt(
                    items[position].text,
                    interlocutorsPublicKey
                )
                holder.bind(decryptedText)
            }
            else -> throw IllegalStateException("Only two message holders are available")
        }

    override fun getItemViewType(position: Int): Int =
        if (items[position].sender == preferences.username())
            HolderType.ME.type
        else
            HolderType.YOU.type

    fun setItems(items: Collection<NexmoMessage>) {
        if (this.items.isEmpty()) {
            this.items = mutableListOf()
            this.items.addAll(items)
        } else {
            this.items.clear()
            this.items.addAll(items)
        }
        notifyDataSetChanged()
    }

    fun addItem(item: NexmoMessage) {
        if (this.items.isEmpty()) {
            this.items = mutableListOf()
            this.items.add(item)
        } else {
            this.items.add(item)
        }
        notifyDataSetChanged()
    }

    fun setPublicKey(publicKey: PublicKey) {
        interlocutorsPublicKey = publicKey
    }
}

enum class HolderType(val type: Int) {
    ME(0),
    YOU(1)
}