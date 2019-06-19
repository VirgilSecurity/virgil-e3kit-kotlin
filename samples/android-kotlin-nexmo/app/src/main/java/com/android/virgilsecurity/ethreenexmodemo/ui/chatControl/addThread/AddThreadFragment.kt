package com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.addThread

import android.content.Context
import android.os.Bundle
import android.support.v4.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import com.android.virgilsecurity.ethreenexmodemo.R
import com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.ChatControlActivity
import com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.threadsList.ThreadsListFragment
import com.nexmo.client.NexmoConversation
import kotlinx.android.synthetic.main.fragment_add_thread.*

/**
 * AddThreadFragment
 */
class AddThreadFragment : Fragment() {

    private lateinit var presenter: AddThreadPresenter

    override fun onAttach(context: Context) {
        super.onAttach(context)

        presenter = AddThreadPresenter(context)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_add_thread, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        btnAddThread.setOnClickListener {
            if (etInterlocutor.text.toString().isNotBlank())
                presenter.requestAddThread(etInterlocutor.text.toString(), ::onAddThreadSuccess, ::onAddThreadError)
        }

        ivBackAddThread.setOnClickListener {
            (activity as ChatControlActivity).goBack()
        }
        tvTitleAddThread.text = "Add Thread"
    }

    private fun onAddThreadSuccess(nexmoConversation: NexmoConversation) {
        Toast.makeText(activity!!, "Created ${nexmoConversation.displayName}", Toast.LENGTH_SHORT).show()

        (activity!! as ChatControlActivity).changeFragment(ThreadsListFragment.instance())
    }

    private fun onAddThreadError(throwable: Throwable) {
        Toast.makeText(activity!!, throwable.message, Toast.LENGTH_SHORT).show()
    }

    companion object {
        fun instance() = AddThreadFragment()
    }
}