package com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.thread

import android.content.Context
import android.os.Bundle
import android.support.v4.app.Fragment
import android.support.v7.widget.LinearLayoutManager
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import com.android.virgilsecurity.ethreenexmodemo.R
import com.android.virgilsecurity.ethreenexmodemo.data.model.chat.NexmoMessage
import com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.ChatControlActivity
import com.nexmo.client.NexmoConversation
import com.virgilsecurity.android.common.exceptions.PublicKeyNotFoundException
import com.virgilsecurity.sdk.crypto.PublicKey
import kotlinx.android.synthetic.main.fragment_thread.*

/**
 * ThreadFragment
 */
class ThreadFragment : Fragment() {

    private lateinit var thread: NexmoConversation
    private lateinit var presenter: ThreadPresenter
    private lateinit var adapter: ThreadRVAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val inputArguments = arguments

        if (inputArguments != null) {
            val nexmoConversation = inputArguments.getParcelable(KEY_THREAD) as NexmoConversation
            thread = nexmoConversation
        } else {
            throw IllegalStateException("No thread passed")
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_thread, container, false)
    }

    override fun onAttach(context: Context) {
        super.onAttach(context)

        presenter = ThreadPresenter(context)
        adapter = ThreadRVAdapter(context)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        rvMessages.layoutManager = LinearLayoutManager(context)
        rvMessages.adapter = adapter

        presenter.startMessagesListener(thread, ::onNewMessageReceived)
        presenter.requestPublicKey(thread, ::onGetPublicKeySuccess, ::onGetPublicKeyError)

        btnSend.setOnClickListener {
            if (etMessage.text.toString().isNotBlank()) {
                presenter.requestSendMessage(
                    thread,
                    etMessage.text.toString(),
                    ::onMessageSendSuccess,
                    ::onMessageSendError
                )
            } else {
                Toast.makeText(activity!!, "Type in message first", Toast.LENGTH_SHORT).show()
            }
        }

        ivBackThread.setOnClickListener {
            (activity as ChatControlActivity).goBack()
        }
        tvTitleThread.text = thread.displayName
    }

    override fun onDestroyView() {
        super.onDestroyView()

        presenter.stopMessagesListener(thread)
    }

    private fun onGetPublicKeySuccess(publicKey: PublicKey) {
        activity!!.runOnUiThread {
            pbLoading.visibility = View.INVISIBLE
            adapter.setPublicKey(publicKey)
        }
    }

    private fun onGetPublicKeyError(throwable: Throwable) {
        activity!!.runOnUiThread {
            pbLoading.visibility = View.INVISIBLE
            if (throwable is PublicKeyNotFoundException)
            Toast.makeText(activity!!, "No public key was found", Toast.LENGTH_SHORT).show()
            else
                Toast.makeText(activity!!, throwable.message, Toast.LENGTH_SHORT).show()
        }
    }

    private fun onNewMessageReceived(nexmoMessage: NexmoMessage) {
        activity!!.runOnUiThread {
            adapter.addItem(nexmoMessage)
        }
    }

    private fun onMessageSendSuccess(nexmoMessage: NexmoMessage) {
        etMessage.text.clear()
        activity!!.runOnUiThread {
            adapter.addItem(nexmoMessage)
        }
    }

    private fun onMessageSendError(throwable: Throwable) {
        activity!!.runOnUiThread {
            pbLoading.visibility = View.INVISIBLE
            Toast.makeText(activity!!, throwable.message, Toast.LENGTH_SHORT).show()
        }
    }

    companion object {

        private const val KEY_THREAD = "KEY_THREAD"

        fun instance(thread: NexmoConversation): ThreadFragment =
            with(Bundle().apply { putParcelable(KEY_THREAD, thread) }) {
                ThreadFragment().apply { arguments = this@with }
            }
    }
}
