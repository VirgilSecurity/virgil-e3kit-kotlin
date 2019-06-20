package com.android.virgilsecurity.ethreenexmodemo.ui.signUp

import android.content.Context
import android.os.Bundle
import android.support.v4.app.Fragment
import android.support.v7.app.AppCompatActivity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import com.android.virgilsecurity.ethreenexmodemo.R
import com.android.virgilsecurity.ethreenexmodemo.data.model.auth.CreateUserResponse
import com.android.virgilsecurity.ethreenexmodemo.ui.chatControl.ChatControlActivity
import kotlinx.android.synthetic.main.fragment_sign_in.*

/**
 * SignUpFragment
 */
class SignUpFragment : Fragment() {

    private lateinit var presenter: SignUpPresenter

    override fun onAttach(context: Context) {
        super.onAttach(context)

        presenter = SignUpPresenter(context)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.fragment_sign_in, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        btnSignUp.setOnClickListener {
            if (etLogin.text.isBlank())
                Toast.makeText(this@SignUpFragment.activity, "Fill in login first", Toast.LENGTH_SHORT).show()
            else
                presenter.requestAuthenticate(etLogin.text.toString(), ::onAuthenticateSuccess, ::onAuthenticateError)
        }
    }

    override fun onDetach() {
        super.onDetach()

        presenter.disposeAll()
    }

    private fun onAuthenticateSuccess() {
        presenter.createUser(
            etLogin.text.toString(),
            etLogin.text.toString() + DISPLAY,
            ::onCreateUserSuccess,
            ::onCreateUserError
        )
    }

    private fun onAuthenticateError(throwable: Throwable) {
        activity!!.runOnUiThread {
            Toast.makeText(activity!!, throwable.message, Toast.LENGTH_SHORT).show()
        }
    }

    private fun onGetTokensSuccess() {
        presenter.initNexmo(::onInitNexmoSuccess, ::onInitNexmoError)
    }

    private fun onGetTokensError(throwable: Throwable) {
        activity!!.runOnUiThread {
            Toast.makeText(activity!!, throwable.message, Toast.LENGTH_SHORT).show()
        }
    }

    private fun onInitNexmoSuccess() {
        presenter.startEthree(::onStartEthreeSuccess, ::onStartEthreeError)
    }

    private fun onInitNexmoError(throwable: Throwable) {
        activity!!.runOnUiThread {
            Toast.makeText(activity!!, throwable.message, Toast.LENGTH_SHORT).show()
        }
    }

    private fun onCreateUserSuccess(user: CreateUserResponse) {
        presenter.requestTokens(::onGetTokensSuccess, ::onGetTokensError)
    }

    private fun onCreateUserError(throwable: Throwable) {
        activity!!.runOnUiThread {
            val errorParts = throwable.message!!.split("HTTP Exception ")
            if (errorParts.size == 2 || errorParts[1].trimEnd() == BAD_REQUEST)
                Toast.makeText(
                    activity!!,
                    "User already exists, please enter other identity",
                    Toast.LENGTH_SHORT
                ).show()
            else
                Toast.makeText(activity!!, throwable.message, Toast.LENGTH_SHORT).show()
        }
    }

    private fun onStartEthreeSuccess() {
        ChatControlActivity.start(activity!! as AppCompatActivity)
    }

    private fun onStartEthreeError(throwable: Throwable) {
        Toast.makeText(activity!!, throwable.message, Toast.LENGTH_SHORT).show()
    }

    companion object {
        fun instance() = SignUpFragment()

        private const val DISPLAY = "-display"
        private const val BAD_REQUEST = "400"
    }
}