/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.android.common.utils

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import com.virgilsecurity.sdk.crypto.VirgilCrypto
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey
import com.virgilsecurity.testcommon.property.EnvPropertyReader
import com.virgilsecurity.testcommon.utils.PropertyUtils
import java.io.File
import java.io.FileOutputStream

class TestConfig {
    companion object {
        private const val APP_ID = "APP_ID"
        private const val APP_PRIVATE_KEY = "APP_PRIVATE_KEY"
        private const val APP_PUBLIC_KEY_ID = "APP_PUBLIC_KEY_ID"
        private const val VIRGIL_SERVICE_ADDRESS = "VIRGIL_SERVICE_ADDRESS"

        private const val ENVIRONMENT_PARAMETER = "environment"

        private val propertyReader: EnvPropertyReader by lazy {
            val environment = PropertyUtils.getSystemProperty(ENVIRONMENT_PARAMETER)

            val resourceEnvStream =
                    this.javaClass.classLoader.getResourceAsStream("testProperties/env.json")
            val tempEnvDirectory = File(context.filesDir, "tempEnvDir")
            tempEnvDirectory.mkdirs()

            val tempEnvFile = File(tempEnvDirectory, "env.json")

            val outputStream = FileOutputStream(tempEnvFile)
            outputStream.write(resourceEnvStream.readBytes())
            outputStream.close()

            if (environment != null)
                EnvPropertyReader.Builder()
                        .environment(EnvPropertyReader.Environment.fromType(environment))
                        .filePath(tempEnvFile.parent)
                        .build()
            else
                EnvPropertyReader.Builder()
                        .filePath(tempEnvFile.parent)
                        .build()
        }

        val virgilCrypto = VirgilCrypto(false)
        val appId: String by lazy { propertyReader.getProperty(APP_ID) }
        val appKey: VirgilPrivateKey by lazy {
            with(propertyReader.getProperty(APP_PRIVATE_KEY)) {
                virgilCrypto.importPrivateKey(com.virgilsecurity.crypto.foundation.Base64.decode(this.toByteArray())).privateKey
            }
        }
        val appPublicKeyId: String by lazy { propertyReader.getProperty(APP_PUBLIC_KEY_ID) }
        val virgilServiceAddress: String by lazy {
            propertyReader.getProperty(VIRGIL_SERVICE_ADDRESS)
        }

        const val VIRGIL_CARDS_SERVICE_PATH = "/card/v5/"

        val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
        val DIRECTORY_PATH: String = InstrumentationRegistry.getInstrumentation()
                .targetContext.filesDir.absolutePath
        const val KEYSTORE_NAME = "virgil.keystore"
    }
}
