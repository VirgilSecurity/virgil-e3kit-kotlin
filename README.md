# Virgil E3Kit Android SDK

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-e3kit-kotlin.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-e3kit-kotlin)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Install E3Kit SDK](#install-e3kit-sdk) | [Usage](#usage) | [Samples](#samples) | [License](#license) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides an SDK which simplifies work with Virgil services and presents easy to use API for adding security to any application. In a few simple steps you can setup user encryption with multidevice support.

## SDK Features
- multidevice support
- manage users' Public Keys

## Install E3Kit SDK

You can install E3Kit SDK using [Gradle](https://gradle.org/). Please, choose package that suits best for your needs:

| Package | Description |
|----------|---------|
| [`E3Kit`](./ethree-kotlin) | Standard package for Java/Kotlin with methods responses in `callbacks` |
| [`E3Kit Coroutines`](./ethree-kotlin-coroutines) | [Coroutines](https://github.com/Kotlin/kotlinx.coroutines) package with methods responses in [`Deferred`](https://kotlin.github.io/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines/-deferred/) |

## Usage

#### Register User
Use the following lines of code to authenticate a user.

```kotlin
var eThree: EThree? = null

// Listener for E3Kit initialization
val initializeListener =
    object : EThree.OnResultListener<EThree> {
        override fun onSuccess(result: EThree) {
            // Init done!
            eThree = result
        }

        override fun onError(throwable: Throwable) {
            // Error handling
        }
    }

// initialize E3Kit
EThree.initialize(context, virgilTokenCallback, initializeListener)
```

#### Encrypt & decrypt

Virgil E3Kit lets you use a user's Private key and his or her Public Keys to sign, then encrypt text.

```kotlin
var eThree: EThree? = null
var encryptedData: ByteArray? = null
var encryptedText: String? = null           

// Listener for keys lookup Two
val lookupKeysListenerTwo =
    object : EThree.OnResultListener<Map<String, PublicKey>> {
        override fun onSuccess(result: Map<String, PublicKey>) {
            // Decrypt data using senders public key (In this example it's E3Kit current user)
            val decryptedData = eThree.decrypt(encryptedData!!, result[identityInToken])
            
            // Decrypt data using senders public key (In this example it's E3Kit current user)
            val decryptedText = eThree.decrypt(encryptedText!!, result[identityInToken])
        }

        override fun onError(throwable: Throwable) {
            // Error handling
        }
    }

// Listener for keys lookup
val lookupKeysListener =
    object : EThree.OnResultListener<Map<String, PublicKey>> {
        override fun onSuccess(result: Map<String, PublicKey>) {
            val text = "I was a text, but become a byte array"
            val data = text.toByteArray()

            // Encrypt data using user public keys
            encryptedData = eThree.encrypt(data, result.values.toList())

            // Encrypt message using user public keys
            encryptedText = eThree.encrypt(text, result.values.toList())
            
            // E3Kit using identity that specified in Jwt provided with *virgilTokenCallback*
            eThree!!.lookupPublicKeys(listOf(identityInToken), lookupKeysListenerTwo)
        }

        override fun onError(throwable: Throwable) {
            // Error handling
        }
    }

// Listener for register
val registerListener =
    object : EThree.OnCompleteListener {
        override fun onSuccess() {
            // User private key loaded!
            // Now we need public keys and we ready for end-to-end encrypt.
            eThree!!.lookupPublicKeys(listOf("AliceUUID", "BobUUID"), lookupKeysListener)
        }

        override fun onError(throwable: Throwable) {
            // Error handling
        }
    }

// Listener for E3Kit initialization
val initializeListener =
    object : EThree.OnResultListener<EThree> {
        override fun onSuccess(result: EThree) {
            // Init done!
            eThree = result
            eThree!!.register(registerListener)
        }

        override fun onError(throwable: Throwable) {
            // Error handling
        }
    }

// initialize E3Kit
EThree.initialize(context, virgilTokenCallback, initializeListener)
```

## Samples

You can find out samples for Java and Kotlin (for Kotlin-Coroutines module as well) here:

| Sample type |
|----------|
| [`Android Java`](./samples/android-java) |
| [`Android Kotlin`](./samples/android-kotlin) |
| [`Android Kotlin Coroutines`](./samples/android-kotlin-coroutines) |

You can run any of them on an emulator to check out example of how E3Kit works.

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).

[_cards_service]: https://developer.virgilsecurity.com/docs/api-reference/card-service/v5
[_use_card]: https://developer.virgilsecurity.com/docs/swift/how-to/public-key-management/v5/use-card-for-crypto-operation
[_get_card]: https://developer.virgilsecurity.com/docs/swift/how-to/public-key-management/v5/get-card
[_search_card]: https://developer.virgilsecurity.com/docs/swift/how-to/public-key-management/v5/search-card
[_create_card]: https://developer.virgilsecurity.com/docs/swift/how-to/public-key-management/v5/create-card
[_own_crypto]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-own-crypto-library
[_key_storage]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-key-storage
[_card_verifier]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-card-verifier
[_card_manager]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-card-manager
[_setup_authentication]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-authentication
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_configure_sdk]: https://developer.virgilsecurity.com/docs/how-to#sdk-configuration
[_more_examples]: https://developer.virgilsecurity.com/docs/how-to#public-key-management
