# Virgil E3Kit Android SDK

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-e3kit-kotlin.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-e3kit-kotlin)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Install E3Kit SDK](#install-e3kit-sdk) | [Usage](#usage) | [Samples](#samples) | [License](#license) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides the E3Kit SDK which simplifies work with Virgil services and presents an easy-to-use API for adding a security layer to any application. E3Kit interacts with Virgil Cards Service, Keyknox Service and Pythia Service.
Virgil E3kit allows you to setup user encryption with multidevice support in just a few simple steps.

## SDK Features
- multi-device support
- group chats
- manage users' Public Keys

## Install E3Kit SDK

You can install E3Kit SDK using [Gradle](https://gradle.org/). Please, choose package that suits best for your needs:

| Package | Description |
|----------|---------|
| [`E3Kit`](./ethree-kotlin) | Standard package for Java/Kotlin with methods responses in `callbacks` |

## Samples

You can find the code samples for Java and Kotlin here:

| Sample type | 
|----------| 
| [`Android Java`](./samples/android-java) | 
| [`Android Kotlin`](./samples/android-kotlin) | 
| [`Android Java Firebase`](./samples/android-java-firebase-function) | 
| [`Android Kotlin Firebase`](./samples/android-kotlin-firebase-function) | 

You can run any of them on an emulator to check out the example of how to initialize the SDK, register users and encrypt messages using the E3Kit.

## Usage

#### Initialize e3kit:

```kotlin
lateinit var eThree: EThree

// Listener for E3Kit initialization
val initializeListener =
    object : OnResultListener<EThree> {
        override fun onSuccess(result: EThree) {
            // Init done!
            eThree = result
        }

        override fun onError(throwable: Throwable) {
            // Error handling
        }
    }

// initialize E3Kit
EThree.initialize(context, virgilTokenCallback).addCallback(initializeListener)
```

#### Register e3kit user
Use the following lines of code to register a user:
```kotlin
// TODO: Initialize e3kit

val registerListener =
    object : OnCompleteListener {
        override fun onSuccess() {
            // User private key loaded, ready for end-to-end encrypt!
        }

        override fun onError(throwable: Throwable) {
            // Error handling
        }
    }

eThree.register().addCallback(registerListener)
```
This function generates PrivateKey/PublicKey keypair, saves PrivateKey locally on device and publishes PublicKey to Virgil Cards Service.

#### Sign Then Encrypt data/text

This method signs the data/text with the sender's private key and encrypts the message for recipients' public key(s).

```kotlin
// TODO: Initialize e3kit, Register e3kit user          

val lookupKeysListener =
    object : OnResultListener<LookupResult> {
        override fun onSuccess(result: LookupResult) {
            val text = "I was text but become byte array"
            val data = text.toByteArray()

            // Encrypt data using user public keys
            val encryptedData = eThree.encrypt(data, result)

            // Encrypt message using user public keys
            val encryptedText = eThree.encrypt(text, result)
        }

        override fun onError(throwable: Throwable) {
            // Error handling
        }
    }

// Lookup destination user public keys
eThree.lookupPublicKeys(listOf("userUID1", "userUID2", "userUID3")).addCallback(lookupKeysListener)
```

#### Decrypt Then Verify data/text

```kotlin
// TODO: Initialize e3kit, Register e3kit user 

val lookupKeysListener =
    object : OnResultListener<LookupResult> {
        override fun onSuccess(result: LookupResult) {
            // Decrypt data and verify if it was really written by Bob
            val decryptedData = eThree.decrypt(encryptedData, result["bobUID"])

            // Decrypt text and verify if it was really written by Bob
            val decryptedText = eThree.decrypt(encryptedText, result["bobUID"])
        }

        override fun onError(throwable: Throwable) {
            // Error handling
        }
    }

// Lookup chat room member key
eThree.lookupPublicKeys("bobUID").addCallback(lookupKeysListener)
```

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
