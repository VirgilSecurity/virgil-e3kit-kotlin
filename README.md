# Virgil E3Kit Android SDK

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-e3kit-kotlin.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-e3kit-kotlin)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Installation](#installation) | [Usage Examples](#usage-examples) | [Samples](#samples) | [License](#license) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides the E3Kit SDK which simplifies work with Virgil services and presents an easy-to-use API for adding a security layer to any application. E3Kit interacts with Virgil Cards Service, Keyknox Service and Pythia Service.
Virgil E3kit allows you to setup user encryption with multidevice support in just a few simple steps.

## SDK Features
- multi-device support
- group chats
- manage users' Public Keys

## Installation

You can install E3Kit SDK using [Gradle](https://gradle.org/). Please, choose package that suits best for your needs:

| Package | Description |
|----------|---------|
| [`E3Kit`](./ethree-kotlin) | Standard package for Java/Kotlin with methods responses in `callbacks` |


## Usage Examples

#### Initialize e3kit

In order to interact with the Virgil Cloud, the Virgil e3kit SDK must be provided with a callback that it will call to fetch the Virgil JWT from your backend for the current user.

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

#### Register user

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

#### Sign and encrypt data/text

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

#### Decrypt data/text and verify signature

This method decrypts the data using the recipient's private key and verifies authenticity of the decrypted data with sender's public key.

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

## Samples

You can find the code samples for Java and Kotlin here:

| Sample type | 
|----------| 
| [`Android Java`](./samples/android-java) | 
| [`Android Kotlin`](./samples/android-kotlin) | 
| [`Android Java Firebase`](./samples/android-java-firebase-function) | 
| [`Android Kotlin Firebase`](./samples/android-kotlin-firebase-function) | 
| [`Android Kotlin Back4App`](./samples/android-kotlin-back4app) | 
| [`Android Kotlin Nexmo`](./samples/android-kotlin-nexmo) | 

You can run any of them on an emulator to check out the example of how to initialize the SDK, register users and encrypt messages using the E3Kit.

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Docs
Virgil Security has a powerful set of APIs, and the documentation below can get you started today.

* E3kit integrations with:
  * [Custom platform][_any_platform]
  * [Firebase][_firebase] 
  * [Twilio][_twilio] 
  * [Nexmo][_nexmo]
  * [Pubnub][_pubnub] 
* [Reference API][_reference_api]

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).

[_any_platform]: https://developer.virgilsecurity.com/docs/use-cases/v5/encrypted-communication
[_twilio]: https://developer.virgilsecurity.com/docs/use-cases/v5/encrypted-communication-for-twilio
[_nexmo]: https://developer.virgilsecurity.com/docs/use-cases/v5/encrypted-communication-for-nexmo
[_firebase]: https://developer.virgilsecurity.com/docs/use-cases/v5/encrypted-communication-for-firebase
[_pubnub]: https://developer.virgilsecurity.com/docs/use-cases/v5/smart-door-lock
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
