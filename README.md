# Virgil E3Kit Android SDK

[![Build Status](https://travis-ci.com/VirgilSecurity/e3kit-kotlin.svg?branch=master)](https://travis-ci.com/VirgilSecurity/e3kit-kotlin)
[![Maven Central (Standard package)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree-kotlin/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree-kotlin)
[![Maven Central (Coroutines package)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree-kotlin-coroutines/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree-kotlin-coroutines)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Install E3Kit Package](#install-e3kit-package) | [License](#license) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides an SDK which simplifies work with Virgil services and presents easy to use API for adding security to any application. In a few simple steps you can setup user encryption with multidevice support.

## SDK Features
- multidevice support
- manage users' Public Keys

## Install E3Kit Package

#### Gradle

[Gradle](https://gradle.org/) is an open-source build automation system that builds upon the concepts of Apache Ant and Apache Maven and introduces a Groovy-based domain-specific language (DSL) instead of the XML form used by Apache Maven for declaring the project configuration.

To integrate E3Kit SDK into your Android project using Gradle, add jcenter() repository if missing:

```
repositories {
    jcenter()
}
```

Set up dependencies in your `build.gradle`:

```
    implementation 'com.virgilsecurity:ethree-kotlin:<latest-version>'
```

The **\<latest-version>** of the SDK can be found in the [Maven Central Repository](https://mvnrepository.com/artifact/com.virgilsecurity/ethree-kotlin)  or in the header of current readme.

#### As well

For Kotlin (and coroutines) fans we released a special package that returns *Deferred* instead of using callbacks.
It's not intended to use with java.
To use it add next in your `build.gradle`:

```
    implementation 'com.virgilsecurity:ethree-kotlin-coroutines:<latest-coroutines-version>'
```

The **\<latest-coroutines-version>** of the SDK can be found in the [Maven Central Repository](https://mvnrepository.com/artifact/com.virgilsecurity/ethree-kotlin-coroutines)  or in the header of current readme.

Samples of usage you can find in [Tests](https://github.com/VirgilSecurity/e3kit-kotlin/tree/master/testscoroutines/src/androidTest/java/com/virgilsecurity/android/ethreeCoroutines/interaction).

#### Register User
Use the following lines of code to authenticate a user.

```kotlin

// Listener for E3Kit initialization
val initializeListener =
    object : EThree.OnResultListener<EThree> {
        override fun onSuccess(result: EThree) {
            // Init done!
        }

        override fun onError(throwable: Throwable) {
            // Error handling
        }
    }

// initialize E3Kit
EThree.initialize(context, tokenCallback, initializeListener)
```

#### Encrypt & decrypt

Virgil E3Kit lets you use a user's Private key and his or her Public Keys to sign, then encrypt text.

```kotlin

val eThree: EThree? = null

// Listener for keys lookup
val lookupKeysListener =
    object : EThree.OnResultListener<Map<String, PublicKey>> {
        override fun onSuccess(result: Map<String, PublicKey>) {
            val text = "I was a text, but become a byte array"
            val data = text.toByteArray()

            // Encrypt data using user public keys
            val encryptedData = eThree.encrypt(data, result.values.toList())

            // Encrypt message using user public keys
            val encryptedText = eThree.encrypt(text, result.values.toList())
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
EThree.initialize(context, tokenCallback, initializeListener)
```

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.slack.com/join/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).

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
