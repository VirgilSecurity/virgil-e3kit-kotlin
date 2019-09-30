# Virgil E3Kit Android SDK

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-e3kit-kotlin.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-e3kit-kotlin)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [SDK Features](#features) | [Installation](#installation) | [Usage Examples](#usage-examples) | [Enable Group Chat](#enable-group-chat) | [Samples](#samples) | [License](#license) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides the E3Kit which simplifies work with Virgil Cloud and presents an easy-to-use API for adding a security layer to any application. In a few simple steps you can add end-to-end encryption with multidevice and group chats support.

The E3Kit allows developers to get up and running with Virgil API quickly and add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

##  Features
- Strong end-to-end encryption with authorization
- One-to-one and group encryption
- Files and stream encryption
- Recovery features for secret keys
- Strong secret keys storage, integration with Keychain
- Integration with any CPaaS providers like Nexmo, Firebase, Twilio, PubNub, etc.
- Public keys cache features
- Access encrypted data from multiple user devices
- Easy setup and integration into new or existing projects

## Installation

You can install E3Kit SDK using [Gradle](https://gradle.org/). Please, choose package that suits best for your needs:

| Package | Description |
|----------|---------|
| [`E3Kit`](./ethree-kotlin) | Standard package for Android API 21+ (Java/Kotlin) |
| [`E3Kit`](./ethree-enclave) | Package with [Android Keystore](https://developer.android.com/training/articles/keystore) for Android API 23+ |


## Usage Examples

> Be sure to import `OnCompleteListener` and `OnResultListener` from `com.virgilsecurity.common.callback`.

#### Register user
Use the following lines of code to authenticate user.

```kotlin
// initialize E3Kit
val ethree = EThree(identity = "Bob", tokenCallback = tokenCallback, context = context)

ethree.register().addCallback(object : OnCompleteListener {
    override fun onSuccess() {
        // Done
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
})
```

#### Encrypt & decrypt

Virgil E3Kit lets you use a user's Private key and his or her Card to sign, then encrypt text.

```kotlin
// TODO: init and register user (see Register User)

// prepare a message
val messageToEncrypt = "Hello, Alice and Den!"

// Search user's Cards to encrypt for
ethree.findUsers(listOf("Alice, Den"))
        .addCallback(object : OnResultListener<FindUsersResult> {
            override fun onSuccess(result: FindUsersResult) {
                // encrypt text
                val encryptedMessage = ethree.encrypt(messageToEncrypt, result)
            }

            override fun onError(throwable: Throwable) {
                // Error handling
            }
        })
```

Decrypt and verify the signed & encrypted data using sender's public key and receiver's private key:

```kotlin
// TODO: init and register user (see Register User)

// Find user
ethree.findUsers(listOf("bobUID"))
        .addCallback(object : OnResultListener<FindUsersResult> {
    override fun onSuccess(result: FindUsersResult) {
        // Decrypt text and verify if it was really written by Bob
        val originText = ethree.decrypt(encryptedText, result["bobUID"])
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
})
```

#### Encrypt & decrypt large files

If the data that needs to be encrypted is too large for your RAM to encrypt all at once, use the following snippets to encrypt and decrypt streams.

Encryption:
```kotlin
// TODO: init and register user (see Register User)
// TODO: Get users UIDs

val usersToEncryptTo = listOf(user1UID, user2UID, user3UID)

// Find users
ethree.findUsers(usersToEncryptTo)
        .addCallback(object : OnResultListener<FindUsersResult> {
    override fun onSuccess(result: FindUsersResult) {
        val assetManager = context.assets

        assetManager.open("some_file.txt").use { inputStream ->
            ByteArrayOutputStream().use { outputStream ->
                ethree.encrypt(inputStream, outputStream, result)
            }
        }
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
})
```

Decryption:
> Stream encryption doesn’t sign the data. This is why decryption doesn’t need Card for verification unlike the general data decryption.
```kotlin
// TODO: init and register user (see Register User)

ByteArrayOutputStream().use { outputStream ->
    eThree.decrypt(encryptedStream, outputStream)
}
```

## Enable Group Chat
In this section, you'll find out how to build a group chat using the Virgil E3Kit.

We assume that your users have installed and initialized the E3Kit, and used snippet above to register.


#### Create group chat
Let's imagine Alice wants to start a group chat with Bob and Carol. First, Alice creates a new group ticket by running the `createGroup` feature and the E3Kit stores the ticket on the Virgil Cloud. This ticket holds a shared root key for future group encryption.

Alice has to specify a unique `identifier` of group with length > 10 and `findUsersResult` of participants. We recommend tying this identifier to your unique transport channel id.
```kotlin 
ethree.createGroup(groupId, users).addCallback(object : OnResultListener<Group> {
    override fun onSuccess(result: Group) {
        // Group created and saved locally!
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
})
```

#### Start group chat session

Now, other participants, Bob and Carol, want to join the Alice's group and have to start the group session by loading the group ticket using the `loadGroup` method. This function requires specifying the group `identifier` and group initiator's Card.
```kotlin
ethree.loadGroup(groupId, users["Alice"]!!).addCallback(object : OnResultListener<Group> {
    override fun onSuccess(result: Group) {
        // Group loaded and saved locally!
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
})
```

Use the loadGroup method to load and save group locally. Then, you can use the getGroup method to retrieve group instance from local storage.
```kotlin
val group = ethree.getGroup(groupId)
```

#### Encrypt and decrypt messages
To encrypt and decrypt messages, use the `encrypt` and `decrypt` E3Kit functions, which allows you to work with data and strings.

Use the following code-snippets to encrypt messages:
```kotlin
// prepare a message
val messageToEncrypt = "Hello, Bob and Carol!"

val encrypted = group.encrypt(messageToEncrypt)
```

Use the following code-snippets to decrypt messages:
```kotlin
val decrypted = group.decrypt(encrypted, findUsersResult["Alice"]!!)
```
At the decrypt step, you also use `findUsers` method to verify that the message hasn't been tempered with.

### Manage group chat
E3Kit also allows you to perform other operations, like participants management, while you work with group chat. In this version of E3Kit only group initiator can change participants or delete group.

#### Add new participant
To add a new chat member, the chat owner has to use the `add` method and specify the new member's Card. New member will be able to decrypt all previous messages history.
```kotlin
group.add(users["Den"]!!).addCallback(object : OnCompleteListener {
    override fun onSuccess() {
        // Den was added!
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
})
```

#### Remove participant
To remove participant, group owner has to use the `remove` method and specify the member's Card. Removed participants won't be able to load or update this group.
```kotlin
group.remove(users["Den"]!!).addCallback(object : OnCompleteListener {
    override fun onSuccess() {
        // Den was removed!
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
})
```

#### Update group chat
In the event of changes in your group, i.e. adding a new participant, or deleting an existing one, each group chat participant has to update the encryption key by calling the `update` E3Kit method or reloading Group by `loadGroup`.
```kotlin
group.update().addCallback(object : OnCompleteListener {
    override fun onSuccess() {
        // Group updated!
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
})
```

#### Delete group chat
To delete a group, the owner has to use the `deleteGroup` method and specify the group `identifier`.
```kotlin
ethree.deleteGroup(groupId).addCallback(object : OnCompleteListener {
    override fun onSuccess() {
        // Group was deleted!
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
})
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
