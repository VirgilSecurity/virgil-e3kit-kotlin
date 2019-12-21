[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree-enclave/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree-enclave)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

## Installation of E3Kit Enclave

> Android API 23+ is required.

This `e3kit` module uses [Android Keystore](https://developer.android.com/training/articles/keystore) to store symmetric key which is used to encrypt `e3kit` user's local private key.
If you use this module after using [Standard e3kit module](../ethree-kotlin) all local private keys will be migrated to Android Keystore, so you won't be able to use them with [Standard e3kit module](../ethree-kotlin) any more. (You can migrate them to [Standard e3kit module](../ethree-kotlin) on your own if needed)

To integrate E3Kit SDK into your Android project using Gradle, add jcenter() repository if missing:

```
repositories {
    jcenter()
}
```

Set up dependencies in your `build.gradle`:

```
    implementation 'com.virgilsecurity:ethree-enclave:<latest-version>'
```

The **\<latest-version>** of the SDK can be found in the [Maven Central Repository](https://mvnrepository.com/artifact/com.virgilsecurity/ethree-kotlin)  or in the header of current readme.

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
            override fun onSuccess(users: FindUsersResult) {
                // encrypt text
                val encryptedMessage = ethree.authEncrypt(messageToEncrypt, users)
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
    override fun onSuccess(users: FindUsersResult) {
        // Decrypt text and verify if it was really written by Bob
        val originText = ethree.authDecrypt(encryptedText, users["bobUID"])
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
    override fun onSuccess(users: FindUsersResult) {
        val assetManager = context.assets

        assetManager.open("some_file.txt").use { inputStream ->
            ByteArrayOutputStream().use { outputStream ->
                ethree.encrypt(inputStream, outputStream, users)
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

#### Multidevice support

In order to enable multidevice support you need to backup Private Key. It wiil be encrypted with [BrainKey](https://github.com/VirgilSecurity/virgil-pythia-x), generated from password and sent to virgil cloud.

```kotlin
val backupListener =
    object : OnCompleteListener {
        override fun onSuccess() {
            // Private Key successfully backuped
        }

        override fun onError(throwable: Throwable) {
            // Error handling
        }
    }

eThree.backupPrivateKey(userPassword).addCallback(backupListener)
```

After private key was backuped you can use `restorePrivateKey` method to load and decrypt Private Key from virgil cloud.

```kotlin
val restoreListener =
    object : OnCompleteListener {
        override fun onSuccess() {
            // Private Key successfully restored and saved locally
        }

        override fun onError(throwable: Throwable) {
            // Error handling
        }
    }

eThree.restorePrivateKey(keyPassword).addCallback(restoreListener)
```

If you authorize users using password in your application, please do not use the same password to backup Private Key, since it breaks e2ee. Instead, you can derive from your user password two different ones.

```kotlin
    val derivedPasswords = EThree.derivePasswords(userPassword)

    // This password should be used for backup/restore PrivateKey
    val backupPassword = derivedPasswords.backupPassword
    // This password should be used for other purposes, e.g user authorization
    val loginPassword = derivedPasswords.loginPassword
```


#### Convinience initializer

`EThree` initializer has plenty of optional parameters to customize it's behaviour. You can easily set them using `EThreeParams` class.

```kotlin     
    val params = EThreeParams(identity = "Alice",
                              tokenCallback = tokenCallback,
                              context = context)

    params.enableRatchet = true
    params.keyChangedCallback = myCallback

    val ethree = EThree(params = params)
```

## Enable Group Channel

In this section, you'll find out how to build a group channel using the Virgil E3Kit.

We assume that your users have installed and initialized the E3Kit, and used snippet above to register.

#### Create group channel

Let's imagine Alice wants to start a group channel with Bob and Carol. First, Alice creates a new group ticket by running the `createGroup` feature and the E3Kit stores the ticket on the Virgil Cloud. This ticket holds a shared root key for future group encryption.

Alice has to specify a unique `identifier` of group with length > 10 and `findUsersResult` of participants. We recommend tying this identifier to your unique transport channel id.

```kotlin 
ethree.createGroup(groupId, users).addCallback(object : OnResultListener<Group> {
    override fun onSuccess(group: Group) {
        // Group created and saved locally!
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
})
```

#### Start group channel session

Now, other participants, Bob and Carol, want to join the Alice's group and have to start the group session by loading the group ticket using the `loadGroup` method. This function requires specifying the group `identifier` and group initiator's Card.

```kotlin
ethree.loadGroup(groupId, users["Alice"]!!).addCallback(object : OnResultListener<Group> {
    override fun onSuccess(group: Group) {
        // Group loaded and saved locally!
    }

    override fun onError(throwable: Throwable) {
        // Error handling
    }
})
```

Use the `loadGroup` method to load and save group locally. Then, you can use the `getGroup` method to retrieve group instance from local storage.

```kotlin
val group = ethree.getGroup(groupId)
```

#### Encrypt and Decrypt Messages

To encrypt and decrypt messages, use the `encrypt` and `decrypt` E3Kit functions, which allows you to work with data and strings.

Use the following code-snippets to encrypt messages:

```kotlin
// prepare a message
val messageToEncrypt = "Hello, Bob and Carol!"

val encrypted = group.encrypt(messageToEncrypt)
```

Use the following code-snippets to decrypt messages:

```kotlin
val decrypted = group.decrypt(encrypted, users["Alice"]!!)
```
At the decrypt step, you also use `findUsers` method to verify that the message hasn't been tempered with.

### Manage Group Channel

E3Kit also allows you to perform other operations, like participants management, while you work with group channel. In this version of E3Kit only group initiator can change participants or delete group.

#### Add new participant

To add a new channel member, the channel owner has to use the `add` method and specify the new member's Card. New member will be able to decrypt all previous messages history.

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

#### Update group channel

In the event of changes in your group, i.e. adding a new participant, or deleting an existing one, each group channel participant has to update the encryption key by calling the `update` E3Kit method or reloading Group by `loadGroup`.

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

#### Delete group channel

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

## Double Ratchet Channel
In this section, you'll find out how to create and manage secure channel sessions between two users using the Double Ratchet algorithm so that each message is separately encrypted.

**Double Ratchet** is a session key management algorithm that provides extra secure end-to-end encryption for messaging between two users or endpoints. 
The Double Ratchet algorithm provides perfect forward secrecy and post-compromise security by generating unique session keys for each new message. Even if the communication is somehow compromised, a potential attacker will only be able to access the most recent message, and soon as a new message is sent by one of the two users, the attacker will be locked out again. 

The session keys are generated using a cryptographically strong unidirectional function, which prevents an attacker from potentially obtaining earlier keys derived from later ones. In addition, the parties renegotiate the keys after each message sent or received (using a new key pair unknown to the attacker), which makes it impossible to obtain later keys from earlier ones.

We assume that you have installed and initialized the E3Kit, and your application users are registered using the snippet above.

#### Create channel

To create a peer-to-peer connection using Double Ratchet protocol use the folowing snippet
```kotlin
ethree.createRatchetChannel(users["Bob"])
        .addCallback(object : OnResultListener<RatchetChannel> {
            override fun onSuccess(result: RatchetChannel) {
                // Channel created and saved locally!
            }

            override fun onError(throwable: Throwable) {
                // Error handling
            }

        })
```

#### Join channel

After someone created channel with user, he can join it

```kotlin
ethree.joinRatchetChannel(users["Bob"])
        .addCallback(object : OnResultListener<RatchetChannel> {
            override fun onSuccess(result: RatchetChannel) {
                // Channel joined and saved locally!
            }

            override fun onError(throwable: Throwable) {
                // Error handling
            }

        })
```

#### Get channel

After joining or creating channel you can use getRatchetChannel method to retrieve it from local storage.
```kotlin
val channel = ethree.getRatchetChannel(users["Alice"])
```

#### Delete channel

Use this snippet to delete channel from local storage and clean cloud invite.

```kotlin
ethree.deleteRatchetChannel(users["Bob"])
        .addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                // Channel was deleted!
            }

            override fun onError(throwable: Throwable) {
                // Error handling
            }
        })
```

#### Encrypt and decrypt messages

Use the following code-snippets to encrypt messages:
```kotlin
// prepare a message
val messageToEncrypt = "Hello, Bob!"

val encrypted = channel.encrypt(messageToEncrypt)
```

Use the following code-snippets to decrypt messages:
```kotlin
val decrypted = channel.decrypt(encrypted)
```

## Unregistered User Encryption
In this section, you'll learn how to create and use temporary channels in order to send encrypted data to users not yet registered on the Virgil Cloud. 

Warning: the temporary channel key used in this method is stored unencrypted and therefore is not as secure as end-to-end encryption, and should be a last resort after exploring the preferred [non-technical solutions](https://help.virgilsecurity.com/en/articles/3314614-how-do-i-encrypt-for-a-user-that-isn-t-registered-yet-with-e3kit).

To set up encrypted communication with unregistered user not yet known by Virgil, the channel creator generates a temporary key pair, saves it unencrypted on Virgil Cloud, and gives access to the identity of the future user. The channel creator uses this key for encryption. Then when the participant registers, he can load this temporary key from Virgil Cloud and use to decrypt messages.

We assume that channel creator has installed and initialized the E3Kit, and used the snippet above to register.

#### Create channel

To create a channel with unregistered user use the folowing snippet
```kotlin
ethree.createTemporaryChannel("Bob")
        .addCallback(object : OnResultListener<TemporaryChannel> {
            override fun onSuccess(result: TemporaryChannel) {
                // Channel created and saved locally!
            }

            override fun onError(throwable: Throwable) {
                // Error handling
            }
        })
```

#### Load channel

After user is registered, he can load temporary channel
```kotlin
ethree.loadTemporaryChannel(asCreator = false, identity = "Bob")
        .addCallback(object : OnResultListener<TemporaryChannel> {
            override fun onSuccess(result: TemporaryChannel) {
                // Channel loaded and saved locally!
            }

            override fun onError(throwable: Throwable) {
                // Error handling
            }
        })
    }
```

If channel creator changes or cleans up their device, he can load temporary channel in simular way
```kotlin
ethree.loadTemporaryChannel(asCreator = true, identity = "Bob")
        .addCallback(object : OnResultListener<TemporaryChannel> {
            override fun onSuccess(result: TemporaryChannel) {
                // Channel loaded and saved locally!
            }

            override fun onError(throwable: Throwable) {
                // Error handling
            }
        })
    }
```

#### Get channel

After loading or creating channel, you can use getTemporaryChannel method to retrieve it from local storage
```kotlin
val channel = ethree.getTemporaryChannel("Alice")
```

#### Delete channel

Use this snippet to delete channel from local storage and clean cloud invite

```kotlin
ethree.deleteTemporaryChannel("Bob")
        .addCallback(object : OnCompleteListener {
            override fun onSuccess() {
                // Channel was deleted!
            }

            override fun onError(throwable: Throwable) {
                // Error handling
            }
        })
```

You can checkout [Tests](https://github.com/VirgilSecurity/virgil-e3kit-kotlin/tree/master/tests/src/androidTest/java/com/virgilsecurity/android/ethree/) to find out more of usage examples.
