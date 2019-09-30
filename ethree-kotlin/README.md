[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

## Installation of E3Kit

> Android API 21+ is required.

To integrate E3Kit SDK into your Android project using Gradle, add jcenter() repository if missing:

```
repositories {
    jcenter()
}
```

Set up dependencies in your `build.gradle`:

```
    implementation 'com.virgilsecurity:ethree:<latest-version>'
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

You can checkout [Tests](https://github.com/VirgilSecurity/virgil-e3kit-kotlin/tree/master/tests/src/androidTest/java/com/virgilsecurity/android/ethree/) to find out more of usage examples.
