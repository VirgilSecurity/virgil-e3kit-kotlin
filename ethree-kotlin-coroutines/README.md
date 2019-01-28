[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree-kotlin-coroutines/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree-kotlin-coroutines)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

## Installation of E3Kit Coroutines

For Kotlin (and coroutines) fans we released a special package that returns [`Deferred`](https://kotlin.github.io/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines/-deferred/) instead of using callbacks.
It's not intended to use with java.
To use it add next in your `build.gradle`:

```
    implementation 'com.virgilsecurity:ethree-kotlin-coroutines:<latest-version>'
```

The **\<latest-version>** of the SDK can be found in the [Maven Central Repository](https://mvnrepository.com/artifact/com.virgilsecurity/ethree-kotlin-coroutines)  or in the header of current readme.

## Usage

#### Register User
Use the following lines of code to authenticate a user.

```kotlin
// initialize E3Kit
val eThree = EThree.initialize(context, tokenCallback).await()
```

#### Encrypt & decrypt

Virgil E3Kit lets you use a user's Private key and his or her Public Keys to sign, then encrypt text.

```kotlin

val eThree = EThree.initialize(context) { yourService.getVirgilToken() }.await()

val keys = eThree.lookupPublicKeys(listOf("AliceUUID", "BobUUID")).await()

val text = "I was a text, but become a byte array"
val data = text.toByteArray()

// Encrypt data using user public keys
val encryptedData = eThree.encrypt(data, keys.values.toList())

// Encrypt message using user public keys
val encryptedText = eThree.encrypt(text, keys.values.toList())

// E3Kit using identity that specified in Jwt provided with *virgilTokenCallback*
val sendersKeys = eThree.lookupPublicKeys(listOf(identityInToken)).await()

// Decrypt data using senders public key (In this example it's E3Kit current user)
val decryptedData = eThree.decrypt(encryptedData, sendersKeys[identityInToken])

// Decrypt data using senders public key (In this example it's E3Kit current user)
val decryptedText = eThree.decrypt(encryptedText, sendersKeys[identityInToken])
```

You can checkout [Tests](https://github.com/VirgilSecurity/virgil-e3kit-kotlin/tree/master/testscoroutines/src/androidTest/java/com/virgilsecurity/android/ethreeCoroutines/interaction) to find out more of usage examples.
