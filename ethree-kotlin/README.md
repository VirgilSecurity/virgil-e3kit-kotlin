[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree-kotlin/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree-kotlin)
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

You can checkout [Tests](https://github.com/VirgilSecurity/virgil-e3kit-kotlin/tree/master/tests/src/androidTest/java/com/virgilsecurity/android/ethree/kotlin/interaction) to find out more of usage examples.
