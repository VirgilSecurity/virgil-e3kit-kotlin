[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree-kotlin/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/ethree-kotlin)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

## Installation of E3Kit

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

You can checkout [Tests](https://github.com/VirgilSecurity/e3kit-kotlin/tree/master/tests/src/androidTest/java/com/virgilsecurity/android/ethree/kotlin/interaction) to find out more of usage examples.
