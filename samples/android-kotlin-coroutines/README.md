## E3Kit Android Kotlin Coroutines Sample

### Prerequisites 
  - Android Studio 3.2.1+
  - [Sample Backend for Java](https://github.com/VirgilSecurity/sample-backend-java) running on localhost:3000.
  
### How to start
Don't forget to setup [Sample Backend for Java](https://github.com/VirgilSecurity/sample-backend-java) first. It is a mandatory part of this sample. After this do next few steps:

```
  - git clone https://github.com/VirgilSecurity/virgil-e3kit-kotlin
  - cd virgil-e3kit-kotlin
  - git checkout dev
  - Open Android Studio -> File -> Open
  - Locate the recently cloned directory 'virgil-e3kit-kotlin' then go to 'samples/android-kotlin-coroutines' and click 'open'
```
  
After these steps you will be able to hit the `Run` button in Android Studio and get the sample to work.

If all works well - you will get Base64 string representation of encoded text on the screen and text "Success. Sample finished it's work.".

Current demo is supposed to run in an emulator while server should be running the localhost:3000 address (10.0.2.2:3000 from the emulator).
