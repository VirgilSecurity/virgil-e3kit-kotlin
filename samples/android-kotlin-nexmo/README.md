## E3Kit Nexmo Kotlin Demo

### Prerequisites 
  - Android Studio 3.3.2+
  - [Sample Java Backend for Nexmo](https://github.com/VirgilSecurity/demo-nexmo-chat-backend-java) running on localhost:3000.
  
### How to start
Don't forget to setup [Sample Java Backend for Nexmo](https://github.com/VirgilSecurity/demo-nexmo-chat-backend-java) first. It is a mandatory part of this demo. After this do next few steps:

```
  - Open Android Studio -> File -> New -> Project from Version Control -> Git
  - Enter `https://github.com/VirgilSecurity/demo-nexmo-chat-e3kit-android`
```
  
> If you have any errors - first try to log out and log in again. This is a simple demo without proper error handling - it's up to you.
  
After these steps you will be able to hit the `Run` button in Android Studio and get the sample to work.

You can `Log In` only once because authorization system in [Sample Java Backend for Nexmo](https://github.com/VirgilSecurity/demo-nexmo-chat-backend-java) is just an example - you have to replace it with your own authorization system, that will support SignIn/SignUp. So `Log In` every time with new user to test this demo out.

Current demo is supposed to run in an emulator while server should be running the localhost:3000 address (10.0.2.2:3000 from the emulator).
