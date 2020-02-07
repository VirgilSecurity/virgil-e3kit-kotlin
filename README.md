# Virgil E3Kit Android

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-e3kit-kotlin.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-e3kit-kotlin)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)



[Introduction](#introduction) | [Benefits](#benefits) | [Features](#features) | [Installation](#installation) | [Docs](#docs) | [Demo](#demo) | [Samples](#samples) | [License](#license) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="100px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/e3kit/E3Kit.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides the [E3Kit](https://developer.virgilsecurity.com/docs/e3kit/) - an open-source client-side framework that allows developers to add end-to-end encryption to their messaging applications, file sharing programs, and other digital communication products in just a few simple steps to become HIPAA and GDPR compliant and more.

## Benefits

- Easy to setup and integrate into new or existing projects
- Compatible with any CPaaS provider, including Nexmo, Firebase, Twilio, PubNub and etc.
- Strong secret keys storage, integration with Keychain
- Provides GDPR and HIPAA compliance

## Features

- Strong one-to-one and group encryption
- Files and stream end-to-end encryption
- Data signature and verification as part of the encrypt and decrypt functions
- Recoverable private encryption keys
- Access to encrypted data from multiple user devices
- Perfect forward secrecy with the Double Ratchet algorithm

## Installation

You can install E3Kit SDK using [Gradle](https://gradle.org/). Please, choose package that suits best for your needs:

| Package | Description |
|----------|---------|
| [`E3Kit`](./ethree-kotlin) | Standard package for Android API 21+ (Java/Kotlin) |
| [`E3Kit`](./ethree-enclave) | Package with [Android Keystore](https://developer.android.com/training/articles/keystore) for Android API 23+ |

## Resources

- [Developer Documentation](https://developer.virgilsecurity.com/docs/e3kit/) - start integrating E3Kit into your project with our detailed guides.
- [Quickstart Demo](https://developer.virgilsecurity.com/docs/e3kit/get-started/quickstart/) - will help you to get started with the Virgil E3Kit quickly, and to learn some common ways to build end-to-end encryption between two fictional characters Alice and Bob.
- [E3Kit Kotlin API Reference](https://virgilsecurity.github.io/virgil-e3kit-kotlin/) - E3Kit API reference for the language of your choice.


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

You can run the samples to find out how to initialize the SDK, register users and encrypt messages using E3Kit.

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support

Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
