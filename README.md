# Zero Touch Provisioning Demonstrator

## Introduction

SEALSQ Zero Touch Provisioning (ZTP) provides an out-of-the-box, simple and cost effective way to provision over-the air and securely digital certificates and private key in the device directly in the field.

This significantly reduces the operational burden and simplifies the  overall  “ device on-boarding” workflow  to the IoT platform.

## Prerequisites

- INeS Account
- Raspberry Pi 4
- An access to git.sealsq.com (ask sales@sealsq.com to get an account)



## Vocab

Crypto world can be complicated to understand, here is some words you need to know :

|||
|--|--|
| Certificate |A certificate is an file that contains an identification, to link this certificate to a device, the certificate contains the public key derivative of the device's private key.  It is like your ID card with your unique face printed on it |
| Private Key |Private key is a unique key stored in the device, only this device is supposed to have this key, to improve security and non-repudiation, this key is supposed to be stored into a secure element (like a SEALSQ Vault-IC 292 or 408) |
|Certificate Authority|A Certificate Authority is signing the certificate to prove the legitimacy of the certificate, some CAs are publicly trusted like SEALSQ (**OISTE WISeKey Global Root**) |
|PKI|Public Key Infrastructure is an entity that is able to manage certificates and digital identity, SEALSQ  PKI is named **INeS**|
|EST|Enrollment over Secure Transport is a standardized PKI protocol to get certificates, INeS can provide this protocol|


## How works SEALSQ Zero Touch Provisioning with INeS ?

Before ZTP, the device must have is own factory Certificate and Key, this identify is used by INeS, You can generate this Factory Certtificate and Key on INeS CMS and copy it on your device

When you launch the ZTP demo, the device generates a key pair (Operational Key) and signs a CSR (Certificate Signing Request) with it. This CSR is sent by the device to an EST server provided by INeS, it authenticates based on the Factory Certificate, INeS recognizes the device and signs the CSR to generate an Operational Certificate.

The device has now an Operational Certificate. If needed, the device can ask multiple certificates, a certficate to connect to OEM server, one for software update server and one for IoT data server for example.


## INeS Configuration
To automate the process, INeS needs some configuration to recognize the device that needs a certificate, is allowed to get one.

You have to contact a SEALSQ sales person to get more information and also to obtain an INeS account.

You have to configure :
 - A Certificate Authority that will sign your certificate, it will be a sub-CA of SEALSQ CA
 - A certificate Template that specifies the mandatory informations in the certificate that will be generated
 - A device type 


## AWS
Amazon Web Service is used in our demonstration to show how the certificates generated can be used for

## Launch Zero Touch Provisioning Application
**On your raspberry**

clone this Repo :

    git clone git@github.com:sealsq/Zero-Touch-Provisioning.git

update submodule

    git submodule update --init

We write scripts to simplify compilation, so make them executable

    chmod +x configure.sh

Update informations in configuration file

    nano data/inesConfig.ini

Execute the program

    ./build/zeroTouchProvisioning_app data/inesConfig.ini
