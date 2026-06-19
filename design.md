# Dnivio Biometric Access Verification for Tailscale

## Overview

Dnivio provides biometric step-up verification for Tailscale network access. The system extends Tailscale through forked repositories maintained under the Dnivio GitHub organization and introduces biometric approval requirements before access is granted to protected resources.

The primary authentication factor is a trusted mobile device running a modified Dnivio-enabled Tailscale application. Access approval is performed through native device biometrics such as fingerprint or facial recognition.

The solution operates across browser access, native applications, APIs, and SSH sessions while remaining platform agnostic and publicly distributable.

## Objectives

* Require biometric approval before access to protected Tailscale resources.
* Support browser-based services exposed through Tailscale.
* Support native applications and API traffic over the tailnet.
* Support SSH access to protected servers.
* Use device-native biometrics as the approval mechanism.
* Maintain compatibility across Linux, macOS, Windows, and Android.
* Operate independently from Odyn.
* Release as public tooling under Dnivio-controlled repositories.

## Architecture

### Components

#### Modified Tailscale Client

The Dnivio fork of the Tailscale client and daemon introduces:

* Access policy evaluation
* Biometric verification enforcement
* Approval request generation
* Temporary access grant validation
* Secure grant storage
* Session expiration management

#### Dnivio Approval Service

Central service responsible for:

* Device registration
* Trusted device management
* Approval request routing
* Grant issuance
* Audit logging
* Policy distribution

#### Modified Android Application

The Android application functions as the trusted approval device.

Responsibilities include:

* Receiving approval requests
* Displaying access details
* Triggering Android biometric authentication
* Generating signed approval responses
* Transmitting approval results to the Dnivio Approval Service

#### Protected Endpoints

Protected resources may include:

* HTTP services
* HTTPS services
* Internal web applications
* APIs
* TCP services
* SSH servers

## Trusted Device Model

Each user enrolls one or more trusted devices.

Trusted devices are associated with:

* User identity
* Device identity
* Cryptographic device keys
* Biometric capabilities

The trusted device becomes the second factor for protected access requests.

Access approval requires:

* Possession of the trusted device
* Successful biometric verification on that device

## Access Grant Model

Upon successful biometric verification, the approval service issues a short-lived access grant.

Each grant is bound to:

* User
* Requesting device
* Destination resource
* Protocol
* Time window

Grants cannot be reused across unrelated resources or sessions.

## Browser Access Flow

### Protected Web Services

1. User opens a protected Tailscale-hosted application.
2. Modified `tailscaled` evaluates policy requirements.
3. Access is temporarily paused.
4. An approval request is sent to the user's trusted Android device.
5. The Android application displays:

   * Resource name
   * Requesting device
   * Request time
6. User completes fingerprint or facial verification.
7. Approval response is returned.
8. Access grant is issued.
9. Browser request proceeds to the destination service.

## Application and API Access Flow

### Protected Network Services

1. Application attempts connection to a protected resource.
2. Modified `tailscaled` evaluates access policy.
3. Access request enters a pending state.
4. Approval request is delivered to the trusted Android device.
5. User verifies identity using biometrics.
6. Grant is issued.
7. Network traffic is released to the destination.

This model applies to:

* Internal APIs
* Desktop applications
* Mobile applications
* Database connections
* Custom TCP services

## SSH Access Flow

### Protected SSH Sessions

1. User initiates SSH connection.
2. Modified SSH authorization logic detects biometric requirements.
3. Approval request is generated.
4. Android application displays:

   * Hostname
   * User account
   * Requesting device
5. User completes biometric verification.
6. Approval response is validated.
7. Access grant is issued.
8. SSH session begins.

## Policy Engine

Policies determine when biometric approval is required.

Supported policy attributes include:

### Subjects

* Individual users
* User groups
* Device groups
* Tagged devices

### Destinations

* Hosts
* Tags
* Services
* Ports
* Application groups

### Protocols

* HTTP
* HTTPS
* TCP
* SSH

### Verification Frequency

* Every request
* Every connection
* Fixed duration window
* Per-session

## Android Application Design

### Core Functions

#### Approval Notifications

The application receives approval requests and presents:

* Destination name
* Requesting device
* Access type
* Timestamp

#### Biometric Verification

Uses Android's native biometric framework.

Supported methods include:

* Fingerprint
* Face authentication
* Device-supported biometric methods

#### Secure Signing

After successful verification:

* Request approval is cryptographically signed.
* Device identity is attached.
* Response is transmitted to the approval service.

### Device Enrollment

Users enroll devices through:

* Initial authentication
* Device registration
* Key generation
* Trust establishment

## Repository Structure

### Dnivio GitHub Organization

Primary repositories:

* `dnivio/tailscale`
* `dnivio/dnivio-approval-service`
* `dnivio/dnivio-android`

Additional required repositories:

* `dnivio/dnivio-packaging`
* `dnivio/dnivio-contracts`
* `dnivio/dnivio-sdk`

## Security Requirements

### Access Grants

* Short-lived
* Destination-bound
* Device-bound
* User-bound
* Non-transferable

### Device Security

* Private keys never leave the enrolled device.
* Approval requests require biometric confirmation.
* Lost devices are revoked with a hard ten-second propagation bound, and active sessions issued through the device are terminated.

### Network Security

* All approval communications are encrypted.
* Approval requests are signed.
* Replay attacks are rejected.
* Expired grants are rejected.

### Failure Behavior

If biometric verification cannot be completed:

* Browser access is denied.
* Application access is denied.
* API access is denied.
* SSH access is denied.

## Logging and Auditing

Events recorded include:

* Access requests
* Approval requests
* Approval decisions
* Grant issuance
* Grant expiration
* Device enrollment
* Device revocation

Audit records include:

* User
* Device
* Destination
* Protocol
* Timestamp
* Result

## Delivery Sequence

The sequence below controls implementation order only. No public release or general-availability designation is permitted until every sequence is complete and all browser, API, TCP, Tailscale SSH, and OpenSSH acceptance gates pass.

### Phase 1

* Fork Tailscale repositories into Dnivio GitHub.
* Implement approval service.
* Implement Android biometric approval application.
* Add browser-access enforcement.

### Phase 2

* Add SSH enforcement.
* Add generic TCP and API enforcement.
* Add grant management and auditing.

### Phase 3

* Complete signed Linux, macOS, Windows, and Android packaging and secure updates.
* Complete per-platform enforcement bypass testing.
* Publish public installation and deployment tooling.

## Non-Goals

* Replacing Tailscale networking
* Building a VPN platform
* Dependency on Odyn
* One-time password authentication
* Authenticator application codes
* SMS verification
* Email verification
* Long-lived human bypass tokens
