Mute — short protocol and system overview
-----------------------------------------

Mute is an asynchronous, SMTP-based and privacy enhancing communication system.


### Design and implementation goals

- All communication between users is to be encrypted end-to-end.
- Communication should accomplish Forward Secrecy in the sense that keys
  required to decrypt past messages are frequently replaced and destroyed.
- Establish Forward Secret communication with first message (no synchronous
  two-way handshake).
- Asynchronous communication between peers.
- Authenticity of the Identity-Key relationship must be established and
  preserved.
- Identities shall be human-readable/human-memorizable (human-friendly
  identities).
- Communication should rely on established standards where possible, as in using
  SMTP as the transport protocol.
- Sending messages and changing the state of one's own identity requires payment
  by the user to both finance the system and to limit SPAM.
- Better-than-nothing anonymity: Mixing/Delaying of messages to prevent simply
  discovery of sender/recipient relationship by third party passive observer.
- Both sender and recipient anonymity.
- Some plausible deniability of message content and communication relationship.


### Components

- Key Repository: To make public signature keys of identities available.
- KeyInit Repository: To make Forward Secrecy keys available for session
  initialization between peers.
- Key HashChain: To provide Identity-Key authenticity.
- Mix: Provide anonymity by implementing Stop-Foward-Mixing and relaying.
- ServiceGuard: Token-based internal authentication and authorization provider.
- Storage: SMTP-ATRN capable mailbox/mail queue storage.
- User application.
- Helper components: Token faucet.


### Protocols

- For message transfer (both sending and receiving): SMTP, with ATRN extension
  for receiving.
- MIME-encoded JSON packages for application-to-application communication,
  attached to messages.
- JSON-RPC over HTTPS for all other communication.


### Encodings

Mute-specific encodings are in JSON. Signature creation and verification makes
it necessary that a well-defined order and naming of fields is established.

Always:
- Keys are converted to uppercase and may not include any whitespace.
- No indention is used, no unnecessary whitespace for element separation.
- All binary data is encoded as base64 with full padding.

Unless explicitely stated otherwise:	
- All optional fields are present but set to the zero value.
- Fields are ordered lexicographically by field name/key.
- In cases where lists of equal alternatives (keys for different ciphersuits,
  addresses etc) are given, they are encoded as array ordered by the _hash_ of
  their _primary member_.
- In cases where preferences are communicated, the array is to be ordered in the
  order of descending preference (more preferred option first).
- In cases where chronological data is given, the array is to be ordered in
  incremental chronological order (oldest entry first).
- In all other cases the order is to be lexicographical by _primary member_.

Explanations:
- _Hashes_ are to be created for binary data before the data is encoded by
  base64 (hash over "raw" data).
- _Primary member_: This is the user-/dataset-specific content, not the metadata
  describing it. In the case of a key this would be the key's content, not the
  ciphersuit/algorithm used.


### Architecture overview

![Mute architecture](https://rawgit.com/mutecomm/mute/master/doc/figures/architecture.svg)
