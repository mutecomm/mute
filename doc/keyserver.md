Keyserver design
----------------


### Components

The function of the keyserver is to:
- Make public keys required for peer-identification available:
  **Who** has sent me a message?
- Make public keys required for content-confidentiality available:
  **How** do I encrypt a message?
- Make addresses required to contact a peer available:
  **Where** do I send a message?
- Increase authenticity of identities:
  **Why** should I trust a public key to belong to a specific person?

Goals:
- Allow independent verification of keyserver integrity by any number of users.
- Support short-lived encryption keys and address: Forward Security.
- Assure that all identifiers are unique.
- Allow the use of short, human-readable pseudonyms as sufficiently secure
  anchors of key authenticity.
- Prevent full enumaration of user pseudonyms even if all public data is
  available.
- Allow users to prove if the keyserver is ill-behaving.

These functions are implemented by three interrelated components:
- The Key Repository:
  Here long-term public keys and public recipient addresses of the system's
  participants are stored and available for lookup.
  The primary function that is accomplished by the Key Repository is to provide
  peer-identification and link the various keys published by a user.
  In addition, it provides the necessary data for addressing and initial content
  confidentiality in case other components are temporarily insufficient to
  accomplish these.
- The KeyInit Repository:
  Here temporary/short-lived public keys and public recipeint addresses of the
  participants are stored and available for consumption (lookup then delete).
  This provides addressing and content-confidentiality functions.
- The Key Hashchain:
  Every change of long-term public identity information in the Key Repository is
  recorded in the permanent Key Hashchain.
  It guarantees the order of events and assures—in combination with a specific
  usage scheme—key authenticity.
  Furthermore the Key Hashchain serves as index to facilitate Key Repository
  lookups. The Key Hashchain is public and at least partially known to each
  participant of the system.

In short:
- The Key Hashchain establishes the link between a claimed pseudonym and a long
  term public signature key of that pseudonym.
- The Key Hashchain indexes the Key Repository which holds the long term public
  signature key.
- The KeyInit Repository holds the temporary public encryption keys and
  addresses of the pseudonym, verified by the public signature key.


### Simplified use-cases

#### To look up a key from the keyserver

Given a pseudonym for which the key is to be looked up, the user searches the
Key Hashchain in chronological order, testing if the entry matches the
pseudonym. In case of a match, the user requests the key referenced by the entry
from the keyserver. The user continues the search on the Key Hashchain until the
last-known entry has been processed. Should there be more than one matching
entry, the user needs to verify that the entry N has been signed by the key
published by entry N-1. If the verification matches for the whole set of
entries, the lookup has been successful. The user may increase the assurance
concerning the integrity and authenticity of the Key Hashchain by exchanging
information about the last known entries with known peers. This establishes
trust in that the Key Hashchain has not been falsified, reorderd or selectively
created, giving the user a high assurance that the pseudonym indeed links to one
specific key (key authenticity).


#### To publish a pseudonym

The user creates a human-readable/human-memorizable pseudonym and verifies that
no Key Hashchain entry matches it already (that is, he verifies that the
pseudonym is not yet taken).
He then creates a signature key pair and signs the pseudonym and public key with
the private key. The resulting message is sent to the Keyserver.
After verifying that the pseudonym is not yet taken, the keyserver enters the
pseudonym and key into the Key Hashchain and Key Repository, respectively.
The Keyserver then replies with a signed statement confirming to the user that
the pseudonym has been registered in the hashchain.
At this point the user can verify the publishing of the pseudonym in the Key
Hashchain and optionally wait some time before announcing his pseudonym to
others. If this order—creation, publication, keyserver confirmation,
verification, announcement—is observed, the authenticity of the pseudonym-key
relationship is assured.


### API

The Keyserver is to provide the following public JSON-RPC API:


#### Mandatory

`KeyRepository.Capabilities()`

Return keyserver capabilities:
- methods implemented
- domains served
- Key Repository URIs
- KeyInit Repository URIs
- Key Hashchain URIs
- last Key Hashchain entry
- public wallet key of keyserver
- public signature key(s) of keyserver

Reply is signed by current keyserver signature key.


`KeyRepository.FetchUID(UIDIndex)`

Return the encrypted UID message specified by UIDIndex from the Key Repository.


`KeyInitRepository.FetchKeyInit(SigKeyHash)`

Return the current encrypted KeyInit message specified by SigKeyHash from the
KeyInit Repository.


`KeyHashchain.FetchHashChain(startPosition [,endPosition])`

Return the Key Hashchain entries between startPosition and optional endPosition.
If endPosition is omitted, only return one entry at startPosition. If position
at startPosition does not exist yet, return last entry.


`KeyHashchain.FetchLastHashChain()`

Return last Hashchain entry.


`KeyRepository.GetLink(domain)`

Return the Identity and Position of the first Authorative entry for the
Chainlink to the domain. (see below: "Linking chains and key repositories")


`KeyRepository.CreateUID(UIDMessage[,Token])`

Add the UID to the Key Hashchain and Key Repository if the identity is not known
yet.
Return a signed confirmation consisting of UID message and Key Hashchain entry
where the UID was added.


`KeyRepository.UpdateUID(UIDMessage[,Token])`

Update the UID message for an identity if the signature(s) on the new UIDMessage
match the keys present in the previous UIDMessage for the same identity.
Return a signed confirmation consisting of UID message and Key Hashchain entry
where the UID was added.


`KeyInitRepository.AddKeyInit(SigPubKey, KeyInits[,Token])`

Add one or more KeyInit messages to the KeyInit Repository if the messages are
signed by the corresponding signature public key.
Return a signed confirmation consisting of the KeyInit.	


#### Optional / restricted

`KeyHashchain.LookupUID(pseudonym)`

Return all Key Hashchain entries referring to pseudonym.


`KeyInitRepository.FlushKeyInit(SigPubKey, Nonce, Signature)`

Flush all keys in the KeyInit Repository for this SigPubKey. Call must be
signed/authenticated by a Signature over Nonce (which is the current 64bit
unixtime).


### Identity/pseudonym format

The pseudonym is of the format `localpart@domain` (e.g.,
`identity@mute.berlin`). The pseudonym **may** only contain printable lowercase
characters of the latin alphabet, the digits `2`-`9` and the special characters
dash (`-`), at (`@`), and dot (`.`).
For comparison-reasons, all occurrences of the digit `1` **must** be translated
to the lower-case letter `l` (Lima), all occurrences of the digit `0` **must**
be translated to the lower-case letter `o` (Oscar), and all occurrences of the
lower-case letter `j` (Juliett) **must** be translated to the lower-case letter
`i` (India).
The digit translation serves the purpose of reducing the cases of mistaken
spelling in copy&paste-scenarios in which an attacker tries to slip a
similar-looking name past the attention of the user.


### General message format

Messages are encoded as JSON according to the global encoding rules (see
[overview](https://github.com/mutecomm/mute/blob/master/doc/overview.md)):
- All optional fields are present but set to the zero value.
- Keys are converted to uppercase and may not include any whitespace.
- No indention is used, no unnecessary whitespace for element separation.
- All binary data is encoded as base64 with full padding.
- Fields are ordered lexicographically by field name/key.
- In cases where lists of cryptographic keys for different ciphersuites are
  given, they are encoded as array and ordered by the hash of binary
  cryptographic key (before base64 encoding).

#### Common fields

Messages share certain common fields:
- `VERSION`: The protocol version, as string. E.g. "0.1a".
- `MSGCOUNT`: Integer that must increase for each message of the same type for
  the same user. Encoded as JSON integer.
- `NOTAFTER`: 64bit unixtime after which the key(s) offered by the message
  should not be used anymore. Encoded as JSON integer.
- `NOTBEFORE`: 64bit unixtime before which the key(s) offered by the message
  should not be used yet. Encoded as JSON integer.


#### Lists of cryptographic keys

Mute supports the use of multiple ciphersuites. This makes it necessary to
communicate multiple keys per message to give the peer a choice to operate from.
Lists of keys are arrays ordered by the hash of the included keys, each entry
consisting of:

```
struct KeyEntry{
  CIPHERSUITE. Ciphersuite for which the key may be used. Example:
               "ECIES25519 KDF3 AES-CTR256 SHA512-HMAC ED25519 ECDHE25519"
  FUNCTION. Function for which the key may be used in the ciphersuite. Example:
            "ECIES25519"
  HASH. SHA512 hash of PUBKEY.
  PUBKEY. The public key.
}
```

During encoding, the binary value of `HASH` can be used to determine the order
of the array containing multiple keys. `HASH` and `PUBKEY` will be encoded
base64.


### Key Repository operation

The key repository maintains a publicly accessible repository of valid signature
key entries for peer identification purposes. To add a key, the user generates a
`UIDMessage` and sends it to the Key Repository.
After validation the `UIDMessage` is added to the Key Repository and the Key
HashChain, and a signed confirmation is returned to the user.


#### UIDMessage

This message contains the necessary keys and other data to serve as peer
identification and optional fallback for addressing and content confidentiality.
It is self-signed by the user and counter-signed by the keyserver after being
added to the Key Repository.

Format:

To be sent from user to server.

```
struct UIDMessage {
  struct UIDContent {
    VERSION: The protocol version, as string. E.g. "0.1a".
    MSGCOUNT: Integer that must increase for each message of the same type for
              the same user. Encoded as JSON integer.
    NOTAFTER: 64bit unixtime after which the key(s) offered by the message
              should not be used anymore. Encoded as JSON integer.
    NOTBEFORE: 64bit unixtime before which the key(s) offered by the message
               should not be used yet. Encoded as JSON integer.
    MIXADDRESS: Fully qualified address of Mix to use as last hop to user.
                String.
    NYMADDRESS: A valid NymAddress. Base64. OPTIONAL. Must be "NULL" if empty.
    IDENTITY: Identity/Pseudonym claimed. Including domain. String.
    SIGKEY: Entry of type KeyEntry (see above). Used to sign the UIDContent and
            to authenticate future UIDMessages for this Identity.

    PUBKEYS: Array of KeyEntry. For static key content confidentiality.
             (Must be ECDH/DH capable)

    SIGESCROW: Entry of type KeyEntry (see above). Used to optionally
               authenticate future UIDMessages for this Identity. Failover for
               a lost SIGKEY. May be zero-value.
    LASTENTRY: Last known Key Hashchain entry. String.

    REPOURIS: URIs of KeyInit Repositories to be used to publish KeyInit
              messages. Array of strings.

    struct PREFERENCES {
      FORWARDSEC: Forward Security preference. Must be "strict", "mandatory" or
                  "optional". "strict" and "mandatory" force the peer to
                  initiate a message via a forward secure mechanism, "optional"
                  allows for degrading the first message to be not forward
                  secure.
      CIPHERSUITES: List of ciphersuites, ordered from most preferred to least
                    preferred. Arra of strings. May be zero-value.
                    [future preferences may be added]
    }

    struct CHAINLINK {
      URI: URI(s) of the foreign key hashchain. Array of strings. May be zero-value.
      LAST: Last entry of the foreign key hashchain. String.
            May be zero-value if URI is zero.
      AUTHORATIVE: Boolean true/false.
      DOMAINS: List of domains that are served currently. Array of strings.
               Must be zero unless AUTHORATIVE is true and URI is set.
      IDENTITY: Own Identity in the foreign key hashchain. String. May be
                zero-value if URI is zero. Currently unused (must be zero).
    }
  }
  ESCROWSIGNATURE: Signature over UIDContent by previous SIGESCROW (see above).
                   Base64 encoded. May be zero-value.
  USERSIGNATURE: Signature over UIDContent by previous SIGKEY (see above).
                 Base64 encoded. May be zero-value.
  SELFSIGNATURE: Signature over UIDContent by current SIGKEY (see above).
                 Base64 encoded.
  LINKAUTHORITY: Signature over UIDContent by key server SIGESCROW in the case
                 of authorative keyserver links (see below: "Linking chains and
                 key repositories"). Base64 encoded. Must be zero unless an
                 authorative link entry.
}
```

Successful reply from server;
```
struct UIDMessageReply {
  struct Entry {
    UIDMessageEncrypted: Encrypted version of UIDMessage.
                         See below: "Storing UIDMessages."
    HASHCHAINENTRY: Corresponding Key Hashchain Entry. String.
    HASHCHAINPOS: Position of Key Hashchain Entry. Integer.
  }
  SERVERSIGNATURE: Signature over Entry by Keyserver's signature key.
}
```


#### Verification rules

Key Server verifies:
- Verify that the `UIDMessage` is well-formed.
- Verify that the `MIXADDRESS` is allowed by configuration of the Key Server.
- Verify that the domain of the `IDENTITY` is allowed by configuration of the
  Key Server.
- Verify that the localpart of the `IDENTITY` is allowed by the configuration
  (allows blocking of special identities like `root@` and `admin@`).
- Verify that the `SELFSIGNATURE` is a valid signature of `UIDContent` by the
  included `SIGKEY`.
- Verify `CHAINLINK` (see below: "Linking chains and key repositories").
- Verify that `UIDContent.LASTENTRY` is reasonably fresh and valid for this
  keyserver.

- If `IDENTITY` is unkown, add to Key Hashchain and add to Key Repository (see
  below: "Storing UIDMessages"). End.
- If IDENTITY is KNOWN, continue:
	
- Verify that `MSGCOUNT` has been increased by exactly 1 (one) from previous
  `UIDMessage`.
- Verify that `NOTBEFORE` and NOTAFTER are valid.
- If `ESCROWSIGNATURE` is not zero, verify that `ESCROWSIGNATURE` is a valid
  signature over `UIDContent` by the previously known `SIGESCROW`.
- If `SIGESCROW` differs from previous `SIGESCROW`, verify that
  `ESCROWSIGNATURE` is **not** zero.
- If `USERSIGNATURE` is not zero, verify that `USERSIGNATURE` is a valid
  signature over `UIDContent` by the previously known `SIGKEY`.
- Verify `USERSIGNATURE or `ESCROWSIGNATURE are not zero.
- Add to Key Hashchain and add to Key Repository (see below: "Storing
  UIDMessages"). End.

The `USERSIGNATURE`/`ESCROWSIGNATURE` verification allows for the updating of
the `SIGKEY` without needing cooperation by the `ESCROW`. It also allows the
updating of the `SIGKEY` when it has been lost. Furthermore, it prevents the
changing of the `SIGESCROW` key unless the previous `SIGESCROW` key is
available.  This allows for secure paper-storage of a very long-term
backup/failover key to recover control over the identity in case of key loss (or
key control loss).


#### Expiring/rolling key chain

Definitions:
- `ROLLOVER`: Time after which the blockchain should be considered "non-authorative" by the client. One year.

Server:
- New entries should not have a `UIDMessage.UIDContent.NOTAFTER` that is more
  than `ROLLOVER` in the future.
- A found `IDENTITY` is only considered "known" if it is **not older** than
  `UIDMessage.UIDContent.NOTAFTER - ROLLOVER * 3`.
- A found `IDENTITY` can be updated if it is **not older** than
  `UIDMessage.UIDContent.NOTAFTER - ROLLOVER * 2`

Client:
- A found `IDENTITY` is only considered "known" if it is **not older** than
  `UIDMessage.UIDContent.NOTAFTER - ROLLOVER`


#### Storing UIDMessages

The Key Repository stores an encrypted form of the `UIDMessageReply` and makes
it accessible to external users:
- Calculate hash: `UIDHash = SHA256(UIDMessage)`
- Calculate hash: `UIDIndex = SHA256(UIDHash)`
- Create `nonce=Random(blocksize)`
- Encrypt `UIDMessage`:
```
  UIDMessageEncrypted = UIDIndex | nonce | aes_ctr(nonce, key=UIDHash, UIDMessage)
```
- Create Key Hashchain entry:
```
  hcEntry, hcPos = hashchain_append(Identity, UIDHash, UIDIndex) // see below: Hashchain operation
```
- Construct `Entry` from `hcEntry`, `hcPos`, `UIDMessageEncrypted`
- Sign `Entry` by Key Server's key pkey: `serverSig = sign(pkey, Entry)`
- Construct `UIDMessageReply` from `Entry` and `serverSig`.
- Store new UIDMessageReply accessible by `UIDIndex`. (User must know `UIDIndex`
  to fetch encrypted `UIDMessageReply`)
- Return `UIDMessageReply` to user.


#### Implementation notes

- Maintain a key-value database "Identity"-"Key HashChain Entry" to facilitate
  quick checks if an identity is already taken, and if yes, what `UIDMessage` it
  points to.
- Maintain a key-value database "Identity"-"ECDSA PubKey" to quickly check
  signatures in KeyInit and Key/UID update situations.
- Maintain a chronologically ordered log of Key Hashchain positions for each
  identity, if the `LookupUID` method is supported.


### Key HashChain operation

The Key Hashchain is constructed as follows.

Key Server computes:

Given: `Identity`, `UIDHash` and `UIDIndex` (see above: "Storing UIDMessages"),
previous entries.
- Set `TYPE = 0x02				// Type field for future extensions`
- Create random `NONCE` 64bit
- Compute `k1, k2 = CKDF(NONCE)`
- Create `HASH(k1 | identity) = HashID`
- Create `HASH(k2 | identity) = IDKEY`
- Create `AES_256_CBC(IDKEY, UIDHash) = CrUID`
- Create `HASH(entry[n]) := Hash(TYPE | NONCE | HashID | CrUID | UIDIndex | Hash(entry[n-1])`
- Publish: `HASH(entry[n]) | TYPE | NONCE | HashID | CrUID | UIDIndex`


#### Looking up an identity

Client computes:

Given: Identity, Hashchain entries
- For each entry n:
```
  Compute: k1, k2 = CKDF(NONCE)
	Compute: HashIDTest = HASH(k1 | Identity)
	If NOT: HashID == HashIDTest: Continue
	Compute: IDKEY = HASH(k2 | Identity)
	Fetch from Key Repository: UIDMessageReply = GET(UIDIndex)
	Decrypt UIDHash = AES_256_CBC_Decrypt( IDKEY, CrUID)
	Decrypt UIDMessageReply.UIDMessage with UIDHash
	Verify UIDMessage, memorize ECDSA Key
```
- If no further entry can be found, the latest `UIDMessage` entry has been
  found.


#### Implementation notes

- A single hashchain entry is `3 * HASH + AES_BLOCK + NONCE` in size:
  `3 * 256 + 256 + 64 bits == 1088 bits == 136 bytes`.
- Start the chain with the `UIDMessage` of the Keyserver itself (containing the
  Keyserver signature public key, self-signed reply).
- Keyservers should keep a private cache of identity -> entry mappings to
  prevent exhaustive searches. The cache is not distributed.
	

#### HashChain verification

UIDMessages and messages sent between peers should contain the last known
hashchain entry. This allows verification of the chain by consensus. In paranoid
cases the user should wait for peers to send him a last known entry after his
own last `UIDMessage` entry before making his pseudonym known. Since
UIDMessageReplies are signed, we can demonstrate the performance of the Key
Server to third parties. Verification of single Identities should always be an
exhaustive search over the Hashchain. In addition, users should verify the
`UIDContent.LASTENTRY` to be reasonably fresh (and valid) in the chronological
context of the entry so that delayed entries can be detected in cooperation with
the keyserver.


### Linking chains and key repositories

The `UIDMessage CHAINLINK struct` serves as a means to linke multiple Key
Repositories and Key Hashchains together for the following purposes:
- Verification binding: Hashchains that verify each other by adding the last
  entry of another hashchain into their own, increasing the security against
  modification for the linked hashchain.
- Connect identities across multiple Key Servers.
- Authorative link: Allows Keyservers to operate in a federated way to support
  finding Identities served by other KeyServers.

Entries in the `CHAINLINK` URI must be ordered lexicographically. No more than
five entries are permitted except in the Authorative Link scenario.
This limitation serves to limit space for preimage attacks.


#### Verification binding

The URI of the `CHAINLINK` is set to the URI(s) of the Origin Key Server to be
bound into the destination hashchain.
The `LAST` entry is the last key hashchain entry on the Origin Key Server at the
time of request.
If `AUTHORATIVE` is true, the entry is verified by the destination keyserver by
making the appropriate calls to the origin keyserver.
The reply of such a call may be off by up to an hour to allow for fast-growing chains to link.
`DOMAINS` and `IDENTITY` must be zero-value.


#### Connecting identities

The URI of the `CHAINLINK` is set to the URI(s) of the Origin Key Server to be
bound into the destination hashchain.
The `LAST` entry is the last key hashchain entry on the Origin Key Server at the
time of request.
`IDENTITY` is set to the origin keyserver identity of this entry.
`DOMAINS` must be zero-value.
If `AUTHORATIVE` is true, the Key Server must get the current `UIDMessage` for
the `IDENTITY` from the Origin Key Server and verify that the `SIGKEY` and
`SIGESCROW` of the connecting `UIDMessage` (this message) are the same as for
the current entry of the `IDENTITY` on the Origin Key Server.
If `AUTHORATIVE` is false, the Key Server must verify that the identity was
connected successfully before (with `AUTHORATIVE` true).
This allows a peer to be identified over multiple keyservers and thus increase
assurance. It also allows for identities to be moved from one keyserver to
another or to be separated.


#### Authorative link

The URI of the `CHAINLINK` is set to the URI(s) of the Origin Key Server to be
bound into the destination hashchain.
The `LAST` entry is the last key hashchain entry on the Origin Key Server at the
time of request.
`AUTHORATIVE` must be true.
`DOMAINS` is a list of domains handled by the Origin Key Server. `IDENTITY` is
set to the identity of the origin key server itself (it's signature key).
Authorative Links are Connected Identities and require the same verification
process. In addition, authorative links that change (add or delete) domains
claimed by the Origin Key Server need to be manually verified by the Key Server
Operator.
For this the `LINKAUTHORITY` signature over the whole `UIDMessage` must be made
by the destination key server `SIGESCROW` key.
`DOMAINS` made known by this operation may not be claimed by future links unless
the chain of identities can be verified.


### KeyInit Repository operation

KeyInit messages allow the asynchronous setup of Forward Secure communication
sessions by making the ephemeral key of the peer always available through a
third party (the KeyInit repository).


### KeyInit Messages

KeyInit messages contain the necessary information to setup a session:
Mixaddress, Nymaddress and ephemeral keys. This information is encrypted to make
it unusable to users that do not know about the Identity. This also allows for
KeyInit Messages to be public and thus increase plausible deniability for peers.
KeyInit messages are created by the user and uploaded to the Key Server. The Key
Server returns a KeyInit message to an inquiring peer when given a `UIDIndex`
(see above: "Key HashChain operation") and depending on `NOTAFTER`/`NOTBEFORE`
settings of the KeyInit messages.


#### Format

```
struct KeyInit{
  struct Contents{
    VERSION: The protocol version, as string. E.g. "0.1a".
    MSGCOUNT: Integer that must increase for each message of the same type for
              the same user. Encoded as JSON integer.
    NOTAFTER: 64bit unixtime after which the key(s) offered by the message
              should not be used anymore. Encoded as JSON integer.
    NOTBEFORE: 64bit unixtime before which the key(s) offered by the message
               should not be used yet. Encoded as JSON integer.
    FALLBACK: Boolean. true/false. Determines if the key may serve as a
              fallback key.
    SIGKEYHASH: SHA512(UIDMessage.UIDContent.SIGKEY.HASH)
    REPOURI: URI of this KeyInit Repository. String
    SESSIONANCHOR: Encrypted SessionAnchor Struct. See below.
    SESSIONANCHORHASH: SHA512 of SessionAnchor Struct before encryption.
  }
  SIGNATURE: Signature of Contents by UIDMessage.UIDContent.SIGKEY
}
```

```
struct SessionAnchor{
  MIXADDRESS: Fully qualified address of Mix to use as last hop to user. String.
  NYMADDRESS: A valid NymAddress. Base64.
              MUST BE "NULL" IF UIDMessage.UIDContent.NYMADDRESS == NULL
  PFKEYS: Array of KeyEntry. For ephemeral/forward secure key agreement.
}
SESSIONANCHOR = AES256_CTR(key=UIDMessage.UIDContent.SIGKEY.HASH, SessionAnchor)
```


#### Verification rules

The Key Server must verify that
(on call of `AddKeyInit(Identity, KeyInit[,Token])`):
- The `REPOURI` points to this KeyInit Repository.
- `SIGKEYHASH` corresponds to the `SIGKEY` of the `Identity`.
- That the `SIGNATURE` was made with `UIDMessage.UIDContent.SIGKEY` over Contents.
- That the `MSGCOUNT` has been increased (by any number).
- That `NOTAFTER` and `NOTBEFORE` are valid.

Client verifies in addition:
- That `SESSIONANCHORHASH` matches decrypted `SESSIONANCHOR`.


#### Dispersing mechanism

A peer can request a `KeyInit` message from the KeyInit repository by
`UIDIndex`. The order in which `KeyInit` messages are returned and deleted
depends on the `NOTAFTER`/`NOTBEFORE` settings as well as the `FALLBACK`
setting. The server is to delete KeyInit messages that have reached `NOTAFTER`
and not return them anymore. `KeyInit` messages that have not reached
`NOTBEFORE` are not returned.

No Fallback:

From the KeyInit messages that have reached `NOTBEFORE` but have not yet reached
`NOTAFTER` the ones with `FALLBACK` set to false are returned first,
ordered by their remaining lifetime (time until `NOTAFTER` is reached). Keys
with `FALLBACK==false` are always deleted immediately.

Fallback:

If no more keys with `FALLBACK==false` are available, the KeyServer will start
returning `FALLBACK==true keys` that have reached `NOTBEFORE` but have not yet
reached `NOTAFTER`.
Out of these keys a random one is selected and returned, biased by remaining
lifetime (the less lifetime remains, the more likely the key is returned).
Fallback keys are deleted only if other valid keys remain and based on a biased
coin-flip (the less lifetime remains, the more likely the key is deleted after
it has been returned).

Biased selection/deletion:
- Calculate the remaining litetime of the key in question: `n = NOTAFTER-NOW()`
- Calculate the maximum lifetime of all keys eligable for selection:
  `m = max(lifetime)`
- Generate random value `0 < r < m : r = random(0,m)`
- If `r > n`, the key is a deletion candidate.
	

#### Forward Secrecy Preference

If no more KeyInit messages are available from the KeyInit repository but the
`FORWARDSEC` (see below) setting of the user is "mandatory", then the peer has
to initiate a session via synchronous prekeying (see [message
protocol](https://github.com/mutecomm/mute/blob/master/doc/messages.md)).
If the KeyInit message returned by the KeyInit repository is the fallback
message and the `FORWARDSEC` setting of the user is "strict", then the peer must
either retry until he receives a unique message or he must initiate a session
via synchronous prekeying.
If the KeyInit message returned is shared (`FALLBACK==true`) and `FOWARDWARDSEC`
setting is "optional", the sender **may** use the KeyInit Message.

```
FORWARDSEC: UIDMessage.UIDContent.PREFERENCES.FORWARDSEC
```


#### Implementation notes

- Users should update the KeyInit message frequently, but not faster than
  `2 * MixMax`.
- After a `KeyInit` message has expired, the user should purge the corresponding
  private key quickly, but not before waiting `2 * MixMax` and then fetching and
  processing messages from the storage account.
- The keyserver may define a maximum number of `KeyInit` messages stored per
  `UIDIndex` and a maximum frequency for downloading/deleting them.
