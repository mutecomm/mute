Solving the key exchange problem
--------------------------------

This article describes the importance of the key exchange problem, gives an
overview of previous attempts to solve it, and introduces a new approach which
is used in the Mute secure messaging system — the trustless keyserver.

A _trustless keyserver_ is a keyserver which distributes public keys without
the ability to perform a man-in-the-middle attack or to withhold keys. If the
presented trustless keyserver tries to cheat **once for one user**, the user's
client can **prove** it, thereby undermining the trust of **all users** in the
system. That is, using a trustless keyserver does not only allow to exchange
public keys without trust in a third party, but also has a clear attribution in
case of attacks.

The content of this article was presented at
[Hackers congress Paralelní Polis 2015](http://www.hcpp.cz)
[[slides](http://mute.berlin/doc/keyexchangeproblem.pdf)].
It follows the presentation closely, but gives additional explanations which
are not contained on the slides.


### Importance of the key exchange problem

#### Alice and Bob have this thing going on...

![Alice, Bob, and Eve](https://rawgit.com/mutecomm/mute/master/doc/figures/alicebobeve.svg)

We consider the classic couple in cryptography: Alice and Bob.


#### ...and they don't like Eve!

![Alice, Bob, no Eve](https://rawgit.com/mutecomm/mute/master/doc/figures/alicebobnoeve.svg)

Alice and Bob want to communicate over an insecure channel without evil Eve
spying on them. The method to do so is encryption.


#### Encryption: introduction

“Conventional” symmetric encryption uses one key for encryption and decryption
and therefore a secure channel is needed for the key exchange.

In contrast, public-key encryption is _asymmetric_ and uses _key pairs_ (a
public and a private key).

Something encrypted for a given _public key_ can only be decrypted by the
corresponding _private key_.
The reverse operation is a digital signature: something encrypted (_signed_) by
a private key can only be decrypted (_verified_) by the corresponding public
key.

To use public-key encryption Alice and Bob only have to exchange their
corresponding public keys. Therefore it easy to conclude: public-key encryption
solves the key exchange problem. But it turns out: public-key encryption
~~solves the~~ still has a key exchange problem! Why is that?


#### Keyserver: distributing public keys

![Keyserver](https://rawgit.com/mutecomm/mute/master/doc/figures/keyserver.svg)

A classic method to exchange public keys is to use a _keyserver_. A keyserver
is a repository for public keys. The public keys are usually bound to
identities. Alice and Bob can query the keyserver for the public key of the
other party.


#### Man-in-the-middle attack / evil keyserver

![Evil keyserver](https://rawgit.com/mutecomm/mute/master/doc/figures/evilkeyserver.svg)

The problem with such a setup are various scenarios where Eve performs a
man-in-the-middle-attack (MITM) or the keyserver is evil. The problem is always
the same: Alice doesn't get Bob's public key (and vice versa), but another
public key where Eve knows the corresponding private key. The resulting
communication is still encrypted, but for a private key that Eve knows and can
be used by her to decrypt the encrypted messages.


#### Key exchange: harder than expected

During the development of public-key cryptography the key distribution / key
exchange problem was considered a minor one.
**But**: after the complicated mathematics was solved the key exchange problem
remained challenging.
A good description of the events during the development of public-key
cryptography can be found in the book
[Crypto: How the Code Rebels Beat the Government Saving Privacy in the Digital
Age](http://www.amazon.com/Crypto-Rebels-Government-Privacy-Digital/dp/0140244328),
Steven Levy, **2001**.

Now let us look at previous attempts to solve the key exchange problem and
their shortcomings...


### Previous attempts

#### Signing keyserver

![Signing keyserver](https://rawgit.com/mutecomm/mute/master/doc/figures/signingkeyserver.svg)

Instead of distributing the plain public keys of Alice and Bob, the keyserver
_signs_ them with his own public key. If Alice and Bob know the signature key
of the keyserver, they can verify that the public keys have not been tampered
with by Eve's MITM attack.


#### Public-key infrastructure (e.g., in SSL)

![PKI](https://rawgit.com/mutecomm/mute/master/doc/figures/pki.svg)

The above scenario can be blown up to setups of arbitrary complexity.
Welcome to the world of public-key infrastructure (PKI).
But no matter the complexity of the setup, one problem always remains:
Alice and Bob have to **trust a third party**.


#### PKI problem (e.g., NSA)

![PKI problem](https://rawgit.com/mutecomm/mute/master/doc/figures/pkiwitheve.svg)

PKI is the key exchange method that is used for SSL, and compromising the
certificate authority is exactly the approach organizations like the NSA are
using to gain access to encrypted SSL traffic. Many such cases have been
documented (see
[Wikipedia](https://en.wikipedia.org/wiki/Certificate_authority#CA_compromise)
for links).

Therefore key exchange methods which require trust in a third party **should be
avoided**.


#### Manual fingerprint comparison: idea (used for PGP)

![Fingerprint idea](https://rawgit.com/mutecomm/mute/master/doc/figures/fingerprintidea.svg)

Another approach Alice and Bob can use to make sure the correct key has been
exchanged is to compare a so-called _fingerprint_ of their public keys using a
_side-channel_. It is absolutely necessary that the communication on the side-channel cannot be tampered with. That is, Alice and Bob either have to meet in person or use voice connection to compare the fingerprint. This approach is used by PGP and other messaging apps like Threema.


#### Manual fingerprint comparison: reality (also PGP)
![Fingerprint reality](https://rawgit.com/mutecomm/mute/master/doc/figures/fingerprintreality.svg)

While the approach is perfectly fine in theory, it is very inconvenient in
practice. Users often do not perform the manual fingerprint comparison and
thereby leave the encryption system open to a MITM attack.


#### Web-of-trust / WOT (used for PGP)
![WOT](https://rawgit.com/mutecomm/mute/master/doc/figures/wot.svg)

In a web-of-trust (WOT) the trust Alice and Bob have in one more more other
parties is transferred to the key of the other parties by a signature. In a
very simplified scenario, Alice and Bob both trust one other party Trent who
did a manual fingerprint comparison with them and signed their public keys.
When Alice trusts Trent and has compared his public key fingerprint manually
then the trust Trent has in Bob's public key (gained by manual fingerprint
comparison) and which is expressed by Trent's signature of Bob's key is transferred to Alice. That is, Alice believes that way that she has Bob's real public key.


#### Web-of-trust problem (nobody likes keyparties)

![WOT problem](https://rawgit.com/mutecomm/mute/master/doc/figures/wotproblem.svg)

In reality, a WOT looks more like the picture above which exemplifies some
common problems with it: Some nodes are not connected at all or are in isolated
subgraphs. In such cases it is not possible to employ the WOT for communication
partners without a path connecting them in the graph. And even if there is a
connection between two nodes, the semantics of trust transfer is not a clear
one: If A trusts B, B trusts C, C trusts D, and D trusts E, what does that mean
about the trust of A in a E's public key?


#### Namecoin / Blockchains (Hashchains)

![Blockchain](https://rawgit.com/mutecomm/mute/master/doc/figures/blockchain.svg)

A blockchain is a data structure which is common in cryptocurrencies like
[Bitcoin](https://bitcoin.org) and [Namecoin](https://namecoin.info/) which
links so-called blocks together with hashes in a way that prevents unnoticed
modifications of earlier blocks. The blocks can contain internal data and links
to external data (by embedding a hash of the external data into the block).


#### Namecoin / Blockchain problems (for key exchange)

Blockchains have very interesting properties but they are not a cure-all!

If we consider Namecoin, which has very interesting properties when used as an
alternative to DNS or as an information registration system, as a means of key
exchange it becomes clear that it is not well-suited for the task:

- It is not possible to revoke keys.
- A chain simulation attack has no attribution.
- Long confirmation times for key updates.
- Enumeration of all user IDs is easily possible.


#### And that's only half the picture...

In addition to the key exchange problem described above, secure (asynchronous)
messaging for the 21th century also needs:

- An identity-key binding with human-readable identities which transparently
  maps to long-term keys. Manual key refreshes (as are common with PGP) are
  problematic.
- Perfect forward secrecy (PFS): Old messages should remain unreadable when
  long-term keys are lost.
- PFS needs a secure distribution of short-term keys.
- Ideally: The PFS setup should be possible with a one-way handshake
  (for convenience reasons).
- Secure updates of long-term keys should be possible.

These are all _key exchange_ / _key distribution_ problems!


### A new approach

#### A trustless keyserver
![Trustless keyserver](https://rawgit.com/mutecomm/mute/master/doc/figures/trustless.svg)

Nevertheless, a hashchain can be used successfully a a  building block for our
trustless keyserver. In that case, The hashchain is used to store long-term
identities and pointers to long-term keys (initial ones and updates). The
actual key material itself is stored in an external repository which is linked
to from the hashchain.


#### A trustless keyserver in action
![Trustless keyserver in action](https://rawgit.com/mutecomm/mute/master/doc/figures/trustlessaction.svg)

In contrast to most cryptocurrencies which employ a _distributed consensus_,
our trustless keyserver design employes an _explicit consensus_: Communicating
parties in the system are always exchanging the latest hashchain entry with
each other (unbeknownst to the keyserver). This allows them to verify that they
have the same state of the hashchain and that they keyserver gives everyone the same chain (more details below).


#### `mutekeyd` overview

![mutekeyd overview](https://rawgit.com/mutecomm/mute/master/doc/figures/mutekeyd.svg)

They trustless keyserver `mutekeyd` used in Mute actually has two repositories:
The Key Repository stores long-term keys (referred to in the hashchain) and the
KeyInit Repository stores short-term keys (not referred to in the hashchain),
which are used to set up PFS-communication with a one-way handshake.
In addition to the last hashchain entry, clients also exchange new keys in
messages to continue PFS-communication (see [message
specification](messages.md) for details).


#### Trustless keyserver implementation in Mute

The trustless keyserver has the following properties:
- Exchange of last hashchain entries is an _explicit consensus_.
- It fixes the web-of-trust: The model has clear semantic and no manual
  intervention is required, trust is in a few contacts is transferred to all of
  them.
- It allows to prevent leaking of contacts to keyserver: Clients always
  download the whole hashchain. The retrieval of long-term keys can be
  obfuscated by retrieving additional (unwanted keys)
- The enumeration of all user IDs in the hashchain is not possible due to
  encrypted user IDs in the hashchain which make an explicit search necessary.
  That is, instead of simply enumerating all user IDs a spammer has to apply a
  dictionary attack. See [keyserver specification](keyserver.md) for details.
- There will **never** be forks in the hashchain. This allows for quick key
  updates. A fork in the hashchain (two different blocks with the same previous
  block) would mean the keyserver cheated and at least one client would have
  proof of that (a signature from the keyserver).

Availability of the design:
- The client source-code is open (BSD-style [license](../LICENSE)).
- The protocols are open and the
  [specifications](../README.md#specification-documents) are published
  (most importantly, the [keyserver specification](keyserver.md)).
- The key server source is closed, but since the keyserver is **trustless** the
  correct behavior of the keyserver can be checked by the client and clients
  gain proof of misbehavior, if it should occur.

For the actual message encryption we use a modified
[Axolotl ratchet](https://github.com/trevp/axolotl/wiki)
(used in [TextSecure](https://github.com/WhisperSystems/TextSecure)):
See [message specification](messages.md).


#### `mutekeyd` trustless keyserver walk-through

The following is a walk-through to the operations that happen, if Alice and Bob
are establishing a secure communication channel via the trustless keyserver:

1. Alice and Bob download the hashchain of the keyserver.
2. Alice searches hashchain to check if `alice@mute.one` is free.
3. Alice sends `UIDMessage` with `SIGKEY` to keyserver to register the user ID
   `alice@mute.one`.
4. Keyserver adds `UIDMessage` to hashchain and replies with _signature_.
5. Alice sends PFS-keys to KeyInit repository.
6. Alice updates hashchain to check that `alice@mute.one` was added.
7. Alice tells Bob (who registered `bob@mute.one`) about her new ID.
8. Bob updates his hashchain and searches for `alice@mute.one`.
9. Bob fetches one of Alice's PFS-keys from the KeyInit repository.
10. Bob sends PFS-message to Alice which contains his own keys (long-term and
    short-term).
11. Alice can reply without contacting the keyserver. Only a hashchain search
    is necessary to verify the validity of Bob's keys.

See also: [Example of a complete Keyserver use-case](keyserver-usecase.md).


### Conclusion

- All keyserver operations are handled transparently by the client.
- Users only have to exchange human-readable, unique identities (e.g.,
  `alice@mute.one`), the retrieval and management of the key-material happens
  automatically in a way that doesn't require trust in any third party.
- User clients ensure that the trustless keyserver is indeed trustworthy.
- If the keyserver cheats **once for one user**, the client can **prove** it.
  This leads to a clear attribution in case of attacks!
- Updates of long-term signature keys happen transparently to the user.
- The trustless keyserver design requires that the message protocol is
  intertwined with keyserver protocol, it is not a drop-in replacement for
  other key exchange mechanisms.


#### Pointers

The secure messaging application Mute uses the trustless keyserver design
described in this document:
- Mute [α release](https://github.com/mutecomm/mute).
- Trustless [keyserver specification](keyserver.md).
- Register for news and β invitation: http://mute.berlin.

The author wants to acknowledge
[Jonathan Logan](https://github.com/JonathanLogan) for the trustless keyserver
design described in this article.
