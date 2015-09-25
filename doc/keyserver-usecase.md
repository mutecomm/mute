Example of a complete Keyserver use-case
----------------------------------------

Parties:
- Keyserver
- Alice (recipient)
- Bob (sender, session initiation)


### Key Hashchain initialization: Bob & Alice

- Call `KeyRepository.Capabilities()` to learn keyserver capabilities.
- Repeatedly call `KeyRepository.FetchHashChain()` to download the Hashchain in
  chunks, starting with position 0 and ending with last entry.
- Track Keyserver identity through the hashchain to always have valid signature
  keys.


### Becoming a user: Alice

Alice generates `SIGKEY` and `SIGESCROW` keys. The `SIGESCROW` private key is
printed to paper, and deleted from the machine after the identity has been added
to the keyserver successfully.

Then Alice selects a pseudonym with a domain served by the keyserver and
verifies that it has not been entered to the Hashchain yet by searching her
local copy of the Hashchain. Alice then constructs the `UIDMessage`, signs it
with both `SIGKEY` and `SIGESCROW`, and sends it to the keyserver using
`KeyRepository.CreateUID()`. Her call is paid by a payment token.

The keyserver will verify the request and (on success) return a signed
`UIDMessageReply`. Alice decrypts the `UIDMessage` in the `UIDMessageReply` and
verifies the signature. She then waits for some time to allow other entries to
be added to the Hashchain. In the meantime, Alice creates a number of KeyInit
Messages for her new identity and publishes them on the keyserver's KeyInit
repository via `KeyInitRepository.AddKeyInit()`. Her call is paid by a payment
token.

She then updates her local Hashchain copy via `KeyRepository.FetchHashChain()`
and verifies that her identity has been added to the Hashchain as demanded. Only
then does she tell Bob about her new Identity.


### Starting a session: Bob

On hearing about Alice's new Identity, Bob updataes his local Hashchain copy via
`KeyRepository.FetchHashChain()` and then searches it exhaustively for Alice's
Identity. On finding the first entry, he then construct a cache of her signature
keys and last `UIDIndex`.

Bob then fetches a single KeyInit message from the KeyInit Repository via
`KeyInitRepository.FetchKeyInit()`. He verifies the reply to be valid and signed
by Alice's `SIGKEY`.

He then constructs a message from the public key material received from the
`UIDMessage` and `KeyInit` Message, adds the NymAddress from the `KeyInit`
Message, adds his own keys and addresses valid **only** for this session, and
sends it to the KeyInit `MIXADDRESS`.

In responding, Alice will not have to consult the keyserver with the exception
of keeping the local hashchain copy current.
