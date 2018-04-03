# WorldID

An experimental project for a distributed PKI.  The goal is similar to OpenID and tne idea is similar to GPG but the hope is to make something that is a) far simpler and easier to use, b) makes authentication trivial for other programs (can be used very easily by libraries, web pages, etc)

Basically, the idea is to put a public key in a DHT -- For the moment this uses IPFS.  Then, a user can fetch other public keys, verify them, and so on, just by getting the object from the DHT.  The public key's unique identifier is its DHT hash.  A user may publish updates to their data just by inserting a new record into the DHT and signing it with the private key.

PGP/GPG focuses on email.  And doesn't even do it well.  Dude.  We are in a world where we want to sign and verify specific API requests (like, say, login) both in a web browser and on a web server.

# Upsides

Anyone can retrieve any public key, verify it, etc; you don't need any centralized authority.

An identifier is just a unique hash

You can have as many keys as you want that may or may not be interlinked with each other

# Downsides

Old keys can't point at new keys and say "you want to look at this instead"

Old keys might get forgotten by the network and thus break the chain of trust

If you lose the private key you're hosed (natch)

You can sign someone else's key by publishing a new record, but you can't start with a key and see who has signed it unless they update their record to advertise those signatures -- and then you have a new key.

## Discussion

Basically, most of these are problems with content-addressed merkle-DAG-like structures such as IPFS in the first place.  Content-addressing is great until the content changes and people have to be notified of this.  Thus we need a human-name-to-content-id mapping.  As far as I know, such a thing currently does not exist as a distributed system; the closest we have is DNS, which is administered by central authorities in a vaguely-sane manner.

One way around this might be something like IPLD, which basically uses DNS TXT or SRV records to provide the human-name-to-content-id mapping.  This probably isn't suitable for things that update rapidly such as interactive webpages, fora, chats, etc, but would probably be fine for something like this where an individual probably isn't updating their key every few seconds and doesn't need real-time updates.

# Transfer

It uses IPFS and requires an IPFS node to be running locally; it talks to the node over its local HTTP API.

Honestly, I love what IPFS does but I dislike how it does it.  It seems very re-invent-the-world-y, and I'm not convinced that's necessary.  The daemon is also very heavyweight and can be very slow with no terribly good tools .  It needs a dedicated server process per machine, that server is resource intensive, and administering it is a pain.  It's far from a plug-and-play solution.  :-/

What's the alternative?

 * Bittorrent -- Needs a tracker generally, though DHT mode might make it work.  Magnet links aren't really convenient though.  Honestly might be the best way.
 * DAT -- Not really designed as a "cloud" of general-purpose block storage, but rather a powerful method for syncing limited data between known machines
 * ???
 * Make IPFS better -- Tried this, it's very difficult to get into the massive and poorly-documented codebase.  It 
 * Roll your own DHT -- Maybe someday.

# Data format

Currently it uses CBOR but its details are strictly undefined.  They'll need to become defined at some point so that other programs/implementations can interoperate, but for now this is an experiment.

CBOR isn't great but it might be the best available.  We can't use JSON or XML or such because, since keys are identified by their hashes, whitespace is significant.  Protobuf might be okay, capnp might be better, but CBOR is simple and has no actual problems I'm aware of so it's fine so far.  This is a yak I love shaving way too much, so suggestions welcome!  Possible alternatives: [bincode](https://github.com/TyOverby/bincode), [msgpack](https://github.com/3Hren/msgpack-rust), maybe [bencode](https://en.wikipedia.org/wiki/Bencode),

 Data fields:

  * Identifier (username)
  * Public key
  * Creation timestamp (UTC)
  * Expiry timestamp (optional)

Public key algorithm: Ed25519

Oh, it would be useful to be able to enesure that these ident block thingies have a strictly limited upper size, to make it easy to reason about them and such.

# Status

## Done

 * Create identities, create public/private keys, serialize/deserialize them both
 * Add identities to IPFS, retrieve them again
 * Sign messages with priv key, verify them with the ID retrieved from IPFS.
 * Publish a new id, replacing an old one, signed with the old one's private key

## To do

 * Check expiration and creation dates for validity and such.
 * Take an ID with a link to a previous old one and verify that the signature is valid
 * Sign someone else's cert with your own... somehow.
 * Encryption/decryption?  ring doesn't seem to do this...  :/
