
extern crate chrono;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate ipfs_api;
extern crate pem;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde_cbor;
extern crate tokio_core;
extern crate untrusted;

use std::fmt;
use std::io;
use chrono::prelude::*;
use failure::Error;
use ring::{ rand, signature };

#[derive(Clone, Debug, PartialEq, Eq, Fail)]
pub enum CryptoError {
    #[fail(display = "Key generation failed; perhaps could not get system RNG?")]
    KeygenFailed,
    #[fail(display = "PKCS#8-formatted key was invalid; corrupt PEM file?")]
    InvalidKey,
    #[fail(display = "Tried to sign an `Id` with a private key that doesn't match its public key.")]
    WrongKey,
}


#[derive(Clone, Debug, PartialEq, Eq, Fail)]
pub enum NetworkError {
    #[fail(display = "Could not add key; is the IPFS server running and listening?")]
    CouldNotAddKey,
    #[fail(display = "Could not add key; is the IPFS server running and listening?")]
    CouldNotGetKey,
    
}


const PEM_TAG: &str = "WORLDID PUBLIC+PRIVATE KEY";

/// The type of a keypair.
/// Right now, only ED25519 is supported,
/// but paranoia dictates that we allow room for expansion.
#[derive(Clone, PartialEq, Eq)]
pub enum Keypair {
    // Annoyingly, there's no real way to store a `ring` Ed25519KeyPair, you have
    // to store and manipulate it as the pkcs8 encoding.  Fiiiine.
    Ed25519(Vec<u8>),
}

/// Doesn't derive debug to avoid leaking the key to console quite as easily. XD
/// Instead has a custom debug method that just prints out the keypair type.
impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Keypair::Ed25519")
    }
}

impl Keypair {
    /// Generates and returns a new public+private key pair.
    pub fn new() -> Result<Keypair, Error> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
        Ok(Keypair::Ed25519(pkcs8_bytes.to_vec()))
            
    }

    /// Saves the keypair to the given `Write` stream as a PEM file
    /// encoded as a PKCS8 #2 document..
    /// Contains both the public and private key?  :/  Seems like you
    /// should be able to have them separate.
    pub fn save_to_pem<W: io::Write>(&self, stream: &mut W) -> Result<(), Error> {
        match *self {
            Keypair::Ed25519(ref pkcs8_bytes) => {
                let pem_data = pem::Pem {
                    tag: PEM_TAG.to_owned(),
                    contents: pkcs8_bytes[..].to_owned(),
                };
                let pem_string = pem::encode(&pem_data);
                stream.write_all(pem_string.as_bytes())?;
                Ok(())

            }
        }
    }

    pub fn load_from_pem<R: io::Read>(data: &mut R) -> Result<Self, Error> {
        let s = &mut String::new();
        let _len = data.read_to_string(s)?;
        // The pem error type uses error_chain, which
        // apparently contains an Rc somewhere, and that just gets weird here,
        // so we strip out its error type.
        let pem = pem::parse(s)
            .map_err(|_| CryptoError::InvalidKey)?;
        if pem.tag != PEM_TAG {
            return Err(CryptoError::InvalidKey.into());
        }
        // Generate the keypair to make sure it's valid
        let _keypair =
            ring::signature::Ed25519KeyPair::from_pkcs8(
                untrusted::Input::from(&pem.contents))?;
        Ok(Keypair::Ed25519(pem.contents))
    }

    /// Signs the given message with the keypair's private key.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        match *self {
            Keypair::Ed25519(ref pkcs8_bytes) => {
                let kp = ring::signature::Ed25519KeyPair::from_pkcs8(
                            untrusted::Input::from(pkcs8_bytes))?;
                Ok(kp.sign(msg).as_ref().to_vec())
            }
        }
    }

    /// This is annoying and maybe we should just store the ring keypair as well
    /// as the pkcs8 bytes, idk.
    fn public_key_bytes(&self) -> Result<Vec<u8>, Error> {
        match *self {
            Keypair::Ed25519(ref pkcs8_bytes) => {
                let ring_keypair = ring::signature::Ed25519KeyPair::from_pkcs8(
                    untrusted::Input::from(&pkcs8_bytes))?;
                Ok(ring_keypair.public_key_bytes().to_owned())
            }
        }
    }
}

/// The main identity struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Id {
    id: String,
    public_key: Vec<u8>,
    creation_date: DateTime<Utc>,
    expiry_date: Option<DateTime<Utc>>,
    prev_id: Option<IdLink>
}

/// A link to a previous `Id`, validated with a signature.
/// The signature is the current `Id`, minus the `IdLink`,
/// serialized to CBOR and signed by the previous `Id`'s
/// private key.
/// The `prev_id` is an IPFS CID referring to the previous
/// `Id`.
///
/// It might be nicer to make this an arbitrary "this key signs
/// that key" type structure, since that's a fairly useful
/// general-purpose association.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdLink {
    prev_id: String,
    signature: Vec<u8>,
}


impl Id {
    pub fn new(id: &str, keypair: &Keypair) -> Result<Self, Error> {
        match *keypair {
            Keypair::Ed25519(ref pkcs8_bytes) => {
                let ring_keypair = ring::signature::Ed25519KeyPair::from_pkcs8(
                    untrusted::Input::from(&pkcs8_bytes))?;
                let pubkey_bytes = ring_keypair.public_key_bytes();
                Ok(Id {
                    id: id.to_owned(),
                    public_key: pubkey_bytes.to_owned(),
                    creation_date: Utc::now(),
                    expiry_date: None,
                    prev_id: None,
                })
            }
        }
    }

    /// Creates a new `Id` descended from `self`, with the public key from
    /// `new_keypair` and signed with the private key from `old_keypair` (ie,
    /// the one `self` was created with.
    pub fn new_child(&self, self_cid: &str, new_keypair: &Keypair, old_keypair: &Keypair) -> Result<Id, Error> {
        if old_keypair.public_key_bytes()? != self.public_key {
            return Err(CryptoError::WrongKey.into());
        }
        
        let mut new_id = Id::new(&self.id, new_keypair)?;
        let serialized_id = new_id.to_cbor()?;
        let new_signature = old_keypair.sign(&serialized_id)?;
        let link = IdLink {
            prev_id: self_cid.to_owned(),
            signature: new_signature,
        };
        new_id.prev_id = Some(link);
        Ok(new_id)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        serde_cbor::to_vec(self)
            .map_err(|e| Error::from(e))
    }

    pub fn from_cbor(c: &[u8]) -> Result<Self, Error> {
        serde_cbor::from_slice(c)
            .map_err(|e| Error::from(e))
    }

    /// Returns whether or not the given message and signature were
    /// signed with this ID's private key.
    pub fn verify(&self, sig: &[u8], msg: &[u8]) -> bool {
        let sig = untrusted::Input::from(sig);
        let msg = untrusted::Input::from(msg);
        let pubkey = untrusted::Input::from(&self.public_key);
        signature::verify(&signature::ED25519, pubkey, msg, sig)
            .is_ok()
    }

    /// Returns whether or not the given child was signed with this ID's
    /// private key.  
    ///
    /// Only verifies that one Id, not a whole chain, so
    /// it does not check intermediate Id's.
    /// ie, if `c` descends from `b` descends from `a`, `a.verify_child(c)`
    /// returns false.
    pub fn verify_child(&self, proposed_child: &Id) -> bool {
        if let Some(ref link) = proposed_child.prev_id {
            // Gotta modify a copy of the child to remove the prev_id section,
            // then serialize it and verify the serialized form.
            let mut child = proposed_child.clone();
            child.prev_id = None;
            let child_cbor = child.to_cbor().expect("Couldn't turn child to cbor; should this EVER happen?");
            self.verify(&link.signature, &child_cbor)
        } else {
            // proposed_child has no prev_id section, so of course it's not
            // a child of this Id.
            false
        }
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let json_str = serde_json::to_string_pretty(self).unwrap();
        write!(f, "{}", json_str)
    }
}





/// A connection to an IPFS server that can put and request identities.
pub struct Server {
    core: tokio_core::reactor::Core,
    client: ipfs_api::IpfsClient,
}

impl Server {
    pub fn new(hostname: &str, port: u16) -> Result<Self, Error> {
        let core = tokio_core::reactor::Core::new()?;
        let client = ipfs_api::IpfsClient::new(&core.handle(), hostname, port)?;
        Ok(Server {
            core,
            client,
        })
    }

    /// Can't implement `Default` 'cause `new()` returns a `Result`
    pub fn default() -> Result<Self, Error> {
        Server::new("localhost", 5001)
    }

    pub fn add(&mut self, id: &Id) -> Result<String, Error> {
        let encoded_id = id.to_cbor()?;
        let req = self.client.add(io::Cursor::new(encoded_id));
        let add_response = self.core.run(req)
            .map_err(|_| NetworkError::CouldNotAddKey)?;
        Ok(add_response.hash)
    }

    pub fn get(&mut self, cid: &str) -> Result<Id, Error> {
        use futures::stream::Stream;
        let resp_stream = &mut self.client.cat(cid);
        let res = resp_stream.concat2();
        let get_response = self.core.run(res)
            .map_err(|_| NetworkError::CouldNotGetKey)?;

        let new_id = Id::from_cbor(&get_response)?;
        Ok(new_id)
    }

    /// A wrapper around `Id::new_child()`, it creates a new Id with the new keypair given, links it to the one
    /// given by the CID (we need to find the CID for it anyway, so might as well look it up in the process),
    /// and signs the new one wit the old one's private key.
    /// Then shoves the new one into IPFS.
    /// Returns the new ID and its CID.
    pub fn replace(&mut self, cid: &str, new_keypair: &Keypair, old_keypair: &Keypair) -> Result<(Id, String), Error> {
        let old_id = self.get(cid)?;
        let new_id = old_id.new_child(cid, new_keypair, old_keypair)?;
        let new_cid = self.add(&new_id)?;
        Ok((new_id, new_cid))
    }

    /// Takes a CID for an `Id`, looks it up, and if it has a previous ID it validates that its signature
    /// is correct, then recurses and continues looking down the chain of authority until it either fails to
    /// validate or reaches the end of the chain.
    pub fn verify_chain(&mut self, cid: &str) -> Result<bool, Error> {
        pub fn verify_chain_helper(server: &mut Server, child_id: &Id) -> Result<bool, Error> {
            println!("Verifying {:?}", child_id);
            if let Some(ref link) = child_id.prev_id {
                let parent_id = server.get(&link.prev_id)?;
                println!("parent is: {:?}", parent_id);
                if parent_id.verify_child(&child_id) {
                    verify_chain_helper(server, &parent_id)
                } else {
                    println!("Parent doesn't recognize child");
                    Ok(false)
                }
            } else {
                // End of chain, if we've gotten here without problems it's valid.
                println!("End of chain");
                Ok(true)
            }
        }
        let root_id = self.get(cid)?;
        verify_chain_helper(self, &root_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    #[test]
    fn serialize_roundtrip() {
        let keypair = Keypair::new().unwrap();
        let id = Id::new("foo!", &keypair).unwrap();
        let cbor = id.to_cbor().unwrap();
        let new_id = Id::from_cbor(&cbor).unwrap();
        assert_eq!(id, new_id);
    }

    #[test]
    fn test_keypair_roundtrip() {
        let keypair = Keypair::new().unwrap();
        let buf = &mut Vec::new();
        keypair.save_to_pem(buf).unwrap();
        {
            let pem_string = std::str::from_utf8(&*buf).unwrap();
            println!("PEM is:\n{}\n", pem_string);
        }

        let new_keypair = Keypair::load_from_pem(&mut io::Cursor::new(buf)).unwrap();
        assert_eq!(keypair, new_keypair);
    }

    #[test]
    fn test_print() {
        let keypair = Keypair::new().unwrap();
        let id = Id::new("foo!", &keypair).unwrap();
        println!("ID is {}", id);
        //assert!(false);
    }


    #[test]
    fn test_id_roundtrip() {
        let keypair = Keypair::new().unwrap();
        let id = Id::new("foo!", &keypair).unwrap();
        println!("ID is {}", id);


        let server = &mut Server::default().unwrap();
        let key_cid = server.add(&id).unwrap();
        println!("CID is {}", key_cid);

        let new_id = server.get(&key_cid).unwrap();
        assert_eq!(id, new_id);
    }

    #[test]
    fn test_id_signature() {
        // Create an ID and sign a message
        let message = "Hello world!".as_bytes();
        let keypair = Keypair::new().unwrap();
        let sig = keypair.sign(message).unwrap();
        let id = Id::new("foo!", &keypair).unwrap();


        // Put the old ID
        let server = &mut Server::default().unwrap();
        let key_cid = server.add(&id).unwrap();
        println!("CID is {}", key_cid);

        // Get the new ID and verify the message with it.
        let new_id = server.get(&key_cid).unwrap();
        assert!(new_id.verify(&sig, message));
        assert!(!new_id.verify("some random signature".as_bytes(), message))
    }

    #[test]
    fn test_id_verify_children() {
        let server = &mut Server::default().unwrap();
        
        // Create an ID 
        let keypair_1 = Keypair::new().unwrap();
        let id_1 = Id::new("foo!", &keypair_1).unwrap();
        let cid_1 = server.add(&id_1).unwrap();


        // Create a child ID and verify its a child.
        {
            let keypair_1_child = Keypair::new().unwrap();
            let id_1_child = id_1.new_child(&cid_1, &keypair_1_child, &keypair_1).unwrap();
            assert!(id_1.verify_child(&id_1_child));
        }

        // Create an unrelated ID and verify it is unrelated.
        {
            let keypair_new = Keypair::new().unwrap();
            let id_new = Id::new("foo!", &keypair_new).unwrap();
            assert!(!id_1.verify_child(&id_new));

            // Create an child of id_new and verify it is unrelated to ID 1
            let cid_new = server.add(&id_new).unwrap();
            let keypair_new_child = Keypair::new().unwrap();
            let id_new_child = id_new.new_child(&cid_new, &keypair_new_child, &keypair_new).unwrap();
            assert!(id_new.verify_child(&id_new_child));
            assert!(!id_1.verify_child(&id_new_child));
        }

    }

    #[test]
    fn test_id_verify_chain() {
        let server = &mut Server::default().unwrap();
        
        // Create an ID 
        let keypair = Keypair::new().unwrap();
        let id = Id::new("foo!", &keypair).unwrap();
        let cid = server.add(&id).unwrap();


        // Create a child ID and verify 
        let keypair_child = Keypair::new().unwrap();
        let id_child = id.new_child(&cid, &keypair_child, &keypair).unwrap();
        let cid_child = server.add(&id_child).unwrap();
        assert!(id.verify_child(&id_child));
        assert!(server.verify_chain(&cid_child).unwrap());

        // Create grandchild and verify
        let keypair_grandchild = Keypair::new().unwrap();
        let id_grandchild = id_child.new_child(&cid_child, &keypair_grandchild, &keypair_child).unwrap();
        let cid_grandchild = server.add(&id_grandchild).unwrap();
        assert!(id_child.verify_child(&id_grandchild));
        assert!(server.verify_chain(&cid_grandchild).unwrap());

    }

}
