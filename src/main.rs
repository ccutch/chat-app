extern crate ring;
extern crate rpassword;

use ring::{digest, pbkdf2, error};
use ring::aead::{self, *};
use ring::rand::*;
use std::error::Error;
use std::io;
use std::sync::mpsc;


// (username, password) -> SHA256 -> (pub_key, priv_key)


/**
 *  Lifecycle:
 *  - Login user
 *  - Connect to known peers (ie: dedicated server or someone on same network) 
 *  - Start thread to Listed for messages
 *  - Listen for user input to create messages
 */

// chat-app ccutch.io | 19.188.24.1
/**
 * Server handshake
 * - open tcp socket with remote server
 * - give sealing key to server with username
 * - server gives all known keys
 * {
 *  "username": sealing_key,
 *  ...
 * }
 */



// //                      nonce  , data
// struct EncryptedMessage(Vec<u8>, Vec<u8>);

// struct User {
//     username: String,
//     public_key: SealingKey,
//     private_key: Option<OpeningKey>
// }

// impl User {
//     fn login() -> User {}
//     fn get_from_server(username: String) -> User {}

//     fn send(recipient: User, message: Message) -> Result<(), Box<error::Error>> {}
//     fn decrypt(message: Message) -> String {}
// }


// chat-app
// - Load historic => create chats from old messages
// - 


struct Chat<D: Decrypter, E: Encrypter, T: Transport> {
    decrypter: D,
    encrypter: E,
    transport: T,

    messages: Vec<Message>,
}

trait Transport {
    fn deliver(message: Message) -> io::Result<()>;
    fn listen() -> mpsc::Receiver<Message>;
}

// impl Chat {
//     fn send(message: Message) -> Result<(), Box<error::Error>> {
//         encrypter.encrypt(message);
//     }

//     fn receive(message: Message) -> Result<String, Box<error::Error>> {
        
//     }
// }

// Currently logged in user
struct User {
    keypair: Keypair,
    // decrypter: Decrypter,
    // encrypyer: Encrypter,
}

struct Recipient {
    encrypter: Encrypter,// sealing key
}

struct Message {
    nonce: Vec<u8>,
    body: Vec<u8>,
}

struct Keypair {
    opener: OpeningKey,
    sealer: SealingKey,
}

struct RemoteKey {
    sealer: SealingKey,
}

// impl Decrypter for OpeningKey{

// }

// impl Encrypter for SealingKey {

// }

trait EncypterAndDecrypter: Encrypter + Decrypter {}

trait Encrypter {
    fn encrypt(&self, message: String) -> Message;
}

trait Decrypter {
    fn decrypt(&self, message: Message) -> String;
}

fn main() -> Result<(), Box<Error>> {
    let username = rpassword::prompt_password_stdout("Enter username: ")?;
    let password = rpassword::prompt_password_stdout("Enter password: ")?;
    let hash = hash(&password.as_bytes(), &username.as_bytes());

    let (opening, sealing) = derive_key_pair(hash)?;
    let crypto = Keypair::new(opening, sealing);
    assert_eq!("Hello!", crypto.decrypt(crypto.encrypt("Hello!".to_owned())));
    println!("Success!");
    Ok(())
}

fn hash(secret: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0; 32];
    pbkdf2::derive(&digest::SHA256, 5, &salt, &secret, &mut key);
    key
}

fn derive_key_pair(key: [u8; 32]) -> Result<(OpeningKey, SealingKey), error::Unspecified> {
    let algorithm = &aead::CHACHA20_POLY1305;
    let opening = OpeningKey::new(algorithm, &key)?;
    let sealing = SealingKey::new(algorithm, &key)?;
    Ok((opening, sealing))
}


impl Keypair {
    fn new(opener: OpeningKey, sealer: SealingKey) -> Keypair {
        Keypair{opener, sealer}
    }
}

impl Encrypter for Keypair {
    fn encrypt(&self, message: String) -> Message {
        let mut body = message.as_bytes().to_vec();
        let tag_len = self.sealer.algorithm().tag_len();
        for _ in 0..tag_len {
            body.push(0);
        }

        let mut nonce = vec![0; 12];
        SystemRandom::new().fill(&mut nonce).unwrap();

        seal_in_place(&self.sealer, &nonce, &[], &mut body, tag_len).unwrap();
        Message{nonce: nonce, body: body}
    }
}

impl Decrypter for Keypair {
    fn decrypt(&self, mut message: Message) -> String {
        let output = open_in_place(&self.opener, &message.nonce, &[], 0, &mut message.body).expect("Could not open");
        String::from_utf8(output.to_vec()).expect("Failed to parse str")
    }
}