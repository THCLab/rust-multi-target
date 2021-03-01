use keri::{
    derivation::{
        basic::{Basic, PublicKey},
        self_signing::SelfSigning,
    },
    error::Error,
    event_message::event_msg_builder::{EventMsgBuilder, EventType},
    prefix::{AttachedSignaturePrefix, Prefix},
};
use universal_wallet::prelude::{Content, KeyPair, KeyType, PublicKeyInfo, UnlockedWallet};

pub struct Wallet {
    current_pk: Option<String>,
    next_pk: Option<String>,
    wallet: UnlockedWallet,
    seeds: Vec<String>,
}

impl Wallet {
    pub fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        let data_bytes = msg; 
        let uw = &self.wallet;
        let controller = self.get_current_controller()[0].clone();
        let key_ref = match uw.get_key_by_controller(&controller) {
            Some(c) => c.id,
            None => return Err(Error::SemanticError("No Key Found".to_string())),
        };

        uw.sign_raw(&key_ref, &data_bytes)
            .map_err(|e| Error::SemanticError(e.to_string()))
    }

    pub fn public_key(&self) -> PublicKey {
        let controller = self.get_current_controller()[0].clone();
        let pk = match self
            .wallet
            .get_key_by_controller(&controller)
            .unwrap()
            .content
        {
            Content::PublicKey(pk_info) => Some(pk_info.public_key),
            _ => None,
        };
        PublicKey(pk.unwrap())
    }

    pub fn next_public_key(&self) -> PublicKey {
        let controller = self.get_next_controller()[0].clone();
        let pk = match self
            .wallet
            .get_key_by_controller(&controller)
            .unwrap()
            .content
        {
            Content::PublicKey(pk_info) => Some(pk_info.public_key),
            _ => None,
        };
        PublicKey(pk.unwrap())
    }

    pub fn rotate(&mut self) -> Result<(), Error> {
        self.current_pk = self.next_pk.clone();

        if self.seeds.is_empty() {
            let new_key = self
                .wallet
                .new_key(KeyType::Ed25519VerificationKey2018, None)
                .map_err(|e| Error::SemanticError(e.to_string()))?;
            self.next_pk = match &new_key.content {
                Content::PublicKey(pk) => Some(
                    Basic::Ed25519
                        .derive(PublicKey {
                            0: pk.public_key.clone(),
                        })
                        .to_str(),
                ),
                _ => None,
            };
            self.wallet
                .set_key_controller(&new_key.id, &self.get_next_controller()[0].clone());
        } else {
            let seeds = self.seeds.clone();
            let next_seed = seeds.get(0).unwrap();
            self.seeds = seeds
                .get(1..)
                .unwrap_or(&vec![])
                .iter()
                .map(|s| s.to_string())
                .collect();
            let next_keypair = KeyPair::new(
                KeyType::Ed25519VerificationKey2018,
                &base64::decode_config(next_seed, base64::URL_SAFE)
                    .map_err(|e| Error::SemanticError(e.to_string()))?,
            )
            .map_err(|e| Error::SemanticError(e.to_string()))?;
            let next_pref = Basic::Ed25519.derive(PublicKey {
                0: next_keypair.clone().public_key.public_key,
            });
            self.next_pk = Some(next_pref.to_str());
            self.wallet.import_content(&Content::KeyPair(
                next_keypair.set_controller(self.get_next_controller()),
            ));
        };
        Ok(())
    }

    pub fn new() -> Wallet {
        Wallet {
            current_pk: None,
            next_pk: None,
            wallet: UnlockedWallet::new(""),
            seeds: vec![],
        }
    }

    fn get_current_controller(&self) -> Vec<String> {
        vec![[self.wallet.id.clone(), self.current_pk.clone().unwrap()]
            .join("#")
            .to_string()]
    }

    fn get_next_controller(&self) -> Vec<String> {
        vec![[self.wallet.id.clone(), self.next_pk.clone().unwrap()].join("#")]
    }

    pub fn incept_wallet_from_seed(&mut self, seeds: Vec<&str>) -> Result<(String, String), Error> {
        let curr_seed = seeds.get(0).unwrap();
        let next_seed = seeds.get(1).unwrap();
        self.seeds = seeds
            .get(2..)
            .unwrap_or(&vec![])
            .iter()
            .map(|s| s.to_string())
            .collect();

        let curr_keypair = KeyPair::new(
            KeyType::Ed25519VerificationKey2018,
            &base64::decode_config(curr_seed, base64::URL_SAFE).unwrap(),
        )
        .unwrap();

        let next_keypair = KeyPair::new(
            KeyType::Ed25519VerificationKey2018,
            &base64::decode_config(next_seed, base64::URL_SAFE).unwrap(),
        )
        .unwrap();

        let curr_pref = Basic::Ed25519.derive(PublicKey {
            0: curr_keypair.public_key.public_key.clone(),
        });
        self.current_pk = Some(curr_pref.to_str());

        let next_pref = Basic::Ed25519.derive(PublicKey {
            0: next_keypair.public_key.public_key.clone(),
        });
        self.next_pk = Some(next_pref.to_str());

        let icp = EventMsgBuilder::new(EventType::Inception)?
            .with_keys(vec![curr_pref])
            .with_next_keys(vec![next_pref])
            .build()?;

        self.wallet.id = ["did:keri", &icp.event.prefix.to_str()].join(":");

        let key_id = self
            .wallet
            .import_content(&Content::KeyPair(
                curr_keypair.set_controller(self.get_current_controller()),
            ))
            .unwrap()
            .id;

        self.wallet.import_content(&Content::KeyPair(
            next_keypair.set_controller(self.get_next_controller()),
        ));

        let signed_event = {
            let serialized = icp.serialize()?;
            // sign
            let sig_pref = AttachedSignaturePrefix::new(
                SelfSigning::Ed25519Sha512,
                self.wallet.sign_raw(&key_id, &serialized).unwrap(),
                0,
            );
            icp.sign(vec![sig_pref])
        };

        Ok((icp.event.prefix.to_str(), String::from_utf8(signed_event.serialize()?).unwrap()))
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let key_type = KeyType::Ed25519VerificationKey2018;
        Ok(PublicKeyInfo::new(key_type, &self.public_key().0)
            .verify(data, signature)
            .map_err(|e| Error::SemanticError(e.to_string()))?)
    }
}

#[test]
pub fn test_rotate() -> Result<(), Error> {
    let mut wallet = Wallet::new();
    wallet.incept_wallet_from_seed(vec![
        "rwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc=",
        "6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q=",
        // "cwFTk-wgk3ZT2buPRIbK-zxgPx-TKbaegQvPEivN90Y=",
        // "lntkt3u6dDgiQxTATr01dy8M72uuaZEf9eTdM-70Gk8=",
        // "1-QxDkso9-MR1A8rZz_Naw6fgaAtayda8hrbkRVVu1E=",
        // "KuYMe09COczwf2nIoD5AE119n7GLFOVFlNLxZcKuswc=",
        // "xFfJTcSuEE11FINfXMqWttkZGnUZ8KaREhrnyAXTsjw=",
        // "Lq-w1UKkdrppwZzGTtz4PWYEeWm0-sDHzOv5sq96xJY="
    ])?;
    let msg = "hi".as_bytes().to_vec();
    let signature = wallet.sign(&msg)?;

    assert!(wallet.verify(&msg, &signature)?);
    let curr_pk = wallet.public_key();
    let next_pk = wallet.next_public_key();

    wallet.rotate()?;
    assert_ne!(wallet.public_key(), curr_pk);
    assert_eq!(wallet.public_key(), next_pk);
    assert!(!wallet.verify(&msg, &signature)?);

    Ok(())
}
