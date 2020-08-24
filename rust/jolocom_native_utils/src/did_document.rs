use keriox::{
    prefix::{BasicPrefix, IdentifierPrefix, Prefix},
    state::IdentifierState,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct DIDDocument {
    #[serde(rename = "@context")]
    context: String,
    id: String,
    #[serde(rename = "verificationMethod")]
    verification_methods: Vec<VerificationMethod>,
}

impl From<IdentifierState> for DIDDocument {
    fn from(state: IdentifierState) -> Self {
        DIDDocument {
            context: "https://www.w3.org/ns/did/v1".to_string(),
            id: ["did:un:".to_string(), state.prefix.to_str()].join(""),
            verification_methods: match state
                .current
                .signers
                .iter()
                .map(|pref| pref_to_vm(pref, &state.prefix))
                .collect::<Result<Vec<VerificationMethod>, String>>()
            {
                Ok(vms) => vms,
                // TODO not clean
                Err(_) => vec![],
            },
        }
    }
}

fn pref_to_vm(
    pref: &BasicPrefix,
    controller: &IdentifierPrefix,
) -> Result<VerificationMethod, String> {
    Ok(VerificationMethod {
        id: ["#".to_string(), pref.to_str()].join(""),
        key_type: match pref {
            BasicPrefix::Ed25519NT(_) | BasicPrefix::Ed25519(_) => {
                KeyTypes::Ed25519VerificationKey2018
            }
            BasicPrefix::ECDSAsecp256k1NT(_) | BasicPrefix::ECDSAsecp256k1(_) => {
                KeyTypes::EcdsaSecp256k1VerificationKey2019
            }
            BasicPrefix::X25519(_) => KeyTypes::X25519KeyAgreementKey2019,
            _ => return Err("bad key type".to_string()),
        },
        controller: ["did:un:".to_string(), controller.to_str()].join(""),
        key: VerificationMethodProperties::Base64(base64::encode_config(
            pref.derivative(),
            base64::URL_SAFE,
        )),
    })
}

#[derive(Serialize, Deserialize)]
pub struct VerificationMethod {
    id: String,

    #[serde(rename = "type")]
    key_type: KeyTypes,
    controller: String,

    #[serde(flatten)]
    key: VerificationMethodProperties,
}

#[derive(Serialize, Deserialize)]
pub enum KeyTypes {
    JwsVerificationKey2020,
    EcdsaSecp256k1VerificationKey2019,
    Ed25519VerificationKey2018,
    GpgVerificationKey2020,
    RsaVerificationKey2018,
    X25519KeyAgreementKey2019,
    SchnorrSecp256k1VerificationKey2019,
    EcdsaSecp256k1RecoveryMethod2020,
}

#[derive(Serialize, Deserialize)]
pub enum VerificationMethodProperties {
    #[serde(rename = "ethereumAddress")]
    EthereumAddress(String),
    #[serde(rename = "publicKeyHex")]
    Base16(String),
    #[serde(rename = "publicKeyBase58")]
    Base58(String),
    #[serde(rename = "publicKeyBase64")]
    Base64(String),
    #[serde(rename = "publicKeyJwk")]
    Jwk(String),
    #[serde(rename = "publicKeyPem")]
    Pem(String),
}
