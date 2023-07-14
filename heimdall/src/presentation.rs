use std::{error::Error, str::FromStr};

use num_bigint::BigInt;
use num_traits::One;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use ark_circom_service::{ArkCircomFullProof, Bn254};
use crypto::{merkle_tree::MerkleProof, HashFunction, Signature, SignatureFunction};

use crate::{
    credential::Credential,
    revocation::{RevocationRegistry, MAX_LEAF_SIZE},
    zkp::{
        attribute::proof_attribute_presentation, delegation::proof_delegation_presentation,
        polygon::proof_polygon_presentation, range::proof_range_presentation,
    },
};

/// Maximum number of points for a polygon as specified in the circuit.
const MAX_POLYGON_SIZE: usize = 50;

///A struct grouping the private meta inputs for the presentation circuits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateInputs<H: HashFunction, S: SignatureFunction> {
    pub values: Vec<BigInt>,
    pub signature_meta: Signature<S>,

    #[serde(bound(
        serialize = "MerkleProof<H,2>: Serialize",
        deserialize = "MerkleProof<H,2>: Deserialize<'de>"
    ))]
    pub proof_revocation: MerkleProof<H, 2>,
    pub revocation_leaf: BigInt,

    pub challenge: BigInt,
    pub signature_challenge: Option<Signature<S>>,

    pub expiration_date: BigInt,
}

///A struct grouping the public meta signals of the presentation circuits.
#[derive(Serialize, Deserialize)]
pub struct PublicSignals {
    //set in creation
    pub meta_type: String,
    pub meta_pk_issuer: Option<[BigInt; 2]>,
    pub revocation_registry: String,

    pub revocation_root: BigInt,
    pub revoked: bool,
    pub delegatable: bool,
    pub link_back: Option<BigInt>,
    pub challenge: BigInt,
    pub expiration_date: BigInt,
}

///An abstract struct representing a standalone meta presentation.
#[derive(Serialize, Deserialize)]
pub struct Presentation<H: HashFunction, S: SignatureFunction> {
    #[serde(bound(
        serialize = "Credential<H,S>: Serialize",
        deserialize = "Credential<H,S>: Deserialize<'de>"
    ))]
    pub credential: Option<Credential<H, S>>,

    #[serde(bound(
        serialize = "PrivateInputs<H,S>: Serialize",
        deserialize = "PrivateInputs<H,S>: Deserialize<'de>"
    ))]
    pub private_inputs: Option<PrivateInputs<H, S>>,

    pub public_signals: PublicSignals,
    pub ark_circom_full_proof: Option<ArkCircomFullProof<Bn254>>,
}

///
pub trait ContentPresentation: Serialize{
    fn verify(&self) -> bool;
    fn generate_input_json(&self) -> Result<String, Box<dyn Error>>;
    fn generate(
        &mut self,
        circuit: Option<&Vec<u8>>,
        zkey: Option<&Vec<u8>>,
    ) -> Result<(), Box<dyn Error>>;
    fn remove_private_data(&mut self);
}

///A struct representing a attribute presentation.
#[derive(Serialize, Deserialize)]
pub struct AttributePresentation<H: HashFunction, S: SignatureFunction> {
    #[serde(bound(
        serialize = "Presentation<H,S>: Serialize",
        deserialize = "Presentation<H,S>: Deserialize<'de>"
    ))]
    pub presentation: Presentation<H, S>,

    pub to_publish: Vec<BigInt>,
    pub content: Vec<String>,
}

///A struct representing a range presentation.
#[derive(Serialize, Deserialize)]
pub struct RangePresentation<H: HashFunction, S: SignatureFunction> {
    #[serde(bound(
        serialize = "Presentation<H,S>: Serialize",
        deserialize = "Presentation<H,S>: Deserialize<'de>"
    ))]
    pub presentation: Presentation<H, S>,
    pub index: usize,
    pub upper_bound: BigInt,
    pub lower_bound: BigInt,
    pub in_bound: bool,
}

///A struct representing a polygon presentation.
#[derive(Serialize, Deserialize)]
pub struct PolygonPresentation<H: HashFunction, S: SignatureFunction> {
    #[serde(bound(
        serialize = "Presentation<H,S>: Serialize",
        deserialize = "Presentation<H,S>: Deserialize<'de>"
    ))]
    pub presentation: Presentation<H, S>,
    pub index: usize,
    #[serde(with = "BigArray")]
    pub vert_x: [BigInt; MAX_POLYGON_SIZE],
    #[serde(with = "BigArray")]
    pub vert_y: [BigInt; MAX_POLYGON_SIZE],
    pub location: Option<[String; 2]>,
    pub in_bound: bool,
}

///A struct representing a delegation presentation.
#[derive(Serialize, Deserialize)]
pub struct DelegationPresentation<H: HashFunction, S: SignatureFunction> {
    #[serde(bound(
        serialize = "Presentation<H,S>: Serialize",
        deserialize = "Presentation<H,S>: Deserialize<'de>"
    ))]
    pub attribute_presentation: AttributePresentation<H, S>,
    pub link_forth: BigInt,
}

impl<H: HashFunction, S: SignatureFunction> Presentation<H, S> {
    ///Private constructor for the basic presentation.
    /// Used in the constructores of the subclasses.
    fn new(
        cred: &Credential<H, S>,
        expiration_date: BigInt,
        revocation_registry: &RevocationRegistry<H, S>,
        challenge: BigInt,
        sk_holder: Option<BigInt>,
        pk_issuer: Option<[BigInt; 2]>,
    ) -> Self {
        let cred: Credential<H, S> = cred.clone();

        //
        // Generating private Inputs
        //

        //Generating circom inputs
        let mut values_zkp = Vec::<BigInt>::new();
        let hash_fn = H::new();
        for i in 0..8 {
            let new_e = match BigInt::from_str(&cred.attributes[i]) {
                Ok(y) => y,
                Err(_) => {
                    if &cred.attributes[i] == "" {
                        BigInt::from(0)
                    } else {
                        hash_fn.hash_str(&cred.attributes[i])
                    }
                }
            };
            values_zkp.push(new_e);
        }
        for i in 8..cred.attributes.len() {
            values_zkp.push(hash_fn.hash_str(&cred.attributes[i]));
        }

        let revoc_tree_position = usize::from_str(&cred.attributes[0]).unwrap() / MAX_LEAF_SIZE;
        let proof_revocation = revocation_registry
            .tree
            .generate_proof(revoc_tree_position)
            .unwrap();
        let revocation_leaf =
            BigInt::from_str(&revocation_registry.tree.leaves[revoc_tree_position]).unwrap();
        //signing challange
        let signature_challenge = match sk_holder {
            Some(sk_holder) => Some(S::sign(sk_holder, challenge.clone())),
            None => None,
        };

        let link_back = match pk_issuer.as_ref() {
            Some(pk_issuer) => Some(hash_fn.hash(&vec![
                challenge.to_string(),
                pk_issuer[0].to_string(),
                pk_issuer[1].to_string(),
            ])),
            None => None,
        };

        let private_inputs = PrivateInputs {
            values: values_zkp,
            signature_meta: cred.signature.clone(),
            proof_revocation,
            revocation_leaf,
            challenge: challenge.clone(),
            signature_challenge,
            expiration_date: expiration_date.clone(),
        };

        let output = PublicSignals {
            meta_type: cred.attributes[1].clone(),
            meta_pk_issuer: pk_issuer,
            revocation_registry: cred.attributes[4].clone(),
            revocation_root: revocation_registry.tree.get_root().clone(),
            revoked: revocation_registry.is_revoked(revoc_tree_position).unwrap(),
            delegatable: cred.attributes[6] != "0",
            link_back,
            challenge,
            expiration_date,
        };

        Presentation {
            credential: Some(cred),
            private_inputs: Some(private_inputs),
            public_signals: output,
            ark_circom_full_proof: None,
        }
    }

    ///Verifies the meta data with the public signals of the ZKP.
    pub fn verify_meta_data(
        &self,
        type_index: usize,
        revocation_root_index: usize,
        revocation_registry_hash_index: usize,
        revoked_index: usize,
        link_back_index: usize,
        delegatable_index: usize,
        challenge_index: usize,
        expiration_date_index: usize,
    ) -> bool {
        match &self.ark_circom_full_proof {
            Some(proof) => {
                let hash_fn = H::new();

                let mut res = true;

                res = res
                    && hash_fn.hash_str(&self.public_signals.meta_type)
                        == proof.outputs[type_index];

                res = res
                    && self.public_signals.revocation_root == proof.outputs[revocation_root_index];

                res = res
                    && hash_fn.hash_str(&self.public_signals.revocation_registry)
                        == proof.outputs[revocation_registry_hash_index];

                res = res && self.public_signals.revoked == proof.outputs[revoked_index].is_one();
                res = res
                    && self.public_signals.delegatable == proof.outputs[delegatable_index].is_one();
                res =
                    res && self.public_signals.challenge == proof.outputs[challenge_index].clone();
                res = res
                    && self.public_signals.expiration_date
                        == proof.outputs[expiration_date_index].clone();

                if self.public_signals.meta_pk_issuer.is_some() {
                    res = res
                        && self.public_signals.link_back.as_ref().unwrap().clone()
                            == proof.outputs[link_back_index];
                }
                res
            }
            None => false,
        }
    }

    ///Verifies the zk-SNARKS.
    pub fn verify_proof(&self) -> bool {
        match &self.ark_circom_full_proof {
            Some(proof) => {
                let result = match proof.verify() {
                    Ok(res) => res,
                    Err(_) => false,
                };
                
                result
            }
            None => false,
        }
    }

    ///Generates a json of the  meta-inputs.
    ///Does not include the closing brace.
    fn generate_input_json(&self) -> Result<String, Box<dyn Error>> {
        let private_inputs = match &self.private_inputs {
            Some(res) => res,
            None => Err("Private inputs have already been consumed!")?,
        };

        let mut json = String::new();

        json.push('{');

        //
        // private inputs
        //

        json.push_str(&format!("\"values\":"));
        append_json_vector(&mut json, &private_inputs.values);

        json.push_str(&format!(
            "\"signatureMeta\":[\"{:?}\",\"{:?}\",\"{:?}\"], ",
            private_inputs.signature_meta.r8[0],
            private_inputs.signature_meta.r8[1],
            private_inputs.signature_meta.s
        ));

        json.push_str(&format!("\"pathRevocation\":"));
        append_json_vector(&mut json, &private_inputs.proof_revocation.path);

        json.push_str(&format!("\"lemmaRevocation\":"));
        append_json_vector(&mut json, &private_inputs.proof_revocation.lemma);

        json.push_str(&format!(
            "\"revocationLeaf\":\"{:?}\", ",
            private_inputs.revocation_leaf
        ));

        match &private_inputs.signature_challenge {
            Some(signature_challenge) => json.push_str(&format!(
                "\"signChallenge\":[\"{:?}\",\"{:?}\",\"{:?}\"], ",
                signature_challenge.r8[0], signature_challenge.r8[1], signature_challenge.s
            )),
            None => (),
        }

        json.push_str(&format!("\"issuerPK\":"));
        append_json_vector(
            &mut json,
            &self
                .credential
                .as_ref()
                .unwrap()
                .signature
                .public_key_signer,
        );

        //
        // public inputs
        //
        json.push_str(&format!(
            "\"challenge\":\"{:?}\",",
            private_inputs.challenge
        ));
        json.push_str(&format!(
            "\"expiration\":\"{:?}\"",
            private_inputs.expiration_date
        ));

        Ok(json)
    }

    ///Removes the private data from the struct.
    pub fn remove_private_data(&mut self) {
        self.credential = None;
        self.private_inputs = None;
    }
}


impl<H: HashFunction, S: SignatureFunction> AttributePresentation<H, S> {
    ///Constructor for initializing a attribute presentation.
    pub fn new(
        cred: &Credential<H, S>,
        expiration_date: BigInt,
        revocation_registry: &RevocationRegistry<H, S>,
        sk_holder: Option<BigInt>, //mandatory for basic Attribute Presentation
        pk_issuer: Option<[BigInt; 2]>,
        challenge: BigInt,
        indizes: Vec<usize>,
    ) -> Result<Self, Box<dyn Error>> {
        let presentation = Presentation::<H, S>::new(
            cred,
            BigInt::from(expiration_date),
            revocation_registry,
            challenge,
            sk_holder,
            pk_issuer,
        );

        let mut to_publish = vec![BigInt::from(0); cred.attributes.len()];
        let mut content = Vec::<String>::new();

        for i in indizes {
            to_publish[i] = BigInt::from(1);
            content.push(cred.attributes[i].clone());
        }

        Ok(AttributePresentation {
            presentation,
            to_publish,
            content,
        })
    }
}

impl<H: HashFunction, S: SignatureFunction> ContentPresentation for AttributePresentation<H, S> where AttributePresentation<H, S> :Serialize {
    ///Verifies the presentation.
    fn verify(&self) -> bool {
        let mut res = self.presentation.verify_proof();

        res = res && self.presentation.verify_meta_data(0, 1, 2, 3, 4, 5, 6, 7);

        let hash_fn = H::new();

        let proof = self.presentation.ark_circom_full_proof.as_ref().unwrap();

        let mut count: usize = 0;
        for i in 8..self.to_publish.len() {
            if self.to_publish[i].is_one() {
                res = res && hash_fn.hash_str(&self.content[count]) == proof.outputs[8 + i];
                count += 1;
            }
        }

        res
    }

    ///Generates a json of the content inputs.
    ///Does not include the closing brace.
    fn generate_input_json(&self) -> Result<String, Box<dyn Error>> {
        match self.presentation.generate_input_json() {
            Ok(mut json) => {
                json.push_str(&format!(",\"toPublish\":"));
                append_json_vector(&mut json, &self.to_publish);

                json.pop();

                Ok(json)
            }
            Err(err) => Err(err),
        }
    }

    ///Generates the presentation.
    /// Removes the private data afterwards.
    fn generate(
        &mut self,
        circuit: Option<&Vec<u8>>,
        zkey: Option<&Vec<u8>>,
    ) -> Result<(), Box<dyn Error>> {
        let input_json = match self.generate_input_json() {
            Ok(mut input_json) => {
                input_json.push('}');
                input_json
            }

            Err(err) => Err(err)?,
        };

        self.presentation.ark_circom_full_proof =
            match proof_attribute_presentation(&input_json, circuit, zkey) {
                Ok(proof) => Some(proof),
                Err(err) => Err(err)?,
            };

        if !self.verify() {
            Err("Proof invalid!")?
        }

        self.remove_private_data();

        Ok(())
    }

    ///Removes the private data from the struct.
    fn remove_private_data(&mut self) {
        self.presentation.remove_private_data();
    }
}

impl<H: HashFunction, S: SignatureFunction> RangePresentation<H, S> {

    ///Constructor for initializing a range presentation.
    pub fn new(
        cred: &Credential<H, S>,
        expiration_date: BigInt,
        revocation_registry: &RevocationRegistry<H, S>,
        sk_holder: Option<BigInt>,
        pk_issuer: Option<[BigInt; 2]>,
        challenge: BigInt,
        index: usize,
        lower_bound: BigInt,
        upper_bound: BigInt,
    ) -> Result<Self, Box<dyn Error>> {
        let presentation = Presentation::<H, S>::new(
            cred,
            BigInt::from(expiration_date),
            revocation_registry,
            challenge,
            sk_holder,
            pk_issuer,
        );

        Ok(RangePresentation {
            presentation,
            index: index,
            upper_bound,
            lower_bound,
            in_bound: false,
        })
    }
}

impl<H: HashFunction, S: SignatureFunction> ContentPresentation for RangePresentation<H, S> where RangePresentation<H,S>: Serialize{

    ///Verifies the presentation.
    fn verify(&self) -> bool {
        let mut res = self.presentation.verify_proof();

        res = res && self.presentation.verify_meta_data(0, 1, 2, 3, 4, 5, 6, 7);

        let proof = self.presentation.ark_circom_full_proof.as_ref().unwrap();

        res = res && self.lower_bound == proof.outputs[8];
        res = res && self.upper_bound == proof.outputs[9];
        res = res && self.in_bound == proof.outputs[10].is_one();

        let position = &proof.outputs[11..proof.outputs.len()]
            .iter()
            .position(|x| x.is_one());

        res = res && self.index == position.unwrap();

        res
    }

    ///Generates a json of the content inputs.
    ///Does not include the closing brace.
    fn generate_input_json(&self) -> Result<String, Box<dyn Error>> {
        match self.presentation.generate_input_json() {
            Ok(mut json) => {
                let cred = self.presentation.credential.as_ref().unwrap();
                let mut index_vec = vec![BigInt::from(0); cred.attributes.len()];
                index_vec[self.index] = BigInt::from(1);
                json.push_str(&format!(",\"index\":"));
                append_json_vector(&mut json, &index_vec);
                json.push_str(&format!("\"value\":\"{}\",", cred.attributes[self.index]));
                json.push_str(&format!("\"upperBound\":\"{:?}\"", self.upper_bound));
                json.push_str(&format!(",\"lowerBound\":\"{:?}\"", self.lower_bound));

                Ok(json)
            }
            Err(er) => Err(er),
        }
    }

    ///Generates the presentation.
    /// Removes the private data afterwards.
    fn generate(
        &mut self,
        circuit: Option<&Vec<u8>>,
        zkey: Option<&Vec<u8>>,
    ) -> Result<(), Box<dyn Error>> {
        let input_json = match self.generate_input_json() {
            Ok(mut input_json) => {
                input_json.push('}');
                input_json
            }
            Err(err) => Err(err)?,
        };

        self.presentation.ark_circom_full_proof =
            match proof_range_presentation(&input_json, circuit, zkey) {
                Ok(proof) => {
                    self.in_bound = proof.outputs[10].is_one();
                    Some(proof)
                }
                Err(err) => Err(err)?,
            };

        if !self.verify() {
            Err("Proof invalid!")?
        }

        self.remove_private_data();

        Ok(())
    }

    ///Removes the private data from the struct.
    fn remove_private_data(&mut self) {
        self.presentation.remove_private_data();
    }
}

impl<H: HashFunction, S: SignatureFunction> PolygonPresentation<H, S> {

    ///Constructor for initializing a polygon presentation.
    pub fn new(
        cred: &Credential<H, S>,
        expiration_date: BigInt,
        revocation_registry: &RevocationRegistry<H, S>,
        sk_holder: Option<BigInt>,
        pk_issuer: Option<[BigInt; 2]>,
        challenge: BigInt,
        index: usize,
        mut vert_x: Vec<BigInt>,
        mut vert_y: Vec<BigInt>,
    ) -> Result<Self, Box<dyn Error>> {
        let presentation = Presentation::<H, S>::new(
            cred,
            BigInt::from(expiration_date),
            revocation_registry,
            challenge,
            sk_holder,
            pk_issuer,
        );
        let x_fill = vert_x[vert_x.len() - 1].clone();
        let y_fill = vert_y[vert_y.len() - 1].clone();
        for _i in vert_x.len()..50 {
            vert_x.push(x_fill.clone());
            vert_y.push(y_fill.clone());
        }

        Ok(PolygonPresentation {
            presentation,
            index: index,
            vert_x: vert_x.try_into().unwrap(),
            vert_y: vert_y.try_into().unwrap(),
            location: Some([
                cred.attributes[index].clone(),
                cred.attributes[index + 1].clone(),
            ]),
            in_bound: false,
        })
    }
}

impl<H: HashFunction, S: SignatureFunction> ContentPresentation for PolygonPresentation<H, S> where PolygonPresentation<H,S>: Serialize{

    ///Verifies the presentation.
    fn verify(&self) -> bool {
        let mut res = self.presentation.verify_proof();

        res = res && self.presentation.verify_meta_data(0, 1, 2, 3, 4, 5, 6, 7);

        let proof = self.presentation.ark_circom_full_proof.as_ref().unwrap();

        for i in 0..50 {
            res = res && self.vert_x[i] == proof.outputs[45 + i];
            res = res && self.vert_y[i] == proof.outputs[45 + 50 + i];
        }

        res = res && self.in_bound == proof.outputs[8].is_one();

        let position = &proof.outputs[9..self
            .presentation
            .credential
            .as_ref()
            .unwrap()
            .attributes
            .len()]
            .iter()
            .position(|x| x.is_one());

        res = res && position.is_some() && self.index == position.unwrap();
        res
    }

    ///Generates a json of the content inputs.
    ///Does not include the closing brace.
    fn generate_input_json(&self) -> Result<String, Box<dyn Error>> {
        match self.presentation.generate_input_json() {
            Ok(mut json) => {
                let mut index_vec = vec![
                    BigInt::from(0);
                    self.presentation
                        .credential
                        .as_ref()
                        .unwrap()
                        .attributes
                        .len()
                ];
                index_vec[self.index] = BigInt::from(1);
                json.push_str(&format!(",\"index\":"));
                append_json_vector(&mut json, &index_vec);
                json.push_str(&format!("\"location\":"));
                append_json_vector(&mut json, self.location.as_ref().unwrap());
                json.push_str(&format!("\"vertx\":"));
                append_json_vector(&mut json, &self.vert_x);
                json.push_str(&format!("\"verty\":"));
                append_json_vector(&mut json, &self.vert_y);
                json.pop();
                Ok(json)
            }
            Err(er) => Err(er),
        }
    }

    ///Generates the presentation.
    /// Removes the private data afterwards.
    fn generate(
        &mut self,
        circuit: Option<&Vec<u8>>,
        zkey: Option<&Vec<u8>>,
    ) -> Result<(), Box<dyn Error>> {
        let input_json = match self.generate_input_json() {
            Ok(mut input_json) => {
                input_json.push('}');
                input_json
            }
            Err(err) => Err(err)?,
        };

        self.presentation.ark_circom_full_proof =
            match proof_polygon_presentation(&input_json, circuit, zkey) {
                Ok(proof) => {
                    self.in_bound = proof.outputs[8].is_one();
                    Some(proof)
                }
                Err(err) => Err(err)?,
            };

        if !self.verify() {
            Err("Proof invalid!")?
        }

        Ok(())
    }

    ///Removes the private data from the struct.
    fn remove_private_data(&mut self) {
        self.presentation.remove_private_data();
        self.location = None;
    }
}


impl<H: HashFunction, S: SignatureFunction> DelegationPresentation<H, S> {
    pub fn new(
        cred: &Credential<H, S>,
        expiration_date: BigInt,
        revocation_registry: &RevocationRegistry<H, S>,
        pk_issuer: Option<[BigInt; 2]>,
        challenge: BigInt,
        indizes: Vec<usize>,
    ) -> Result<Self, Box<dyn Error>> {
        let hash_fn = H::new();
        let link_forth = hash_fn.hash(&vec![
            challenge.to_string(),
            cred.attributes[2].to_string(),
            cred.attributes[3].to_string(),
        ]);

        let attribute_presentation = AttributePresentation::new(
            cred,
            expiration_date,
            revocation_registry,
            None,
            pk_issuer,
            challenge,
            indizes,
        )?;

        Ok(DelegationPresentation {
            attribute_presentation,
            link_forth,
        })
    }
}

impl<H: HashFunction, S: SignatureFunction> ContentPresentation for DelegationPresentation<H, S>
 where DelegationPresentation<H, S>: Serialize, AttributePresentation<H, S>: Serialize {
    

    ///Verifies the presentation.
    fn verify(&self) -> bool {
        let mut res = self.attribute_presentation.presentation.verify_proof();

        res = res
            && self.link_forth
                == self
                    .attribute_presentation
                    .presentation
                    .ark_circom_full_proof
                    .as_ref()
                    .unwrap()
                    .outputs[8];

        res
    }

    ///Generates a json of the content inputs.
    ///Does not include the closing brace.
    fn generate_input_json(&self) -> Result<String, Box<dyn Error>> {
        match self.attribute_presentation.generate_input_json() {
            Ok(json) => Ok(json),
            Err(er) => Err(er),
        }
    }

    ///Generates the presentation.
    /// Removes the private data afterwards.
    fn generate(
        &mut self,
        circuit: Option<&Vec<u8>>,
        zkey: Option<&Vec<u8>>,
    ) -> Result<(), Box<dyn Error>> {
        let input_json = match self.generate_input_json() {
            Ok(mut input_json) => {
                input_json.push('}');
                input_json
            }
            Err(err) => Err(err)?,
        };

        self.attribute_presentation
            .presentation
            .ark_circom_full_proof = match proof_delegation_presentation(&input_json, circuit, zkey)
        {
            Ok(proof) => Some(proof),
            Err(err) => Err(err)?,
        };

        if !self.verify() {
            Err("Proof invalid!")?
        }

        Ok(())
    }

    ///Removes the private data from the struct.
    fn remove_private_data(&mut self) {
        self.attribute_presentation.remove_private_data();
    }
}

///Function appending a vector in json format to a string.
fn append_json_vector<T: ToString>(json: &mut String, vec: &[T]) {
    json.push('[');

    for element in vec {
        json.push('"');
        json.push_str(&element.to_string());
        json.push('"');
        json.push(',');
    }
    if vec.len() > 0 {
        json.pop();
    }
    json.push(']');
    json.push(',');
}

#[cfg(test)]
mod test {
    use std::time::Instant;

    use crypto::poseidon::{PoseidonHasher, PoseidonSignature};

    use crate::revocation::RevocationRegistry;

    use super::*;

    ///TEST: attribute presentation
    #[test]
    fn presentation_attribute() {
        println!("Testing attribute");
        let issuer_sk =
            BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872")
                .unwrap();
        let holder_sk =
            BigInt::from_str("5728529159811704811523142037611732735149121473808289891486793728")
                .unwrap();

        let cred = Credential::<PoseidonHasher, PoseidonSignature>::new(
            &vec![
                "John".to_owned(),
                "Jones".to_owned(),
                "male".to_owned(),
                "843995700".to_owned(),
                "blue".to_owned(),
                "180".to_owned(),
                "115703781".to_owned(),
                "499422598".to_owned(),
            ],
            255 as u64,
            &[
                BigInt::from_str(
                    "11568348142699582059879762896692005650111252224863899748681544124434641871979",
                )
                .unwrap(),
                BigInt::from_str(
                    "3313301605305461355814038303705256811688733498785606352476634260778286273969",
                )
                .unwrap(),
            ],
            365,
            "Identity",
            false,
            "revocRegistry",
            issuer_sk.clone(),
        );

        let revoc_reg =
            RevocationRegistry::<PoseidonHasher, PoseidonSignature>::new(Some(issuer_sk.clone()));

        let start = Instant::now();
        let mut attr_pres = AttributePresentation::<PoseidonHasher, PoseidonSignature>::new(
            &cred,
            BigInt::from_str("1678460108000").unwrap(),
            &revoc_reg,
            Some(holder_sk.clone()),
            None,
            BigInt::from(1234),
            vec![0, 1, 2, 3, 4, 5, 6, 7],
        )
        .unwrap();

        attr_pres.generate(None, None).unwrap();
        let duration = start.elapsed().as_millis();
        println!("Presentation took {} ms", duration);

        assert!(attr_pres.verify());

        let attribute_presentation_json = serde_json::to_string(&attr_pres).unwrap();
        let attribute_presentation: AttributePresentation<PoseidonHasher, PoseidonSignature> =
         serde_json::from_str(&attribute_presentation_json).unwrap();
        assert!(attribute_presentation.verify())
    }

    ///TEST: range presentation
    #[test]
    fn presentation_range() {
        let issuer_sk =
            BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872")
                .unwrap();
        let holder_sk =
            BigInt::from_str("5728529159811704811523142037611732735149121473808289891486793728")
                .unwrap();

        let cred = Credential::<PoseidonHasher, PoseidonSignature>::new(
            &vec![
                "John".to_owned(),
                "Jones".to_owned(),
                "male".to_owned(),
                "843995700".to_owned(),
                "blue".to_owned(),
                "180".to_owned(),
                "115703781".to_owned(),
                "499422598".to_owned(),
            ],
            255 as u64,
            &[
                BigInt::from_str(
                    "11568348142699582059879762896692005650111252224863899748681544124434641871979",
                )
                .unwrap(),
                BigInt::from_str(
                    "3313301605305461355814038303705256811688733498785606352476634260778286273969",
                )
                .unwrap(),
            ],
            365,
            "Identity",
            false,
            "revocRegistry",
            issuer_sk.clone(),
        );

        let revoc_reg =
            RevocationRegistry::<PoseidonHasher, PoseidonSignature>::new(Some(issuer_sk.clone()));

        let start = Instant::now();
        let mut range_pres = RangePresentation::<PoseidonHasher, PoseidonSignature>::new(
            &cred,
            BigInt::from_str("1678460108000").unwrap(),
            &revoc_reg,
            Some(holder_sk.clone()),
            None,
            BigInt::from(1234),
            13,
            BigInt::from(170),
            BigInt::from(190),
        )
        .unwrap();

        range_pres.generate(None, None).unwrap();

        let duration = start.elapsed().as_millis();
        println!("Presentation took {} ms", duration);

        assert!(range_pres.verify());
    }

    ///TEST: polygon presentation
    #[test]
    fn presentation_polygon() {
        let issuer_sk =
            BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872")
                .unwrap();
        let holder_sk =
            BigInt::from_str("5728529159811704811523142037611732735149121473808289891486793728")
                .unwrap();

        let cred = Credential::<PoseidonHasher, PoseidonSignature>::new(
            &vec![
                "John".to_owned(),
                "Jones".to_owned(),
                "male".to_owned(),
                "843995700".to_owned(),
                "blue".to_owned(),
                "180".to_owned(),
                "115703781".to_owned(),
                "499422598".to_owned(),
            ],
            255 as u64,
            &[
                BigInt::from_str(
                    "11568348142699582059879762896692005650111252224863899748681544124434641871979",
                )
                .unwrap(),
                BigInt::from_str(
                    "3313301605305461355814038303705256811688733498785606352476634260778286273969",
                )
                .unwrap(),
            ],
            365,
            "Identity",
            false,
            "revocRegistry",
            issuer_sk.clone(),
        );

        let revoc_reg =
            RevocationRegistry::<PoseidonHasher, PoseidonSignature>::new(Some(issuer_sk.clone()));

        let start = Instant::now();
        let mut polygon_pres = PolygonPresentation::<PoseidonHasher, PoseidonSignature>::new(
            &cred,
            BigInt::from_str("1678460108000").unwrap(),
            &revoc_reg,
            Some(holder_sk.clone()),
            None,
            BigInt::from(1234),
            14,
            vec![
                BigInt::from(110000000u64),
                BigInt::from(120000000u64),
                BigInt::from(120000000u64),
                BigInt::from(110000000u64),
            ],
            vec![
                BigInt::from(400000000u64),
                BigInt::from(400000000u64),
                BigInt::from(600000000u64),
                BigInt::from(600000000u64),
            ],
        )
        .unwrap();

        polygon_pres.generate(None, None).unwrap();
        let duration = start.elapsed().as_millis();
        println!("Presentation took {} ms", duration);

        assert!(polygon_pres.verify());
    }

    ///TEST: delegation presentation
    #[test]
    fn presentation_delegation() {
        let issuer_sk =
            BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872")
                .unwrap();

        let cred = Credential::<PoseidonHasher, PoseidonSignature>::new(
            &vec![
                "John".to_owned(),
                "Jones".to_owned(),
                "male".to_owned(),
                "843995700".to_owned(),
                "blue".to_owned(),
                "180".to_owned(),
                "115703781".to_owned(),
                "499422598".to_owned(),
            ],
            255 as u64,
            &[
                BigInt::from_str(
                    "11568348142699582059879762896692005650111252224863899748681544124434641871979",
                )
                .unwrap(),
                BigInt::from_str(
                    "3313301605305461355814038303705256811688733498785606352476634260778286273969",
                )
                .unwrap(),
            ],
            365,
            "Identity",
            false,
            "revocRegistry",
            issuer_sk.clone(),
        );

        let revoc_reg =
            RevocationRegistry::<PoseidonHasher, PoseidonSignature>::new(Some(issuer_sk.clone()));

        let start = Instant::now();
        let mut del_pres = DelegationPresentation::<PoseidonHasher, PoseidonSignature>::new(
            &cred,
            BigInt::from_str("1678460108000").unwrap(),
            &revoc_reg,
            None,
            BigInt::from(1234),
            vec![5],
        )
        .unwrap();

        del_pres.generate(None, None).unwrap();
        let duration = start.elapsed().as_millis();
        println!("Presentation took {} ms", duration);

        assert!(&del_pres
            .attribute_presentation
            .presentation
            .ark_circom_full_proof
            .unwrap()
            .verify()
            .unwrap());
    }
}
