use std::{marker::PhantomData, time::{SystemTime, UNIX_EPOCH}};

use serde::{Serialize, Deserialize};
use num_bigint::BigInt;

use crypto::{HashFunction, Signature,merkle_tree::{HashTree, self}, SignatureFunction};

///Number of leaves reserved for meta attributes.
pub const META_SIZE: usize = 8;


///A struct representing a Heimdall credential.
#[derive(Debug,Serialize,Deserialize)]
pub struct Credential<H: HashFunction, S: SignatureFunction>{

    pub attributes: Vec<String>,
    pub root: BigInt,
    pub signature: Signature<S>,
    _hash_fn: PhantomData<fn()->H>,
    _sig_fn: PhantomData<fn()->S>
}


impl<H: HashFunction, S: SignatureFunction> Credential<H,S>{

    ///Generates a new Heimdall credential.
    pub fn new(attributes: &Vec<String>, id: u64, pk_holder: &[BigInt;2],
    expiration: u128, credential_type: &str,delegatable: bool, registry: &str, sk_issuer: BigInt)
     -> Credential<H,S>{
        
        let mut full_attributes = Vec::<String>::new();

        full_attributes.push(id.to_string());
        full_attributes.push(credential_type.to_owned());
        full_attributes.push(pk_holder[0].to_string());
        full_attributes.push(pk_holder[1].to_string());
        full_attributes.push(registry.to_owned());
        full_attributes.push((
             SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis() + expiration*24*60*60*1000).to_string());
        full_attributes.push((delegatable as u8).to_string());
        full_attributes.push("".to_owned());

        full_attributes.append(&mut attributes.clone());

        merkle_tree::fill_vec(&mut full_attributes, 6);
        let tree = HashTree::<H,6>::new(&full_attributes);
        let root = tree.get_root().to_owned();
        
        let signature = S::sign(sk_issuer, root.clone());

        Credential { attributes: full_attributes, root, signature,
        _hash_fn:PhantomData::<fn()->H>, _sig_fn: PhantomData::<fn()->S> }
    }
}

///Implements the Clone trait for the Heimdall Credential struct.
impl<H: HashFunction, S: SignatureFunction> Clone for Credential<H,S>{
    fn clone(&self) -> Self {
        Self { 
            attributes: self.attributes.clone(),
            root: self.root.clone(),
            signature: self.signature.clone(),
            _hash_fn: self._hash_fn.clone(),
            _sig_fn: self._sig_fn.clone() }
    }
}

#[cfg(test)]
mod test{
    use std::{str::FromStr};

    use crypto::{poseidon::{PoseidonHasher, PoseidonSignature}, SignatureFunction};
    use num_bigint::BigInt;

    use super::Credential;



    ///TEST: credential
    #[test]
    fn credential(){
        
        let issuer_sk = BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872").unwrap();

        let cred = Credential::<PoseidonHasher,PoseidonSignature>::new(&vec![
            "John".to_owned(),
            "Jones".to_owned(),
            "male".to_owned(),
            "843995700".to_owned(),
            "blue".to_owned(),
            "180".to_owned(),
            "115703781".to_owned(),
            "499422598".to_owned()
        ],
        255 as u64,
        &[BigInt::from_str("11568348142699582059879762896692005650111252224863899748681544124434641871979").unwrap(),
        BigInt::from_str("3313301605305461355814038303705256811688733498785606352476634260778286273969").unwrap()],
        365,
        "Identity",
        false,
        "revocRegistry",
        issuer_sk.clone()
        );
        
        assert!(PoseidonSignature::verify(&cred.signature, &cred.root));
    }

    
}