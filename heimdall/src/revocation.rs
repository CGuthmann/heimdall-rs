use std::{error::Error, str::FromStr};

use crypto::{HashFunction, merkle_tree::HashTree, SignatureFunction, Signature};
use num_bigint::BigInt;
use num_traits::One;
use serde::{Serialize, Deserialize};

///Depth of the Merkle tree in the revocation registry, as defined in the circuit.
pub const REVOC_TREE_DEPTH: usize = 13;

///Maximum data points per tree leave.
/// 
/// Limitation is derived from the field used in the ZKP.
pub const MAX_LEAF_SIZE: usize = 252;

///A struct representing a revocation registry.
#[derive(Serialize,Deserialize)]
pub struct RevocationRegistry<H: HashFunction,S: SignatureFunction>{
    #[serde(bound(serialize = "HashTree<H,2>: Serialize", deserialize = "HashTree<H,2>: Deserialize<'de>"))]
    pub tree: HashTree<H,2>,
    pub signature: Option<Signature<S>>
}

impl<H:HashFunction, S: SignatureFunction> RevocationRegistry<H,S>{
    
    ///Creates a empty revocation registry.
    /// If present, signs the root with the secret key.
    pub fn new(secret_key: Option<BigInt>) ->Self{
        let depth = (REVOC_TREE_DEPTH as f32).exp2() as usize;
        let leaves = vec!["0".to_owned();depth];

        let tree = HashTree::<H,2>::new(&leaves);

        let signature = match secret_key{
            Some(sk) => Some(S::sign(sk, tree.get_root().clone())),
            None => None,
        };
        RevocationRegistry { tree, signature }
    }

    ///Switches the status of the id.
    pub fn update(&mut self, id: usize, sk: Option<BigInt>)
    -> Result<(),Box<dyn Error>>{
        if id >= ((REVOC_TREE_DEPTH as f32).exp2() * (MAX_LEAF_SIZE as f32)) as usize {
            Err("Id not in Tree")?;
        }

        let index_leaf = id / MAX_LEAF_SIZE;
        let index_bit = id % MAX_LEAF_SIZE;

        let value : BigInt= (BigInt::from_str(&self.tree.leaves[index_leaf]).unwrap() / BigInt::from(2).pow(index_bit as u32)) % 2;
        if  value.is_one(){
            self.tree.update(index_leaf,
                 (BigInt::from_str(
                    &self.tree.leaves[index_leaf]).unwrap() - BigInt::from(2).pow(index_bit as u32)
                ).to_string());
        }else {
            self.tree.update(index_leaf,
                 (BigInt::from_str(
                    &self.tree.leaves[index_leaf]).unwrap() + BigInt::from(2).pow(index_bit as u32)
                ).to_string());}

        self.signature = match sk{
            Some(sk) => Some(S::sign(sk, self.tree.get_root().clone())),
            None => None,
        };
        
        Ok(())
    }

    pub fn get_leaves(&self)-> &Vec<String>{
        &self.tree.leaves
    }

    ///Checks wether an id is revoked.
    pub fn is_revoked(&self, id: usize)-> Result<bool,Box<dyn Error>>{
        if id >= ((REVOC_TREE_DEPTH as f32).exp2() * (MAX_LEAF_SIZE as f32)) as usize {
            Err("Id not in Tree")?;
        }

        let index_leaf = id / MAX_LEAF_SIZE;
        let index_bit = id % MAX_LEAF_SIZE;

        let value : BigInt= (BigInt::from_str(&self.tree.leaves[index_leaf]).unwrap() / BigInt::from(2).pow(index_bit as u32)) % 2;
        Ok(value.is_one())
    }
}


#[cfg(test)]
mod test{
    use super::*;
    use crypto::{poseidon::{PoseidonHasher, PoseidonSignature}};


    ///TEST: revocation registry presentation
    #[test]
    pub fn revocation_registry() {
        let issuer_sk = BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872").unwrap();
        let mut rev_reg =
         RevocationRegistry::<PoseidonHasher,PoseidonSignature>::new(Some(issuer_sk.clone()));

        std::fs::write("revocation_registry_test.json", serde_json::to_string(&rev_reg).unwrap()).unwrap();

        rev_reg.update(255 as usize, Some(issuer_sk.clone())).unwrap();

        assert!(rev_reg.is_revoked(255).unwrap() == true);
        assert!(rev_reg.is_revoked(200).unwrap() == false);

    }
}