//! A hash tree implementation.
//! 
//! Provides an implementation for a hash tree. 
//! In case the BRANCHING_FACTOR=2 it also provides the ability to create a Merkle proof.

use std::{marker::PhantomData, error::Error, vec};

use num_bigint::BigInt;
use num_traits::Pow;
use serde::{Serialize, Deserialize};

use crate::HashFunction;

/// A struct representing a hash tree.
/// 
/// Serializable with serde.
#[derive(Debug, Serialize, Deserialize)]
pub struct HashTree<H: HashFunction, const BRANCHING_FACTOR: usize > {
    depth: u32,
    pub leaves: Vec<String>,
    pub data: Vec<BigInt>,
    _hasher: PhantomData<H>,
}

/// A struct representing a Merkle proof.
/// Only availabe for BRANCHING_FACTOR=2.
/// 
/// Serializable with serde.
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct  MerkleProof<H: HashFunction, const BRANCHING_FACTOR: usize > {
    pub path: Vec<usize>, //0 or 1
    pub lemma: Vec<BigInt>,
    _hash_fn: PhantomData<H>,
}

impl<H: HashFunction, const BRANCHING_FACTOR: usize > MerkleProof<H,BRANCHING_FACTOR> {

    ///Instatiates a new MerkleProof.
    pub fn new(path: Vec<usize>, 
        lemma: Vec<BigInt>) -> Self{
            Self { path, lemma, _hash_fn: PhantomData::<H> }
        }
}

///Implements generic hash tree functions.
impl<H: HashFunction, const BRANCHING_FACTOR: usize> HashTree<H, BRANCHING_FACTOR> {
    
    ///Instatiates a new hash tree. 
    /// 
    /// # Arguments
    /// * 'input' - A vector of strings, which become the leaves by hashing.
    /// 
    /// # Panics
    /// 
    /// The function whill panic, should the input size not be a power of the BRANCHING_FACTOR.
    pub fn new(input: &Vec<String>) -> Self {
        let depth = (input.len() as f32).log(BRANCHING_FACTOR as f32).ceil() as u32;

        assert!((BRANCHING_FACTOR as f32).pow(depth as f32) == (input.len() as f32));

        let data = Vec::<BigInt>::new();
        let mut leaves = Vec::<String>::new();

        leaves.append(&mut input.clone());


        let mut tree = HashTree { depth,leaves, data, _hasher: PhantomData::<H> };
        tree.generate_tree();        
        
        tree
    }

    /// Retrieves the root of the hash tree.
    pub fn get_root(&self) -> &BigInt {
        &self.data[self.data.len() - 1]
    }

    /// Generates the hash tree from the leaves.
    /// 
    /// While the leaves can be modified, the number of leaves is assumed to be constant.
    fn generate_tree(&mut self){
        let hasher = H::new();
        
        let size = ( ((BRANCHING_FACTOR as f32).pow((self.depth + 1) as f32) - 1.0)/ ((BRANCHING_FACTOR -1 ) as f32) ) as usize;
        self.data = Vec::new();

        let mut hashes: Vec<BigInt> = self.leaves.clone().into_iter().map(|x| hasher.hash_str(&x)).collect();

        self.data.append(&mut hashes);

        for j in (BRANCHING_FACTOR-1..size).step_by(BRANCHING_FACTOR) {
            self.data.push(hasher.hash_big_int(&self.data[j + 1 -BRANCHING_FACTOR..=j]));
        }
    }

    ///Updates the leave at 'index' and regenerates the hash tree.
    pub fn update(&mut self, index: usize, new_leave: String) {
        self.leaves[index] = new_leave;
        self.generate_tree();
    }



}

///Implements the Merkle tree functionality.
impl<H: HashFunction> HashTree<H,2>  {
    
    ///Generates a Merkle proof for the leave at 'index'.
    pub fn generate_proof(&self,index: usize)
    -> Result<MerkleProof<H,2>,Box<dyn Error>>{
        if self.leaves.len() <= index {
            Err("Index out of bounds")?;
        } 
        let mut path = vec![0 as usize;self.depth as usize];

        for i in 0 .. self.depth as usize{
            path[i] = ((index >> i) & 1) as usize;
        }

        let mut lemma  = vec![self.data[index].clone()];
        let mut offset: usize = 0; 
        let mut pos = index;
        let mut width = self.leaves.len();
        for i in 0 .. self.depth as usize {
            if path[i] == 1{
                lemma.push(self.data[offset + pos -1].clone());
            } else {
                lemma.push(self.data[offset + pos +1].clone());
            }
            pos >>= 1;
            offset += width;
            width >>= 1;
        }
        lemma.push(self.get_root().clone());

        Ok(MerkleProof::<H,2>::new(path,lemma))
        
    }
}

///Implements the Merkle proof functionality.
impl<H: HashFunction>  MerkleProof<H,2>{
    
    ///Checks if the proof is valid.
    pub fn verify(&self)
    ->Result<bool,Box<dyn Error>>{
        let hash_fn = H::new();

        let mut current_hash = self.lemma[0].clone();

        for i in 0..self.path.len() {

            if self.path[i] == 0 {
                current_hash = hash_fn.hash_big_int(&[
                    current_hash,
                    self.lemma[i+1].clone()
                ]);
            }else if self.path[i]  == 1{
                current_hash = hash_fn.hash_big_int(&[
                    self.lemma[i+1].clone(),
                    current_hash
                ]);
            }else {
                Err("Path index out of bounds")?
            }
        }
        
        Ok(current_hash == self.lemma[self.lemma.len() -1])
    }
}

/// Helper function for preparing the inputs for a hash tree.
/// 
/// Fills the 'values' vector up to the next bigger power of the branching factor.
pub fn fill_vec(values: &mut Vec<String>, branching_factor: usize){
    let depth = (values.len() as f32).log(branching_factor as f32).ceil();
    let leave_count =  (branching_factor as f32).pow(depth) as usize;

    for _i in values.len() .. leave_count{
        values.push("".to_owned());
    }
}

#[cfg(test)]
mod test{
    use crate::poseidon::PoseidonHasher;

    use super::HashTree;

    ///TEST: basic hash tree functionality
    #[test]
    fn hash_tree(){
        let mut tree = HashTree::<PoseidonHasher,2>::new(
            &vec!["a".to_owned(),"b".to_owned(),"c".to_owned(),"d".to_owned()]
        );
        assert!(tree.get_root().to_string() ==
         "17730910362166365378641598934717218753860034849162057842670951476042705047777");

        tree.update(0, "b".to_owned());
        assert!(tree.get_root().to_string() ==
         "3850662019765955860838380521649163158910746042417369858350919191420916554922");

    }

    ///TEST: binary hash tree (Merkle tree)
    #[test]
    fn merkle_tree(){
        let tree = HashTree::<PoseidonHasher,2>::new(
            &vec!["a".to_owned(),"b".to_owned(),"c".to_owned(),"d".to_owned()]
        );

        let merkle_proof = tree.generate_proof(3).unwrap();
        assert!(merkle_proof.verify().unwrap());
    }
}