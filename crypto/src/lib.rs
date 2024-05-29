//!Cryptography crate.
//! 
//! A Cryptography crate, providing functionallity for hashing and signing data
//! and creating hash and Merkle trees.

pub mod merkle_tree;
pub mod poseidon;

use std::marker::PhantomData;

use num_bigint::BigInt;
use serde::{Serialize, Deserialize};

///A trait representing the basic functionallity of a hash function.
pub trait HashFunction{

    //Instatiates the hash function.
    fn new() ->Self;

    ///Hashes an vector of strings.
    fn hash(&self,inputs: &Vec<String>) -> BigInt;

    ///Hashes an array of numbers.
    fn hash_big_int(&self, inputs: &[BigInt]) -> BigInt;

    ///Hashes a signle string.
    /// Based on the hashing of an array of Strings.
    fn hash_str(&self,input: &str) -> BigInt{
        self.hash(&vec![input.to_owned()])
     }
}

///A trait representing the basic functionallity of a signature function.
pub trait SignatureFunction: Sized{

    ///Signs a message with the provided private key.
    fn sign(private_key: BigInt, message: BigInt)
    -> Signature<Self>;

    ///Verifies the signature.
    fn verify(sig: &Signature<Self>, msg: &BigInt) -> bool;
}

///A struct representing a signature
///  based on the provided SignatureFunction.
#[derive(Debug, Serialize,Deserialize)]
pub struct Signature<S: SignatureFunction>{
    pub r8: [BigInt;2],
    pub s: BigInt,
    pub public_key_signer: [BigInt;2],
    _signature_function: PhantomData<fn()->S>
}

///Implements the Clone trait for a Signature.
impl<S: SignatureFunction> Clone for Signature<S>{
    fn clone(&self) -> Self {
        Self { r8: self.r8.clone(), s: self.s.clone(),
             public_key_signer: self.public_key_signer.clone(),
             _signature_function: self._signature_function.clone() }
    }
}

