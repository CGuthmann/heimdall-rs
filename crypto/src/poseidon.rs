//! A sample hash and signature function implementation.
//! 
//! Provides a implementation for the hash and signature trait based
//! on the poseidon hash function.


use std::str::FromStr;

use ff::{PrimeField, PrimeFieldRepr,to_hex};
use num_bigint::BigInt;
use num_traits::Num;
use poseidon_rs::{Fr, Poseidon};
use babyjubjub_rs::{PrivateKey, Signature as babySignature, Point, Fr as babyjubjubFr, new_key};
use serde::{Serialize, Deserialize};

use crate::{HashFunction, Signature, SignatureFunction};


/// A struct representing the instance of a poseidon hash function.
/// 
/// A tuple struct wrapping the poseidon hasher provided by poseidon_rs.
/// This allows for the further implementation of this struct.
pub struct PoseidonHasher(
    Poseidon
);

/// A struct representing the poseidon signature function.
#[derive(Serialize,Deserialize)]
pub struct PoseidonSignature;

///Implementing additions to the poseidon_rs implementation.
impl PoseidonHasher {  

    ///Constant for the maximum input length
    /// of the poseidon hash function.
    const POSEIDON_MAX_LENGTH: usize = 6;   
}

///Implementing the HashFunction trait for the PoseidonHasher struct.
impl HashFunction for PoseidonHasher{

    ///Instatiates a new poseidon hash function.
    fn new() -> PoseidonHasher{
        PoseidonHasher(Poseidon::new())
    }

    ///Hashes an array of numbers.
    /// Array length is limited by POSEIDON_MAX_LENGTH.
    fn hash_big_int(&self, inputs: &[BigInt]) -> BigInt {
        let inputs_converted: Vec<Fr> = inputs.into_iter().map(|x| Fr::from_str(&x.to_string()).unwrap()).collect();
        
        let repr = self.0.hash(inputs_converted).unwrap().into_repr();
        if repr.is_zero(){
            return BigInt::from(0);
        }

        let mut buf = Vec::<u8>::new();
        repr.write_le(&mut buf).unwrap();
        BigInt::from_bytes_le(num_bigint::Sign::Plus, &buf)
    }

    ///Hashes an vector of strings.
    /// Vector length is limited by POSEIDON_MAX_LENGTH.
    fn hash(&self,inputs: &Vec<String>) -> BigInt {
        let inputs_converted: Vec<BigInt> = inputs.into_iter().map(
            |x| {
                let res = match BigInt::from_str(&x){
                    Ok(y) => y,
                    Err(_) => {
                        if x == ""{
                            return BigInt::from(0);
                        }

                        let v: Vec<u16> = x.encode_utf16().collect();
                        let mut input_array = Vec::<u8>::new();
                        for i in 0..v.len(){
                            input_array.push((v[i] & 255) as u8);
                            input_array.push((v[i] >> 8) as u8);
                        }
                        let mut first = BigInt::from(input_array[0]);
                        let upper_bound = (input_array.len() as f32/PoseidonHasher::POSEIDON_MAX_LENGTH as f32).ceil() as usize;
                        for i in 1 ..upper_bound+1 {   
                            let mut input = vec![first];
                            for j in 0 .. PoseidonHasher::POSEIDON_MAX_LENGTH -1 {
                                let index = i*PoseidonHasher::POSEIDON_MAX_LENGTH + j;
                                if input_array.len() > index {
                                    input.push(BigInt::from(input_array[index]));
                                }
                            }
                            first = self.hash_big_int(input.as_slice());
                        }

                        first
                    }
                };

                res
            }
        ).collect();

        self.hash_big_int(inputs_converted.as_slice())
    }
}


///Implementing the SignatureFunction trait for PoseidonSignature.
/// Utilizes the babyjubjubrs crate.
impl SignatureFunction for PoseidonSignature {

    //Signs a message with the provided private key.
    fn sign(private_key: BigInt, message: BigInt) -> Signature<PoseidonSignature> {

        let mut private_key_raw = private_key.to_bytes_le().1;
        assert!(private_key_raw.len() <= 32);
        for _i in private_key_raw.len() .. 32 {
            private_key_raw.push(0);
        }
        private_key_raw.reverse();

        assert!(private_key_raw.len() == 32);


        let private_key = PrivateKey::import(private_key_raw).expect("imported key can not be bigger than 32 bytes");

        let sig: babySignature = private_key.sign(message).expect("Message outside of finite field");

        let public_key = private_key.public();
        
        
        Signature { r8: [
                    BigInt::from_str_radix(&to_hex(&sig.r_b8.x),16).unwrap(),
                    BigInt::from_str_radix(&to_hex(&sig.r_b8.y),16).unwrap()
                    ],
                     s: sig.s,
                    public_key_signer: [
                        BigInt::from_str_radix(&to_hex(&public_key.x),16).unwrap(),
                        BigInt::from_str_radix(&to_hex(&public_key.y),16).unwrap()
                    ],
                _signature_function: std::marker::PhantomData::<fn()->PoseidonSignature>}
    }

    ///Verifies the signature.
    fn verify(sig: &Signature<Self>, msg: &BigInt) -> bool {
        
        let public_key = Point{ x: babyjubjubFr::from_str(&sig.public_key_signer[0].to_string()).unwrap(), 
                                   y: babyjubjubFr::from_str(&sig.public_key_signer[1].to_string()).unwrap(), };
        
        let baby_jubjub_signature = babySignature { 
            r_b8: Point{
                 x: babyjubjubFr::from_str(&sig.r8[0].to_string()).unwrap(), 
                 y: babyjubjubFr::from_str(&sig.r8[1].to_string()).unwrap() 
                },
                 s: sig.s.clone() };

        babyjubjub_rs::verify(public_key, baby_jubjub_signature, msg.clone())
    }
}

///Implementing private/public key functionality
impl PoseidonSignature {    

    pub fn generate_private_key() -> BigInt{
        let private_key = new_key();
        private_key.scalar_key()
    }

    pub fn get_public_keys(secret_key: BigInt) -> [BigInt;2]{      

        let mut private_key_raw = secret_key.to_bytes_le().1;
        assert!(private_key_raw.len() <= 32);
        for _i in private_key_raw.len() .. 32 {
            private_key_raw.push(0);
        }
        private_key_raw.reverse();

        assert!(private_key_raw.len() == 32);

        let private_key = PrivateKey::import(private_key_raw).expect("imported key can not be bigger than 32 bytes");
        let public_key = private_key.public();
        [
                        BigInt::from_str_radix(&to_hex(&public_key.x),16).unwrap(),
                        BigInt::from_str_radix(&to_hex(&public_key.y),16).unwrap()
                    ]
    }
}

#[cfg(test)]
mod test{
    use super::*;
    use crate::SignatureFunction;
    use num_bigint::BigInt;
    use ff::{ hex};

    ///TEST: poseidon hash function
    #[test]
    fn test_poseidon_hash(){
        let input = vec![
            BigInt::from_str("2010143491207902444122668013146870263468969134090678646686512037244361350365").unwrap()
        ];
        let hasher = PoseidonHasher::new();
        let result = hasher.hash_big_int(&input);

        assert_eq!(result,BigInt::from_str("12353927035604053351139001901051657562744637204994815165268679511342104426088").unwrap());

    }

    ///TEST: conversion for the private key between BigInt to PrivateKey
    #[test]
    fn test_poseidon_signature_key_conversion(){

        let private_key = 
        BigInt::from_str_radix("0001020304050607080900010203040506070809000102030405060708090001",16).unwrap();
    
    
        let mut sk_raw = private_key.to_bytes_le().1;
        assert!(sk_raw.len() <= 32);
        for _i in sk_raw.len() .. 32 {
            sk_raw.push(0);
        }
        sk_raw.reverse();

        assert!(sk_raw.len() == 32);


        let pk = PrivateKey::import(sk_raw).expect("imported key can not be bigger than 32 bytes");
        
        let sk = PrivateKey::import(
            hex::decode("0001020304050607080900010203040506070809000102030405060708090001")
                .unwrap(),
        ).unwrap();

        assert_eq!(&sk.key,&pk.key);
    }

    ///TEST: signing a message with the poseidon signature
    #[test]
    fn test_poseidon_signature(){
        let private_key = 
        BigInt::from_str_radix("0001020304050607080900010203040506070809000102030405060708090001",16).unwrap();

        let msg = BigInt::from(42);

        let sig: Signature<PoseidonSignature> = PoseidonSignature::sign(private_key.clone(), msg.clone());

        assert!(PoseidonSignature::verify(&sig, &msg));
    }

}