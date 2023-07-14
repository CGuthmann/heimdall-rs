
pub use ark_bn254::{Bn254, FrParameters};
pub use ark_ff::BigInteger;

use std::{io::{Seek,SeekFrom, Cursor}, error::Error};
use color_eyre::Result;

use ark_circom::{CircomReduction,read_zkey};
use ark_ec::PairingEngine;
use ark_ff::{Fp256,FromBytes, UniformRand, BigInteger256};
use ark_serialize::{Write, CanonicalSerialize, CanonicalDeserialize};
use ark_std::rand::thread_rng;
use ark_groth16::{
    VerifyingKey,Proof,create_proof_with_reduction_and_matrices,verify_proof as verify_proof_groth16,prepare_verifying_key
};
use num_bigint::{ BigInt};
use serde::{Serialize, Deserialize};
use witness_utils::Witness;

///Serializing function for arkworks structs with serde compatibility.
fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
    let mut bytes = vec![];
    a.serialize(&mut bytes).map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}

///Deserializing function for arkworks structs with serde compatibility.
fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error> where D: serde::de::Deserializer<'de> {
    let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize(s.as_slice());
    a.map_err(serde::de::Error::custom)
}

/// A struct capsuling a Groth16 proof
#[derive(Serialize,Deserialize)]
pub struct ArkCircomFullProof<E: PairingEngine>{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    
    pub proof: Proof<E>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub verification_key: VerifyingKey<E>,

    pub outputs: Vec<BigInt>
}

///Creates a groth16 proof for a given witness and proving key
pub fn create_proof_from_witness(witness: &Witness, zkey: &Vec<u8>)->
Result<ArkCircomFullProof<Bn254>,Box<dyn Error>>{

    let mut outputs = Vec::<BigInt>::new();

    let mut assignment: Vec<Fp256<FrParameters>> = witness.assignment.iter().map(|x| {
        let y = x.clone();
        Fp256::from(    
            BigInteger256::read(y.as_slice()).unwrap()        
        )
    }).rev().collect();
    
    assignment.reverse();
    let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    buf.write_all(&zkey).unwrap();
    buf.seek(SeekFrom::Start(0)).unwrap();
    let (params, matrices) = read_zkey(&mut buf).unwrap();

    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    for i in 1..num_inputs {
        outputs.push(
            BigInt::from_bytes_le(num_bigint::Sign::Plus,&witness.assignment[i])
        );
    }
    
    let mut rng = thread_rng();
    
    let r = ark_bn254::Fr::rand(&mut rng);
    let s = ark_bn254::Fr::rand(&mut rng);

    let proof = create_proof_with_reduction_and_matrices::<_,CircomReduction>(&params, r, s, &matrices,
         num_inputs, num_constraints, assignment.as_slice()).unwrap();

    let pvk = prepare_verifying_key(&params.vk);
    let inputs = &assignment[1..num_inputs];
    
    let verified = verify_proof_groth16(&pvk, &proof, inputs).unwrap();
    if !verified {
        Err("Proof invalid.")?
    }
        
    Ok(ArkCircomFullProof { proof, verification_key: params.vk, outputs })
}

///Implement the functionality for groth16 proofs over the Bn254 curve
impl ArkCircomFullProof<Bn254> {

    ///Checks if the proof is valid.
    pub fn verify(&self)
    -> Result<bool,Box<dyn Error>>{
    
        let pvk = prepare_verifying_key(&self.verification_key);
        
        let mut inputs: Vec<Fp256<FrParameters>> = self.outputs.iter().map(|x| {
            let mut y = x.to_bytes_le().1;
            for _i in y.len()..32{
                y.push(0);
            }
            Fp256::from(    
                BigInteger256::read(y.as_slice()).unwrap()
            )
        }).rev().collect();
        
        inputs.reverse();

        match verify_proof_groth16(&pvk, &self.proof, &inputs) {
            Ok(res) => Ok(res),
            Err(err) => Err(err.to_string())?
        } 
    }        
}

///Provides functionality required for the benchmarks.
pub mod poseidon_witnesscalc{
    use std::error::Error;

    use witness_utils::{create::WITNESS_SIZE_GUESS, read::read_wtns, Witness};


    #[link(name = "poseidon_bench", kind = "static")]   
    extern "C" {
        fn witnesscalc_poseidon_bench(
            circuit_buffer: *const u8,
            circuit_size: u64,
            json_buffer: *const u8,
            json_size: u64,
            wtns_buffer: *mut u8,
            wtns_size: *mut u64,
            error_buffer: *mut u8,
            error_msg_maxsize: u64,
        ) -> i32;
    }

    ///generates a witness for the poseidon circuit for a given json input
    /// 
    /// # Arguments
    /// * 'circuit' - The circuit definition provided by circom in the .dat file.
    ///                 Needs to be consistant with the witnesscalc library.
    pub fn generate_poseidon_witness(
        json: &str,circuit:&Vec<u8>
    ) -> Result<Witness, Box<dyn Error>> {

        let mut wtns: Vec<u8> = Vec::with_capacity(WITNESS_SIZE_GUESS as usize);
        let mut witness_size: u64 = WITNESS_SIZE_GUESS;

        let mut error: Vec<u8> = Vec::with_capacity(200);

        let mut result;
        unsafe {
            result = witnesscalc_poseidon_bench(
                circuit.as_ptr(),
                circuit.len() as u64,
                json.as_ptr(),
                json.len() as u64,
                wtns.as_mut_ptr(),
                &mut witness_size,
                error.as_mut_ptr(),
                200,
            );
        }

        if result == 1 {
            Err(result.to_string())?
        } else if result == 2 {
            wtns = Vec::with_capacity(witness_size as usize);
            unsafe {
                result = witnesscalc_poseidon_bench(
                    circuit.as_ptr(),
                    circuit.len() as u64,
                    json.as_ptr(),
                    json.len() as u64,
                    wtns.as_mut_ptr(),
                    &mut witness_size,
                    error.as_mut_ptr(),
                    200,
                );
            };

            if result != 0 {
                Err(result.to_string())?
            }
        }
        unsafe {
            wtns.set_len(witness_size as usize);
        }
        let witness = read_wtns(&wtns);
        Ok(witness)
    }
}


