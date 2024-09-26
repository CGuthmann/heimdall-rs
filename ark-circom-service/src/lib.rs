pub use ark_bn254::{Bn254, FrParameters};
pub use ark_ff::BigInteger;
use serde_json::Value;

use ark_std::Zero;
use num_traits::cast::ToPrimitive;

use color_eyre::Result;
use std::{
    error::Error,
    io::{Cursor, Seek, SeekFrom},
    str::FromStr,
};

use ark_circom::{read_zkey, CircomBuilder, CircomConfig, CircomReduction};
use ark_ec::PairingEngine;
use ark_ff::{BigInteger256, Fp256, FromBytes, PrimeField, UniformRand};
use ark_groth16::{
    create_proof_with_reduction_and_matrices, prepare_verifying_key,
    verify_proof as verify_proof_groth16, Proof, VerifyingKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use ark_std::rand::thread_rng;
use num_bigint::{BigInt, BigUint};
use serde::{de::value, Deserialize, Serialize};
use witness_utils::Witness;

///Serializing function for arkworks structs with serde compatibility.
fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = vec![];
    a.serialize(&mut bytes).map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}

///Deserializing function for arkworks structs with serde compatibility.
fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize(s.as_slice());
    a.map_err(serde::de::Error::custom)
}

/// A struct capsuling a Groth16 proof
#[derive(Serialize, Deserialize)]
pub struct ArkCircomFullProof<E: PairingEngine> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub proof: Proof<E>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub verification_key: VerifyingKey<E>,

    pub outputs: Vec<BigInt>,
}

///Creates a groth16 proof for a given witness and proving key
pub fn create_proof_from_witness(
    witness: &Witness,
    zkey: &Vec<u8>,
) -> Result<ArkCircomFullProof<Bn254>, Box<dyn Error>> {
    let mut outputs = Vec::<BigInt>::new();

    let mut assignment: Vec<Fp256<FrParameters>> = witness
        .assignment
        .iter()
        .map(|x| {
            let y = x.clone();
            Fp256::from(BigInteger256::read(y.as_slice()).unwrap())
        })
        .rev()
        .collect();

    assignment.reverse();
    let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    buf.write_all(&zkey).unwrap();
    buf.seek(SeekFrom::Start(0)).unwrap();
    let (params, matrices) = read_zkey(&mut buf).unwrap();

    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    for i in 1..num_inputs {
        outputs.push(BigInt::from_bytes_le(
            num_bigint::Sign::Plus,
            &witness.assignment[i],
        ));
    }

    let mut rng = thread_rng();

    let r = ark_bn254::Fr::rand(&mut rng);
    let s = ark_bn254::Fr::rand(&mut rng);

    let proof = create_proof_with_reduction_and_matrices::<_, CircomReduction>(
        &params,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        assignment.as_slice(),
    )
    .unwrap();

    let pvk = prepare_verifying_key(&params.vk);
    let inputs = &assignment[1..num_inputs];

    let verified = verify_proof_groth16(&pvk, &proof, inputs).unwrap();
    if !verified {
        Err("Proof invalid.")?
    }

    Ok(ArkCircomFullProof {
        proof,
        verification_key: params.vk,
        outputs,
    })
}

///Creates a groth16 proof for a given witness vektor and proving key
pub fn create_proof_from_witness_vector(
    witness: &Vec<Fp256<FrParameters>>,
    zkey: &Vec<u8>,
) -> Result<ArkCircomFullProof<Bn254>, Box<dyn Error>> {
    let mut outputs = Vec::<BigInt>::new();

    
    let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    buf.write_all(&zkey).unwrap();
    buf.seek(SeekFrom::Start(0)).unwrap();
    let (params, matrices) = read_zkey(&mut buf).unwrap();

    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;


    let mut rng = thread_rng();

    let r = ark_bn254::Fr::rand(&mut rng);
    let s = ark_bn254::Fr::rand(&mut rng);

    let proof = create_proof_with_reduction_and_matrices::<_, CircomReduction>(
        &params,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        witness.as_slice(),
    )
    .unwrap();

    let pvk = prepare_verifying_key(&params.vk);
    let inputs = &witness[1..num_inputs];

    let verified = verify_proof_groth16(&pvk, &proof, inputs).unwrap();
    if !verified {
        Err("Proof invalid.")?
    }

    Ok(ArkCircomFullProof {
        proof,
        verification_key: params.vk,
        outputs,
    })
}

pub fn create_proof_from_circuit(
    wasm_path: &str,
    r1cs_path: &str,
    json: &str,
    zkey: &Vec<u8>,
) -> Result<ArkCircomFullProof<Bn254>, Box<dyn Error>> {
    let cfg = CircomConfig::<Bn254>::new(wasm_path, r1cs_path)?;

    let mut builder = CircomBuilder::new(cfg);

    let inputs: Value = serde_json::from_str(json)?;

    dbg!("creating inputs");
    
    match inputs.as_object() {
        Some(inputs) => {
            for (key, value) in inputs {
                if value.is_string() {
                    builder.push_input(
                        key,
                        BigInt::from_str(&value.as_str().ok_or("Input value not a string.")?)?,
                    )
                } else if value.is_array() {
                    for value in value.as_array().ok_or("Input value not  an array.")? {
                        builder.push_input(
                            key,
                            BigInt::from_str(&value.as_str().ok_or("Input value not a string.")?)?,
                        )
                    }
                } else {
                    dbg!(key);
                    dbg!(value);
                }
            }
        }
        None => {}
    }
    dbg!(&builder.inputs);
    dbg!("creating circuit");
    let circom = builder.build()?;

    
    let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    buf.write_all(&zkey).unwrap();
    buf.seek(SeekFrom::Start(0)).unwrap();
    let (params, matrices) = read_zkey(&mut buf).unwrap();

    let mut rng = thread_rng();

    let r = ark_bn254::Fr::rand(&mut rng);
    let s = ark_bn254::Fr::rand(&mut rng);

    
    let inputs = circom.get_public_inputs().expect("No inputs");// &assignment[1..num_inputs];

    let assignment = circom.witness.expect("Witness error!");

    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;


    let proof = create_proof_with_reduction_and_matrices::<_,CircomReduction>(&params, r, s, &matrices,
         num_inputs, num_constraints, assignment.as_slice()).unwrap();

    let pvk = prepare_verifying_key(&params.vk);
    

    let verified = verify_proof_groth16(&pvk, &proof, inputs.as_slice()).unwrap();
    if !verified {
        Err("Proof invalid.")?
    }

    let mut outputs = Vec::<BigInt>::new();

    for i in 1..num_inputs {
        outputs.push(BigInt::from_bytes_be(num_bigint::Sign::Plus,assignment[i].into_repr().to_bytes_be().as_slice()));
        
    }
    
    Ok(ArkCircomFullProof {
        proof,
        verification_key: params.vk,
        outputs
    })
}


///Implement the functionality for groth16 proofs over the Bn254 curve
impl ArkCircomFullProof<Bn254> {
    ///Checks if the proof is valid.
    pub fn verify(&self) -> Result<bool, Box<dyn Error>> {
        let pvk = prepare_verifying_key(&self.verification_key);

        let mut inputs: Vec<Fp256<FrParameters>> = self
            .outputs
            .iter()
            .map(|x| {
                let mut y = x.to_bytes_le().1;
                for _i in y.len()..32 {
                    y.push(0);
                }
                Fp256::from(BigInteger256::read(y.as_slice()).unwrap())
            })
            .rev()
            .collect();

        inputs.reverse();

        match verify_proof_groth16(&pvk, &self.proof, &inputs) {
            Ok(res) => Ok(res),
            Err(err) => Err(err.to_string())?,
        }
    }
}

///Provides functionality required for the benchmarks.

#[cfg(feature = "rapid_witnesscalc")]
pub mod poseidon_witnesscalc {
    use std::{error::Error, io::{Cursor, Seek, SeekFrom, Write}, time::Instant};

    use ark_bn254::{Bn254, FrParameters};
    use ark_circom::{read_zkey, CircomBuilder, CircomConfig, CircomReduction};
    use ark_ff::{BigInteger, BigInteger256, Fp256, FromBytes, UniformRand};
    use ark_groth16::{
        create_proof_with_reduction_and_matrices, create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof
    };
    use ark_std::rand::thread_rng;
    use witness_utils::{create::WITNESS_SIZE_GUESS, read::read_wtns, Witness};

    use crate::create_proof_from_circuit;

    ///generates a witness for the poseidon circuit for a given json input
    ///
    /// # Arguments
    /// * 'circuit' - The circuit definition provided by circom in the .dat file.
    ///                 Needs to be consistant with the witnesscalc library.
    pub fn generate_poseidon_witness(json: &str) -> Result<Vec<Fp256<FrParameters>>, Box<dyn Error>> {
        let cfg =
            CircomConfig::<Bn254>::new("./lib/poseidon_bench.wasm", "./lib/poseidon_bench.r1cs")?;
        
        let mut builder = CircomBuilder::new(cfg);
        builder.push_input("a", 3);


        // Get the populated instance of the circuit with the witness
        let circom = builder.build()?;

        let inputs = circom.get_public_inputs().unwrap();
        dbg!(&inputs);


        let witness_vec = circom.witness.expect("No witness.");
    
        Ok(witness_vec)
    }
}




#[cfg(test)]
mod test{
    use crate::create_proof_from_circuit;


    #[test]
    pub fn test_proof_gen(){
        let zkey = std::fs::read("./lib/test_circuit.zkey").unwrap();
        let proof = create_proof_from_circuit("./lib/test_circuit.wasm", "./lib/test_circuit.r1cs", "{\"a\": [\"1\",\"2\"]}", &zkey).unwrap();
        dbg!(proof.verify());
    }
}