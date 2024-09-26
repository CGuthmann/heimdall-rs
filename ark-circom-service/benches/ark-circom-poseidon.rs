use std::{collections::HashMap, io::{Cursor, Seek, SeekFrom, Write}, time::Duration};

use ark_bn254::{Bn254};
use ark_circom::{ read_zkey, CircomReduction, WitnessCalculator};
use ark_ff::UniformRand;
use ark_groth16::create_proof_with_reduction_and_matrices;
use ark_std::rand::thread_rng;
use criterion::{criterion_group, criterion_main,  Criterion};
use ark_circom_service::{create_proof_from_witness, create_proof_from_witness_vector};

#[cfg(feature = "rapid_witnesscalc")]
use ark_circom_service:: poseidon_witnesscalc;
use num_bigint::BigInt;

///Benchmark for the ark-circom wasm witness generation based on the poseidon hash
fn poseidon_witness_wasm(c: &mut Criterion) {


    let inputs = {
        let mut inputs: HashMap<String, Vec<num_bigint::BigInt>> = HashMap::new();

        //name-value pair as defined in poseidon_bench.circom
        let values = inputs.entry("a".to_string()).or_insert_with(Vec::new);
        values.push(3.into());
        inputs
    };

    c.bench_function("poseidon witness wasm", |b| {
        b.iter(|| {
            let mut wtns =
                WitnessCalculator::new("lib/poseidon_bench.wasm").unwrap();
            wtns.calculate_witness_element::<Bn254, _>(inputs.clone(), false)
                .unwrap();
        })
    });
}



#[cfg(feature = "rapid_witnesscalc")]
///Benchmark for the witnesscalc witness generation based on the poseidon hash
fn poseidon_witness_witnesscalc(c: &mut Criterion) {
    c.bench_function("poseidon witness witnesscalc", |b| {
        b.iter(|| {
            let circuit = std::fs::read("lib/poseidon_bench.dat").unwrap();

            //json name-value pair as defined in poseidon_bench.circom
            poseidon_witnesscalc::generate_poseidon_witness("{\"a\":\"3\"}").unwrap();
            
        })
    });
}


#[cfg(feature = "rapid_witnesscalc")]
fn poseidon_prove(c: &mut Criterion) {
    let zkey = std::fs::read("lib/poseidon_bench.zkey").unwrap();


    let circuit = std::fs::read("lib/poseidon_bench.dat").unwrap();
    //json name-value pair as defined in poseidon_bench.circom

    let witness = poseidon_witnesscalc::generate_poseidon_witness("{\"a\":\"3\"}").unwrap();

    
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

    c.bench_function("poseidon witness witnesscalc", |b| {
        b.iter(|| {

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

                    })
                });
}

#[cfg(not(feature = "rapid_witnesscalc"))]
fn poseidon_prove(c: &mut Criterion) {

    use ark_circom::{CircomBuilder, CircomConfig};

    let zkey = match std::fs::read("lib/poseidon_bench.zkey") {
        Ok(res) => res,
        Err(_) => return,
    };

    dbg!("Create proof from circuit");
    
    let cfg = match CircomConfig::<Bn254>::new("./lib/poseidon_bench.wasm", "./lib/poseidon_bench.r1cs"){
        Ok(res) => res,
        Err(_) => return,
    };

    let mut builder = CircomBuilder::new(cfg);

    builder.push_input("a", 3);
    dbg!(&builder.inputs);
    dbg!("creating circuit");
    let circom = match builder.build() {
        Ok(res) => res,
        Err(_) => return,
    };

    
    let mut buf: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    buf.write_all(&zkey).unwrap();
    buf.seek(SeekFrom::Start(0)).unwrap();
    let (params, matrices) = read_zkey(&mut buf).unwrap();

    let mut rng = thread_rng();

    let r = ark_bn254::Fr::rand(&mut rng);
    let s = ark_bn254::Fr::rand(&mut rng);



    let assignment = circom.witness.expect("Witness error!");

    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;


    c.bench_function("poseidon witness witnesscalc", |b| {
        b.iter(|| {
            
            let proof = create_proof_with_reduction_and_matrices::<_,CircomReduction>(&params, r, s, &matrices,
        num_inputs, num_constraints, assignment.as_slice()).unwrap();

        })
    });
    
}
//Defines criterion parameters
criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_millis(1000));
    targets = poseidon_prove);

//Generates main function for the benchmarks.
criterion_main!(benches);