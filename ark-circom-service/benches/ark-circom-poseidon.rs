use std::{collections::HashMap, time::{Duration}};

use ark_bn254::{Bn254};
use ark_circom::{ WitnessCalculator};
use criterion::{criterion_group, criterion_main,  Criterion};
use ark_circom_service::{poseidon_witnesscalc, create_proof_from_witness,};

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

///Benchmark for the witnesscalc witness generation based on the poseidon hash
fn poseidon_witness_witnesscalc(c: &mut Criterion) {
    c.bench_function("poseidon witness witnesscalc", |b| {
        b.iter(|| {
            let circuit = std::fs::read("lib/poseidon_bench.dat").unwrap();

            //json name-value pair as defined in poseidon_bench.circom
            poseidon_witnesscalc::generate_poseidon_witness("{\"a\":\"3\"}", &circuit).unwrap();
            
        })
    });
}

fn poseidon_prove(c: &mut Criterion) {
    let circuit = std::fs::read("lib/poseidon_bench.dat").unwrap();
    let zkey = std::fs::read("lib/poseidon_bench.zkey").unwrap();


    //json name-value pair as defined in poseidon_bench.circom
    let witness = poseidon_witnesscalc::generate_poseidon_witness("{\"a\":\"3\"}", &circuit).unwrap();

    c.bench_function("poseidon witness witnesscalc", |b| {
        b.iter(|| {
            create_proof_from_witness(&witness, &zkey).unwrap();
        })
    });
}

//Defines criterion parameters
criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_millis(1000));
    targets = poseidon_witness_wasm, poseidon_witness_witnesscalc);

//Generates main function for the benchmarks.
criterion_main!(benches);