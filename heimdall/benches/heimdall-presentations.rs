use heimdall::{presentation::*, credential::Credential, revocation::RevocationRegistry,
     zkp::{attribute::proof_attribute_presentation, delegation::proof_delegation_presentation,
    polygon::proof_polygon_presentation, range::proof_range_presentation}
    };

use crypto::{poseidon::*};
use criterion::{
    criterion_group,
    criterion_main,
    Criterion, black_box
};
use num_bigint::BigInt;
use std::{str::FromStr, time::{Duration, Instant}};

//benchmarks the attribute presentation generation 
fn attribute_presentation(c: &mut Criterion){
    let issuer_sk =
        BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872")
            .unwrap();
    let holder_sk =
        BigInt::from_str("5728529159811704811523142037611732735149121473808289891486793728")
            .unwrap();

    let credential = black_box(
        Credential::<PoseidonHasher, PoseidonSignature>::new(
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
        )
    );

    let mut circuit = None;
    let mut zkey = None;
    if cfg!(target_os = "android") {
        circuit = Some(
            std::fs::read("presentation_attribute.dat").unwrap()
        );
        zkey = Some(
            std::fs::read("presentation_attribute.zkey").unwrap()
        );

    }
    
    let revoc_reg =
    RevocationRegistry::<PoseidonHasher, PoseidonSignature>::new(Some(issuer_sk.clone()));

    c.bench_function("attribute presentation generation", 
        |b| b.iter(||{
            let mut attr_pres = AttributePresentation::<PoseidonHasher, PoseidonSignature>::new(
                &credential,
                BigInt::from_str("1678460108000").unwrap(),
                &revoc_reg,
                Some(holder_sk.clone()),
                None,
                BigInt::from(1234),
                vec![0, 1, 2, 3, 4, 5, 6, 7],
            )
            .unwrap();
            attr_pres.generate(circuit.as_ref(), zkey.as_ref()).unwrap();
        })
    );
}

//benchmarks the attribute presentation step by step
fn attribute_presentation_fragmented(c: &mut Criterion){
    let issuer_sk =
        BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872")
            .unwrap();
    let holder_sk =
        BigInt::from_str("5728529159811704811523142037611732735149121473808289891486793728")
            .unwrap();

    let mut start = Instant::now();
    let credential = black_box(
        Credential::<PoseidonHasher, PoseidonSignature>::new(
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
        )
    );
    let mut duration = start.elapsed().as_millis();
    println!("//Credential creation: {}ms", duration);

    let mut circuit = None;
    let mut zkey = None;
    if cfg!(target_os = "android") {
        circuit = Some(
            std::fs::read("presentation_attribute.dat").unwrap()
        );
        zkey = Some(
            std::fs::read("presentation_attribute.zkey").unwrap()
        );

    }
    
    let revoc_reg =
    RevocationRegistry::<PoseidonHasher, PoseidonSignature>::new(Some(issuer_sk.clone()));

    start = Instant::now();
    let mut attr_pres = AttributePresentation::<PoseidonHasher, PoseidonSignature>::new(
        &credential,
        BigInt::from_str("1678460108000").unwrap(),
        &revoc_reg,
        Some(holder_sk.clone()),
        None,
        BigInt::from(1234),
        vec![0, 1, 2, 3, 4, 5, 6, 7],
    )
    .unwrap();

    duration = start.elapsed().as_millis();
    println!("Attribute presentation initiation: {}ms", duration);


    start = Instant::now();
    let input_json = match attr_pres.generate_input_json() {
        Ok(mut input_json) => {
            input_json.push('}');
            input_json
        }

        Err(err) => panic!("Input json creation failed."),
    };
    duration = start.elapsed().as_millis();
    println!("Attribute presentation input creation: {}ms", duration);

    start = Instant::now();
    attr_pres.presentation.ark_circom_full_proof =
        match proof_attribute_presentation(&input_json, circuit.as_ref(), zkey.as_ref()) {
            Ok(proof) => Some(proof),
            Err(err) => panic!("Proving process failed"),
        };

    duration = start.elapsed().as_millis();
    println!("Attribute presentation generation: {}ms", duration);

    start = Instant::now();
    attr_pres.remove_private_data();
    duration = start.elapsed().as_millis();
    println!("Attribute presentation removing private data: {}ms", duration);
}

//benchmarks the range presentation generation 
fn range_presentation(c: &mut Criterion){
    let issuer_sk =
        BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872")
            .unwrap();
    let holder_sk =
        BigInt::from_str("5728529159811704811523142037611732735149121473808289891486793728")
            .unwrap();

    let credential = black_box(
        Credential::<PoseidonHasher, PoseidonSignature>::new(
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
        )
    );
    
    let revoc_reg =
    RevocationRegistry::<PoseidonHasher, PoseidonSignature>::new(Some(issuer_sk.clone()));

    let mut circuit = None;
    let mut zkey = None;
    if cfg!(target_os = "android") {
        circuit = Some(
            std::fs::read("presentation_range.dat").unwrap()
        );
        zkey = Some(
            std::fs::read("presentation_range.zkey").unwrap()
        );

    }

    c.bench_function("range presentation generation", 
        |b| b.iter(||{
            let mut range_pres = RangePresentation::<PoseidonHasher, PoseidonSignature>::new(
                &credential,
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
    
            range_pres.generate(circuit.as_ref(), zkey.as_ref()).unwrap();
        })
    );
}

//benchmarks the range presentation step by step
fn range_presentation_fragmented(c: &mut Criterion){
    let issuer_sk =
        BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872")
            .unwrap();
    let holder_sk =
        BigInt::from_str("5728529159811704811523142037611732735149121473808289891486793728")
            .unwrap();

    let mut start = Instant::now();
    let credential = black_box(
        Credential::<PoseidonHasher, PoseidonSignature>::new(
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
        )
    );
    let mut duration = start.elapsed().as_millis();
    println!("//Credential creation: {}ms", duration);

    let mut circuit = None;
    let mut zkey = None;
    if cfg!(target_os = "android") {
        circuit = Some(
            std::fs::read("presentation_range.dat").unwrap()
        );
        zkey = Some(
            std::fs::read("presentation_range.zkey").unwrap()
        );

    }
    
    let revoc_reg =
    RevocationRegistry::<PoseidonHasher, PoseidonSignature>::new(Some(issuer_sk.clone()));

    start = Instant::now();
    let mut range_pres = RangePresentation::<PoseidonHasher, PoseidonSignature>::new(
        &credential,
        BigInt::from_str("1678460108000").unwrap(),
        &revoc_reg,
        Some(holder_sk.clone()),
        None,
        BigInt::from(1234),
        13,
        BigInt::from(100),
        BigInt::from(200)
    )
    .unwrap();

    duration = start.elapsed().as_millis();
    println!("Range presentation initiation: {}ms", duration);


    start = Instant::now();
    let input_json = match range_pres.generate_input_json() {
        Ok(mut input_json) => {
            input_json.push('}');
            input_json
        }

        Err(err) => panic!("Input json creation failed."),
    };
    duration = start.elapsed().as_millis();
    println!("Range presentation input creation: {}ms", duration);

    start = Instant::now();
    range_pres.presentation.ark_circom_full_proof =
        match proof_range_presentation(&input_json, circuit.as_ref(), zkey.as_ref()) {
            Ok(proof) => Some(proof),
            Err(err) => panic!("Proving process failed"),
        };

    duration = start.elapsed().as_millis();
    println!("Range presentation generation: {}ms", duration);

    start = Instant::now();
    range_pres.remove_private_data();
    duration = start.elapsed().as_millis();
    println!("Range presentation removing private data: {}ms", duration);
}

//benchmarks the polygon presentation generation 
fn polygon_presentation(c: &mut Criterion){
    let issuer_sk =
        BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872")
            .unwrap();
    let holder_sk =
        BigInt::from_str("5728529159811704811523142037611732735149121473808289891486793728")
            .unwrap();

    let credential = black_box(
        Credential::<PoseidonHasher, PoseidonSignature>::new(
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
        )
    );
    
    let revoc_reg =
    RevocationRegistry::<PoseidonHasher, PoseidonSignature>::new(Some(issuer_sk.clone()));


    let mut circuit = None;
    let mut zkey = None;
    if cfg!(target_os = "android") {
        circuit = Some(
            std::fs::read("presentation_polygon.dat").unwrap()
        );
        zkey = Some(
            std::fs::read("presentation_polygon.zkey").unwrap()
        );

    }

    c.bench_function("polygon presentation generation", 
        |b| b.iter(||{
            let mut polygon_pres = PolygonPresentation::<PoseidonHasher, PoseidonSignature>::new(
                &credential,
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
    
            polygon_pres.generate(circuit.as_ref(), zkey.as_ref()).unwrap();
        })
    );
}

//benchmarks the polygon presentation step by step
fn polygon_presentation_fragmented(c: &mut Criterion){
    let issuer_sk =
        BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872")
            .unwrap();
    let holder_sk =
        BigInt::from_str("5728529159811704811523142037611732735149121473808289891486793728")
            .unwrap();

    let mut start = Instant::now();
    let credential = black_box(
        Credential::<PoseidonHasher, PoseidonSignature>::new(
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
        )
    );
    let mut duration = start.elapsed().as_millis();
    println!("//Credential creation: {}ms", duration);

    let mut circuit = None;
    let mut zkey = None;
    if cfg!(target_os = "android") {
        circuit = Some(
            std::fs::read("presentation_polygon.dat").unwrap()
        );
        zkey = Some(
            std::fs::read("presentation_polygon.zkey").unwrap()
        );

    }
    
    let revoc_reg =
    RevocationRegistry::<PoseidonHasher, PoseidonSignature>::new(Some(issuer_sk.clone()));

    start = Instant::now();
    let mut polygon_pres = PolygonPresentation::<PoseidonHasher, PoseidonSignature>::new(
        &credential,
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

    duration = start.elapsed().as_millis();
    println!("Polygon presentation initiation: {}ms", duration);


    start = Instant::now();
    let input_json = match polygon_pres.generate_input_json() {
        Ok(mut input_json) => {
            input_json.push('}');
            input_json
        }

        Err(err) => panic!("Input json creation failed."),
    };
    duration = start.elapsed().as_millis();
    println!("Polygon presentation input creation: {}ms", duration);

    start = Instant::now();
    polygon_pres.presentation.ark_circom_full_proof =
        match proof_polygon_presentation(&input_json, circuit.as_ref(), zkey.as_ref()) {
            Ok(proof) => Some(proof),
            Err(err) => panic!("Proving process failed"),
        };

    duration = start.elapsed().as_millis();
    println!("Polygon presentation generation: {}ms", duration);

    start = Instant::now();
    polygon_pres.remove_private_data();
    duration = start.elapsed().as_millis();
    println!("Polygon presentation removing private data: {}ms", duration);
}


//benchmarks the delegation presentation generation 
fn delegation_presentation(c: &mut Criterion){
    let issuer_sk =
        BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872")
            .unwrap();

    let credential = black_box(
        Credential::<PoseidonHasher, PoseidonSignature>::new(
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
        )
    );
    
    let revoc_reg =
    RevocationRegistry::<PoseidonHasher, PoseidonSignature>::new(Some(issuer_sk.clone()));


    let mut circuit = None;
    let mut zkey = None;
    if cfg!(target_os = "android") {
        circuit = Some(
            std::fs::read("presentation_delegation.dat").unwrap()
        );
        zkey = Some(
            std::fs::read("presentation_delegation.zkey").unwrap()
        );

    }

    c.bench_function("delegation presentation generation", 
        |b| b.iter(||{
            let mut del_pres = DelegationPresentation::<PoseidonHasher, PoseidonSignature>::new(
                &credential,
                BigInt::from_str("1678460108000").unwrap(),
                &revoc_reg,
                None,
                BigInt::from(1234),
                vec![5],
            )
            .unwrap();
    
            del_pres.generate(circuit.as_ref(), zkey.as_ref()).unwrap();
        })
    );
}

//benchmarks the delegation presentation step by step
fn delegation_presentation_fragmented(c: &mut Criterion){
    let issuer_sk =
        BigInt::from_str("2951225162891973271265230278305932248884420185229553697262927872")
            .unwrap();
    let holder_sk =
        BigInt::from_str("5728529159811704811523142037611732735149121473808289891486793728")
            .unwrap();

    let mut start = Instant::now();
    let credential = black_box(
        Credential::<PoseidonHasher, PoseidonSignature>::new(
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
        )
    );
    let mut duration = start.elapsed().as_millis();
    println!("//Credential creation: {}ms", duration);

    let mut circuit = None;
    let mut zkey = None;
    if cfg!(target_os = "android") {
        circuit = Some(
            std::fs::read("presentation_delegation.dat").unwrap()
        );
        zkey = Some(
            std::fs::read("presentation_delegation.zkey").unwrap()
        );

    }
    
    let revoc_reg =
    RevocationRegistry::<PoseidonHasher, PoseidonSignature>::new(Some(issuer_sk.clone()));

    start = Instant::now();
    let mut delegation_pres = DelegationPresentation::<PoseidonHasher, PoseidonSignature>::new(
        &credential,
        BigInt::from_str("1678460108000").unwrap(),
        &revoc_reg,
        None,
        BigInt::from(1234),
        vec![8,9,11]
    )
    .unwrap();

    duration = start.elapsed().as_millis();
    println!("Delegation presentation initiation: {}ms", duration);


    start = Instant::now();
    let input_json = match delegation_pres.generate_input_json() {
        Ok(mut input_json) => {
            input_json.push('}');
            input_json
        }

        Err(err) => panic!("Input json creation failed."),
    };
    duration = start.elapsed().as_millis();
    println!("Delegation presentation input creation: {}ms", duration);

    start = Instant::now();
    delegation_pres.attribute_presentation.presentation.ark_circom_full_proof =
        match proof_delegation_presentation(&input_json, circuit.as_ref(), zkey.as_ref()) {
            Ok(proof) => Some(proof),
            Err(err) => panic!("Proving process failed"),
        };

    duration = start.elapsed().as_millis();
    println!("Delegation presentation generation: {}ms", duration);

    start = Instant::now();
    delegation_pres.remove_private_data();
    duration = start.elapsed().as_millis();
    println!("Delegation presentation removing private data: {}ms", duration);
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_millis(1000));
    targets = attribute_presentation, attribute_presentation_fragmented,
     range_presentation, range_presentation_fragmented,
     polygon_presentation, polygon_presentation_fragmented,
     delegation_presentation, delegation_presentation_fragmented);
criterion_main!(benches);