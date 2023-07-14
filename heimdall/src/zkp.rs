///default circuit location depending on the target
#[cfg(target_os = "android")]
const CIRCUITS_PATH: &str = "/data/data/com.cguthmann.vidar/circuits";
#[cfg(not(target_os = "android"))]
const CIRCUITS_PATH: &str = "lib";

///Provides witness generation for the attribute presentation circuit.
pub mod attribute {

    use super::*;
    use std::{error::Error};

    use ark_circom_service::{create_proof_from_witness, ArkCircomFullProof, Bn254};
    use witness_utils::{create::WITNESS_SIZE_GUESS, read::read_wtns};

    //Link to external witness generation provided by witnesscalc
    #[link(name = "presentation_attribute", kind = "static")]
    extern "C" {
        fn witnesscalc_presentation_attribute(
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

    ///Generates a witness for the attribute presentation circuit.
    /// 
    /// # Arguments
    /// * 'circuit' -  The circuit definition provided by circom in the .dat file.
    ///                 If not provided, the function attempts to read it from
    ///                  the default directory for the system.
    /// 
    /// * 'zkey' - The proving key for the circuit.
    ///            If not provided, the function attempts to read it from
    ///               the default directory for the system.
    /// 
    pub fn proof_attribute_presentation(
        json: &str,circuit: Option<&Vec<u8>>, zkey: Option<&Vec<u8>>
    ) -> Result<ArkCircomFullProof<Bn254>, Box<dyn Error>> {
        let circuit = match circuit {
            Some(res) => res.clone(),
            None => match get_ressource("presentation_attribute.dat") {
                Ok(res) => res,
                Err(er) => Err(er)?,
            },
        }; 

        let mut wtns: Vec<u8> = Vec::with_capacity(WITNESS_SIZE_GUESS as usize);
        let mut witness_size: u64 = WITNESS_SIZE_GUESS;

        let mut error: Vec<u8> = Vec::with_capacity(200);

        let mut result;
        unsafe {
            result = witnesscalc_presentation_attribute(
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
                result = witnesscalc_presentation_attribute(
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

        let zkey = match zkey {
            Some(res) => res.clone(),
            None => match get_ressource("presentation_attribute.zkey") {
                Ok(res) => res,
                Err(er) => Err(er)?,
            },
        }; 

        let proof = create_proof_from_witness(&witness, &zkey)?;

        Ok(proof)
    }
}

///Provides witness generation for the range presentation circuit.
pub mod range {
    use super::*;

    use std::{error::Error};

    use ark_circom_service::{create_proof_from_witness, ArkCircomFullProof, Bn254};
    use witness_utils::{create::WITNESS_SIZE_GUESS, read::read_wtns};

    //Link to external witness generation provided by witnesscalc
    #[link(name = "presentation_range", kind = "static")]
    extern "C" {
        fn witnesscalc_presentation_range(
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

    ///Generates a witness for the range presentation circuit.
    /// 
    /// # Arguments
    /// * 'circuit' -  The circuit definition provided by circom in the .dat file.
    ///                 If not provided, the function attempts to read it from
    ///                  the default directory for the system.
    /// 
    /// * 'zkey' - The proving key for the circuit.
    ///            If not provided, the function attempts to read it from
    ///               the default directory for the system.
    /// 
    pub fn proof_range_presentation(
        json: &str,circuit: Option<&Vec<u8>>, zkey: Option<&Vec<u8>>
    ) -> Result<ArkCircomFullProof<Bn254>, Box<dyn Error>> {
        let circuit = match circuit {
            Some(res) => res.clone(),
            None => match get_ressource("presentation_range.dat")  {
                Ok(res) => res,
                Err(er) => Err(er)?,
            },
        }; 

        let mut wtns: Vec<u8> = Vec::with_capacity(WITNESS_SIZE_GUESS as usize);
        let mut witness_size: u64 = WITNESS_SIZE_GUESS;

        let mut error: Vec<u8> = Vec::with_capacity(200);

        let mut result;
        unsafe {
            result = witnesscalc_presentation_range(
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
                result = witnesscalc_presentation_range(
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

        
        let zkey = match zkey {
            Some(res) => res.clone(),
            None => match get_ressource("presentation_range.zkey")  {
                Ok(res) => res,
                Err(er) => Err(er)?,
            },
        }; 

        let proof = create_proof_from_witness(&witness, &zkey)?;

        Ok(proof)
    }

}

///Provides witness generation for the polygon presentation circuit.
pub mod polygon {
    use super::*;
    use std::{error::Error};

    use ark_circom_service::{create_proof_from_witness, ArkCircomFullProof, Bn254};
    use witness_utils::{create::WITNESS_SIZE_GUESS, read::read_wtns};
    
    //Link to external witness generation provided by witnesscalc
    #[link(name = "presentation_polygon", kind = "static")]
    extern "C" {
        fn witnesscalc_presentation_polygon(
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

    ///Generates a witness for the polygon presentation circuit.
    /// 
    /// # Arguments
    /// * 'circuit' -  The circuit definition provided by circom in the .dat file.
    ///                 If not provided, the function attempts to read it from
    ///                  the default directory for the system.
    /// 
    /// * 'zkey' - The proving key for the circuit.
    ///            If not provided, the function attempts to read it from
    ///               the default directory for the system.
    /// 
    pub fn proof_polygon_presentation(
        json: &str,circuit: Option<&Vec<u8>>, zkey: Option<&Vec<u8>>
    ) -> Result<ArkCircomFullProof<Bn254>, Box<dyn Error>> {
        let circuit = match circuit {
            Some(res) => res.clone(),
            None => match get_ressource("presentation_polygon.dat") {
                Ok(res) => res,
                Err(er) => Err(er)?,
            },
        }; 

        let mut wtns: Vec<u8> = Vec::with_capacity(WITNESS_SIZE_GUESS as usize);
        let mut witness_size: u64 = WITNESS_SIZE_GUESS;

        let mut error: Vec<u8> = Vec::with_capacity(500);

        let mut result;
        unsafe {
            result = witnesscalc_presentation_polygon(
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
                result = witnesscalc_presentation_polygon(
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

        
        let zkey = match zkey {
            Some(res) => res.clone(),
            None => match get_ressource("presentation_polygon.zkey") {
                Ok(res) => res,
                Err(er) => Err(er)?,
            },
        }; 

        let proof = create_proof_from_witness(&witness, &zkey)?;

        Ok(proof)
    }

}

///Provides witness generation for the delegation presentation circuit.
pub mod delegation {
    use super::*;

    use std::{error::Error};

    use ark_circom_service::{create_proof_from_witness, ArkCircomFullProof, Bn254};
    use witness_utils::{create::WITNESS_SIZE_GUESS, read::read_wtns};
    
    //Link to external witness generation provided by witnesscalc
    #[link(name = "presentation_delegation", kind = "static")]
    extern "C" {
        fn witnesscalc_presentation_delegation(
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

    ///Generates a witness for the delegation presentation circuit.
    /// 
    /// # Arguments
    /// * 'circuit' -  The circuit definition provided by circom in the .dat file.
    ///                 If not provided, the function attempts to read it from
    ///                  the default directory for the system.
    /// 
    /// * 'zkey' - The proving key for the circuit.
    ///            If not provided, the function attempts to read it from
    ///               the default directory for the system.
    /// 
    pub fn proof_delegation_presentation(
        json: &str,circuit: Option<&Vec<u8>>, zkey: Option<&Vec<u8>>
    ) -> Result<ArkCircomFullProof<Bn254>, Box<dyn Error>> {
        let circuit = match circuit {
            Some(res) => res.clone(),
            None => match get_ressource("presentation_delegation.dat") {
                Ok(res) => res,
                Err(er) => Err(er)?,
            },
        }; 
        let mut wtns: Vec<u8> = Vec::with_capacity(WITNESS_SIZE_GUESS as usize);
        let mut witness_size: u64 = WITNESS_SIZE_GUESS;

        let mut error: Vec<u8> = Vec::with_capacity(500);

        let mut result;
        unsafe {
            result = witnesscalc_presentation_delegation(
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
                result = witnesscalc_presentation_delegation(
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

        
        let zkey = match zkey {
            Some(res) => res.clone(),
            None => match get_ressource("presentation_delegation.zkey") {
                Ok(res) => res,
                Err(er) => Err(er)?,
            },
        }; 

        let proof = create_proof_from_witness(&witness, &zkey)?;

        Ok(proof)
    }

}

///Attempts to load the specified ressoruce at the default location for the system.
fn get_ressource(name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match std::fs::read(format!("{}/{}", CIRCUITS_PATH, name)) {
        Ok(res) => Ok(res),
        Err(err) => Err(err)?,
    }
}

