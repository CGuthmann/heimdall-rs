use std::collections::HashMap;
use num_bigint::BigInt;

///A struct representing a R1CS witness.
pub struct Witness{
    pub version: u32,
    pub n_sections: u32,
    pub sections: HashMap<u32,Vec<(usize,usize)>>,
    pub field_element_size: usize,
    pub field_prime: BigInt,
    pub num_constraints: u32,
    pub assignment: Vec<[u8;32]>
}


impl Witness {

    ///Default constructor initializing an empty witness.
    pub fn new()
    -> Witness
    {
        Witness { version: 0, n_sections: 0, sections: HashMap::new(),
            field_element_size: 0, field_prime: BigInt::from(0), num_constraints: 0, assignment: Vec::new() }
    }
}

///Provides functionality around reading a witness.
pub mod read{
    use super::*;
    use std::{fs::read};
    use byteorder::{ByteOrder,LittleEndian};
    use num_bigint::{Sign};

    //reads the first part of the binary, describing the structure
    fn read_wtns_descriptor(full_wtns: &Vec<u8>, witness: &mut Witness)
    {

        let mut pos: usize = 0;
        let _file_type = &full_wtns[pos..pos+4];
        pos +=4;

        witness.version = LittleEndian::read_u32(&full_wtns[pos..pos+4]);
        pos +=4;

        witness.n_sections = LittleEndian::read_u32(&full_wtns[pos..pos+4]);
        pos +=4;

        for _i in 0..witness.n_sections {
            let ht = LittleEndian::read_u32(&full_wtns[pos..pos+4]);
            pos +=4;
            let hl = LittleEndian::read_u64(&full_wtns[pos..pos+8]) as usize;
            pos +=8;
            witness.sections.entry(ht).or_insert_with(Vec::new).push((pos,hl));
            pos += hl;
        }
        
    
    }

    //reads the witness header, returns (FieldDataSize, FieldPrime,numConstraintss)
    fn read_wtns_header(full_wtns: &Vec<u8>, witness: &mut Witness)
    {
        
        let mut pos = witness.sections.get(&1).unwrap()[0].0;

        witness.field_element_size = LittleEndian::read_u32(&full_wtns[pos..pos+4]) as usize;
        pos +=4;
        witness.field_prime = BigInt::from_bytes_le(Sign::Plus,&full_wtns[pos..pos+witness.field_element_size]);
        pos +=witness.field_element_size;

        witness.num_constraints = LittleEndian::read_u32(&full_wtns[pos..pos+4]);
        
    }

    //transcodes binary witness to Witness struct
    pub fn read_wtns(full_wtns: &Vec<u8>)
    -> Witness{
        
        let mut witness = Witness::new();

        read_wtns_descriptor(&full_wtns, &mut witness);

        read_wtns_header(&full_wtns, &mut witness);
        let mut pos = witness.sections.get(&2).unwrap()[0].0;

        for _i in 0 .. witness.num_constraints {
            witness.assignment.push({
                full_wtns[pos..pos+witness.field_element_size].try_into().unwrap()
            }
            );
            pos += witness.field_element_size;
        }
        witness
    }

    //loads binary witness from file
    pub fn read_wtns_from_file(file_name: &str)
    -> Vec<[u8;32]>{
        let full_wtns: Vec<u8> = read(file_name).unwrap();
        
        let witness = read_wtns(&full_wtns);
        witness.assignment
    }
}



///Provides functionality around creating a witness.
/// Because witnesscalc generates C++ libraries,
///  implementing a generic creation function is not possible
pub mod create{
    /// Suggestion for a generic witness size
    pub const WITNESS_SIZE_GUESS: u64 = 4*1024*1024;
}
