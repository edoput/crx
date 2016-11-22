extern crate byteorder;
extern crate clap;
extern crate openssl;

extern crate crx;

use std::io;
use std::io::prelude::*;
use std::io::Error;
use std::fs::{File};

use byteorder::{LittleEndian, WriteBytesExt};
use clap::{Arg, App};

use openssl::sign::{Signer, Verifier};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::error::ErrorStack;

type Buffer = Vec<u8>;

fn main () {
    let matches = App::new("crx creator")
                        .version("0.0.1")
                        .author("Edoardo Putti <edoardo.putti@gmail.com>")
                        .about("Package a chrome extension")
                        .arg(Arg::with_name("source")
                            .required(true))
                        .arg(Arg::with_name("pem")
                            .required(true))
                        .get_matches();


    let source : &str = matches.value_of("source").unwrap();

    let pem : &str = matches.value_of("pem").unwrap();

    // read input file and store them into buffers
    let mut source_buff = load_buffer(source).unwrap();

    let user_key = load_key_from_file(pem).unwrap();

    let mut public_key_content : Vec<u8> = user_key.public_key_to_der().unwrap();

    let mut signer = Signer::new(MessageDigest::sha1(), &user_key).unwrap();

    signer.update(&source_buff).unwrap();

    let mut signature : Vec<u8> = signer.finish().unwrap();

    let mut pub_key_len : Vec<u8> = vec![];
    pub_key_len.write_u32::<LittleEndian>(public_key_content.len() as u32).unwrap();

    let mut sig_len : Vec<u8> = vec![];
    sig_len.write_u32::<LittleEndian>(signature.len() as u32).unwrap();

    let mut package_file : File = File::create("package.crx").unwrap();
    let mut package_buffer : Vec<u8> = Vec::new();

    let mut magic_bytes : Vec<u8> = vec![0x43, 0x72, 0x32, 0x34];
    let mut version : Vec<u8> = vec![];

    version.write_u32::<LittleEndian>(2);

    package_buffer.append(&mut magic_bytes);
    package_buffer.append(&mut version);
    package_buffer.append(&mut pub_key_len);
    package_buffer.append(&mut sig_len);
    package_buffer.append(&mut public_key_content);
    package_buffer.append(&mut signature);
    package_buffer.append(&mut source_buff);
    
    package_file.write_all(&package_buffer).unwrap();
}

fn load_buffer(path : &str) -> Result<Buffer, std::io::Error> {
    // read input file and store them into buffers
    let file = File::open(path);

    let mut source_file = match file {
        Ok(x) => x,
        Err(_) => panic!(),
    };

    let mut file_buffer : Buffer = Vec::new();

    source_file.read_to_end(&mut file_buffer).unwrap();

    Ok(file_buffer)
    
}

fn load_key_from_file(path: &str) -> Result<PKey, openssl::error::ErrorStack> {
    // take a path and read the private key from the file
    //
    let pem_buff = load_buffer(path).unwrap();

    PKey::private_key_from_pem(&pem_buff)
}
