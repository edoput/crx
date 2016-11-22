const magic_number : [u8; 4] = [ 43, 72, 32, 34];
// The length of the RSA public key in bytes
//let mut public_key_lenght : u32 = 0;
//let mut signature_lenght : u32 = 0; 
// The contents of the author's RSA public key, formatted as an X509 SubjectPublicKeyInfo block
//public_key = [];

// The signature of the ZIP content using the author's private key. The signature is created using
// the RSA algorithm with the SHA-1 hash function. 
//let mut signature : u32 = 0;
//
//OID for rsaEncryption 1.2.840.113549.1.1
//in byte 06 08 2A 86 48 86 F7 0D 01 01

//OID for sha1withRSAEncryption 1.2.840.113549.1.1.5
//in byte 06 08 2A 86 48 86 F7 0D 01 01 05

//OID for id_sha1 1.3.14.3.2.26
//in byte 06 05 2B 0E 03 02 1A
extern crate openssl;

use openssl::pkey::{PKey};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
