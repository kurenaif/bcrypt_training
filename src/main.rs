// references
// https://www.schneier.com/wp-content/uploads/2015/12/constants-2.txt
// https://link.springer.com/chapter/10.1007/3-540-58108-1_24#:~:text=Blowfish%2C%20a%20new%20secret%2Dkey%20block%20cipher%2C%20is%20proposed.&text=The%20block%20size%20is%2064,very%20efficient%20on%20large%20microprocessors.
// https://en.wikipedia.org/wiki/Blowfish_(cipher)
// https://ja.wikipedia.org/wiki/Bcrypt
// https://github.com/libressl-portable/openbsd/blob/master/src/lib/libc/crypt/bcrypt.c
// https://github.com/golang/crypto/blob/5ea612d1eb830b38bc4e914e37f55311eb58adce/blowfish/block.go#L71

extern crate kurebcrypt;

mod consts;
use kurebcrypt::*;



fn main() {

    println!("{:?}", encode("hello".as_bytes()));
    println!("{:?}", encode("".as_bytes()));

    // // InitialState
    // let state = State {
    //     s0: consts::SBOX0,
    //     s1: consts::SBOX1,
    //     s2: consts::SBOX2,
    //     s3: consts::SBOX3,
    //     p: consts::PARRAY
    // };

    // let byte_array: [u8; 5] = [1, 2, 3, 4, 5];
    // let mut j: usize = 0;
    // let salt: [u8; 16] = [00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00];
    // bcrypt(10, &salt, "password".as_bytes());
    // // let res = 
    // // println!("{:#02x}, {}", bcrypt(&byte_array, &mut j).unwrap(), j);

    // println!("{:?}", consts::PARRAY);
}

