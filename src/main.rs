// references
// https://www.schneier.com/wp-content/uploads/2015/12/constants-2.txt
// https://link.springer.com/chapter/10.1007/3-540-58108-1_24#:~:text=Blowfish%2C%20a%20new%20secret%2Dkey%20block%20cipher%2C%20is%20proposed.&text=The%20block%20size%20is%2064,very%20efficient%20on%20large%20microprocessors.
// https://en.wikipedia.org/wiki/Blowfish_(cipher)
// https://ja.wikipedia.org/wiki/Bcrypt
// https://github.com/libressl-portable/openbsd/blob/master/src/lib/libc/crypt/bcrypt.c
// https://github.com/golang/crypto/blob/5ea612d1eb830b38bc4e914e37f55311eb58adce/blowfish/block.go#L71

extern crate kurebcrypt;

// mod consts;
// use kurebcrypt::*;
// use pprof;
// use std::fs::File;

use kurebcrypt::*;
use pprof;
use pprof::protos::Message;
use std::fs::File;
use std::io::Write;

fn main() {
    let guard = pprof::ProfilerGuard::new(100).unwrap();

    let salt: [u8; 16] =  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let password = "password".as_bytes();
    for _ in 0..1000  {
        bcrypt(5, &salt, password);
        // println!("{}", bcrypt(5, &salt, password));
    }

    // if let Ok(report) = guard.report().build() {
    //     let file = File::create("flamegraph.svg").unwrap();
    //     let mut options = pprof::flamegraph::Options::default();
    //     options.image_width = Some(2500);
    //     report.flamegraph_with_options(file, &mut options).unwrap();
    // };

    // match guard.report().build() {
    //     Ok(report) => {
    //         let mut file = File::create("profile.pb").unwrap();
    //         let profile = report.pprof().unwrap();

    //         let mut content = Vec::new();
    //         profile.encode(&mut content).unwrap();
    //         file.write_all(&content).unwrap();

    //         // println!("report: {}", &report);
    //     }
    //     Err(_) => {}
    // };
}
