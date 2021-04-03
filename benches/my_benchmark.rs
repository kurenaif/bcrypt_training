use kurebcrypt::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn kurebcrypt() {
    let salt: [u8; 16] =  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let password = "password".as_bytes();
    bcrypt(5, &salt, password);
    // println!("{}", bcrypt(5, &salt, password));
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("kurebcrypt", |b| b.iter(|| kurebcrypt()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
