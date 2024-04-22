// mod custom_test;
#![feature(lazy_cell)]
mod manager;
fn main() {
    // Use cargo run -- --run-tests
    if std::env::args().any(|arg| arg == "--run-tests") {
        let _ =manager::test();
    } else {
        println!("Running normal program logic.");
    }
}
