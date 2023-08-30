use std::io;
mod break_xor;
mod mt19937;
mod set1;
mod set2;
mod set3;
mod util;

fn main() -> io::Result<()> {
    set3::challenge24();
    Ok(())
}
