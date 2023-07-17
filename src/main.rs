use std::io;
mod break_xor;
mod util;
mod set1;
mod set2;

fn main() -> io::Result<()> {
    set2::challenge14();

    Ok(())
}
