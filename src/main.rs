use std::io;
mod break_xor;
mod util;
mod set1;
mod set2;
mod set3;

fn main() -> io::Result<()> {
    set3::challenge18();

    Ok(())
}
