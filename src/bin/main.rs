use biip::Biip;
use std::io::{self, BufRead, Write};

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let biip = Biip::new();

    for line_res in stdin.lock().lines() {
        writeln!(stdout, "{}", biip.process(&line_res?))?;
    }
    Ok(())
}
