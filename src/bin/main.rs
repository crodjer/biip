use biip::Biip;
use dotenv::dotenv;
use std::io::{self, BufRead, IsTerminal, Write};

fn main() -> io::Result<()> {
    dotenv().ok();

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let biip = Biip::new();

    if stdin.is_terminal() {
        writeln!(stdout, "Error: `biip` expects input via stdin.")?;
        writeln!(
            stdout,
            "Usage:\n\tcat your-potentiall-sensitive-content | biip"
        )?;
        writeln!(stdout, "Or:\n\tbiip < your-potentiall-sensitive-file")?;
    } else {
        for line_res in stdin.lock().lines() {
            writeln!(stdout, "{}", biip.process(&line_res?))?;
        }
    }
    Ok(())
}
