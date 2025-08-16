use biip::Biip;
use dotenv::dotenv;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Seek, SeekFrom, Write};

const HELP: &str = r#"Usage:
  cat file | biip
  biip [FILE ...]   # read and redact one or more files
  biip              # interactive paste; press Ctrl-D to finish
"#;

fn main() -> io::Result<()> {
    dotenv().ok();

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let biip = Biip::new();
    let args: Vec<String> = env::args().skip(1).collect();

    // Help
    if args.iter().any(|a| a == "-h" || a == "--help") {
        write!(stdout, "{}", HELP)?;
        return Ok(());
    }

    // If file args are provided, read each in order.
    if !args.is_empty() {
        run_with_args(&args, &biip, &mut stdout, &mut stderr)?;
        return Ok(());
    }

    // If input is piped, read from stdin.
    if !stdin.is_terminal() {
        run_with_piped_stdin(&stdin, &biip, &mut stdout)?;
        return Ok(());
    }

    // Interactive paste mode: stdin is a terminal and no args provided.
    eprintln!("Paste content. Press Ctrl-D (Unix/macOS) or Ctrl-Z then Enter (Windows) to finish:");
    run_interactive_paste(&stdin, &biip, &mut stdout, &mut stderr)
}

fn process_lines<R: BufRead>(reader: R, biip: &Biip, out: &mut dyn Write) -> io::Result<()> {
    for line_res in reader.lines() {
        writeln!(out, "{}", biip.process(&line_res?))?;
    }
    Ok(())
}

fn run_with_args(
    paths: &[String],
    biip: &Biip,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<()> {
    for path in paths {
        process_file_path(path, biip, out, err)?;
    }
    Ok(())
}

fn process_file_path(
    path: &str,
    biip: &Biip,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<()> {
    let mut file = File::open(path)?;
    // Detect binary early; skip with a warning like less.
    if is_probably_binary(&mut file)? {
        writeln!(err, "warning: binary file skipped: {}", path)?;
        return Ok(());
    }
    // Reset cursor and process with header
    file.seek(SeekFrom::Start(0))?;
    writeln!(out, "─── {} ───", path)?;
    let reader = BufReader::new(file);
    process_lines(reader, biip, out)
}

fn run_with_piped_stdin(stdin: &io::Stdin, biip: &Biip, out: &mut dyn Write) -> io::Result<()> {
    process_lines(stdin.lock(), biip, out)
}

const SEPARATOR: &str = "──────────";

fn run_interactive_paste(stdin: &io::Stdin, biip: &Biip, out: &mut dyn Write, err: &mut dyn Write) -> io::Result<()> {
    writeln!(err, "{}", SEPARATOR)?;
    let mut buf = String::new();
    stdin.lock().read_to_string(&mut buf)?;
    writeln!(err, "{}", SEPARATOR)?;
    writeln!(out, "{}", biip.process(&buf))
}

fn is_probably_binary(file: &mut File) -> io::Result<bool> {
    let mut buf = [0u8; 8192];
    let n = file.read(&mut buf)?;
    let slice = &buf[..n];
    if slice.is_empty() {
        return Ok(false);
    }
    // If NUL byte present, very likely binary (matches less/grep heuristics)
    if slice.iter().any(|&b| b == 0) {
        return Ok(true);
    }
    // If not valid UTF-8, treat as binary to avoid mojibake
    Ok(std::str::from_utf8(slice).is_err())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Cursor;
    use std::path::PathBuf;

    fn tmp_file_with(content: &[u8], name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("biip_test_{}_{}", name, std::process::id()));
        fs::write(&p, content).expect("write temp file");
        p
    }

    #[test]
    fn test_is_probably_binary_detects_binary() {
        let text_p = tmp_file_with(b"hello world", "text");
        let bin_p = tmp_file_with(b"\x00\xFF\x00BIN", "bin");

        let mut tf = File::open(&text_p).unwrap();
        let mut bf = File::open(&bin_p).unwrap();
        assert!(!is_probably_binary(&mut tf).unwrap());
        assert!(is_probably_binary(&mut bf).unwrap());

        let _ = fs::remove_file(text_p);
        let _ = fs::remove_file(bin_p);
    }

    #[test]
    fn test_process_lines_redacts_email() {
        let biip = Biip::new();
        let input = b"email: foo@bar.com\n";
        let reader = Cursor::new(&input[..]);
        let mut out = Vec::new();
        process_lines(reader, &biip, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("•••@•••"));
    }

    #[test]
    fn test_run_with_args_skips_binary_and_prints_header_for_text() {
        let text_p = tmp_file_with(b"hello user foo@bar.com", "text2");
        let bin_p = tmp_file_with(b"\x00\x00PNG", "bin2");
        let biip = Biip::new();
        let mut out = Vec::new();
        let mut err = Vec::new();
        run_with_args(
            &vec![
                text_p.to_string_lossy().into(),
                bin_p.to_string_lossy().into(),
            ],
            &biip,
            &mut out,
            &mut err,
        )
        .unwrap();
        let so = String::from_utf8(out).unwrap();
        let se = String::from_utf8(err).unwrap();
        assert!(so.contains("─── ")); // header present for text file
        assert!(se.contains("warning: binary file skipped:"));
        let _ = fs::remove_file(text_p);
        let _ = fs::remove_file(bin_p);
    }
}
