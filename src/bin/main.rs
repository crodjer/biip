use biip::Biip;
use dotenv::dotenv;
use std::{env, fs};
use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Seek, SeekFrom, Write};
use std::process::Command;

const HELP: &str = r#"Usage:
  cat file | biip
  biip [FILE ...]   # read and redact one or more files
  biip              # open default editor for interactive input.
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

    // Interactive editor mode.
    let editor = find_editor();
    run_with_editor(&editor, &biip, &mut stdout, &mut stderr)
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
    let show_header = paths.len() > 1;
    for path in paths {
        process_file_path(path, show_header, biip, out, err)?;
    }
    Ok(())
}

fn process_file_path(
    path: &str,
    show_header: bool,
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
    if show_header {
        writeln!(out, "─── {} ───", path)?;
    }
    let reader = BufReader::new(file);
    process_lines(reader, biip, out)
}

fn run_with_piped_stdin(stdin: &io::Stdin, biip: &Biip, out: &mut dyn Write) -> io::Result<()> {
    process_lines(stdin.lock(), biip, out)
}

fn find_editor() -> String {
    env::var("EDITOR").unwrap_or_else(|_| "vi".to_string())
}

fn run_with_editor(editor: &str, biip: &Biip, out: &mut dyn Write, err: &mut dyn Write) -> io::Result<()> {

    // Create a temporary file for the user to edit.
    let temp_path = env::temp_dir().join(format!("biip-interactive-{}.txt", std::process::id()));
    File::create(&temp_path)?;

    // Open /dev/tty for the editor so it can interact with the terminal
    // even when stdout is piped (e.g., biip | pbcopy).
    let tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok();

    // Launch the editor process and wait for it to exit.
    let mut cmd = Command::new(&editor);
    cmd.arg(&temp_path);

    // If we successfully opened /dev/tty, use it for stdin/stdout/stderr
    // so the editor can interact with the terminal even when piped.
    if let Some(tty_file) = tty {
        cmd.stdin(tty_file.try_clone()?);
        cmd.stdout(tty_file.try_clone()?);
        cmd.stderr(tty_file);
    }

    let status = cmd.status();

    // Ensure editor process is cleaned up even on early return.
    // This is a simple RAII guard for file deletion.
    let _cleanup = TempFileGuard { path: temp_path.clone() };

    match status {
        Ok(status) if status.success() => {
            let file = File::open(&temp_path)?;
            let reader = BufReader::new(file);
            process_lines(reader, biip, out)
        }
        Ok(_) => {
            writeln!(err, "Editor closed without saving. Aborting.")?;
            Ok(())
        }
        Err(e) => {
            writeln!(
                err,
                "Failed to open editor '{}'. Is it in your $PATH?",
                editor
            )?;
            Err(e)
        }
    }
}

// RAII guard to ensure the temporary file is always deleted.
struct TempFileGuard {
    path: std::path::PathBuf,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
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
    fn test_run_with_args_single_file_omits_header() {
        let text_p = tmp_file_with(b"hello user foo@bar.com", "single_text");
        let biip = Biip::new();
        let mut out = Vec::new();
        let mut err = Vec::new();
        run_with_args(
            &vec![text_p.to_string_lossy().into()],
            &biip,
            &mut out,
            &mut err,
        )
        .unwrap();
        let so = String::from_utf8(out).unwrap();
        assert!(!so.contains("─── "));
        let _ = fs::remove_file(text_p);
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

    #[test]
    fn test_run_with_editor_success() {
        // Create a fake editor script that writes content to the temp file
        let script_path = tmp_file_with(
            b"#!/bin/sh\necho 'test@example.com' > \"$1\"",
            "editor_success",
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms).unwrap();
        }

        let biip = Biip::new();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = run_with_editor(
            &script_path.to_string_lossy(),
            &biip,
            &mut out,
            &mut err,
        );

        assert!(result.is_ok());
        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("•••@•••")); // Email should be redacted
        let _ = fs::remove_file(script_path);
    }

    #[test]
    fn test_run_with_editor_non_success_exit() {
        // Create a fake editor script that exits with non-zero status
        let script_path = tmp_file_with(b"#!/bin/sh\nexit 1", "editor_fail");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms).unwrap();
        }

        let biip = Biip::new();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = run_with_editor(
            &script_path.to_string_lossy(),
            &biip,
            &mut out,
            &mut err,
        );

        assert!(result.is_ok()); // Should not error, just abort
        let output = String::from_utf8(out).unwrap();
        assert!(output.is_empty()); // No output when editor fails
        let err_output = String::from_utf8(err).unwrap();
        assert!(err_output.contains("Editor closed without saving"));
        let _ = fs::remove_file(script_path);
    }

    #[test]
    fn test_run_with_editor_nonexistent() {
        let biip = Biip::new();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = run_with_editor(
            "/nonexistent/editor/path/xyz123",
            &biip,
            &mut out,
            &mut err,
        );

        assert!(result.is_err()); // Should error when editor doesn't exist
        let err_output = String::from_utf8(err).unwrap();
        assert!(err_output.contains("Failed to open editor"));
    }
}
