# biip
`biip` (Beep + PII) is a tool (and a library) to scrub PII from text.

## Install
For Linux and MacOS, you can install `biip` using the pre-built binaries:
```
curl -sfSL https://raw.githubusercontent.com/crodjer/biip/main/download.sh | bash
```

If you have Rust installed, you can install `biip` using Cargo:
```
cargo install biip
```

## How does it work?
Pipe any text to `biip` to have it scrub away sensitive information.

For example, if you have a file with content:

```
Hi, I am "awesome-user"
Current Directory: /Users/awesome-user/foo/bar/baz
My Secret Key: mAM3zwogXpV6Czj6J
My Email: foo@bar.com
My IPs:
- 2001:db8:85a3::8a2e:370:7334
- 8.8.8.8
Connect via ftp://user:pass@example.com
Auth token is eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sZtZQ...
My MAC address is 00-1A-2B-3C-4D-5E.
```

`biip` can redact some sensitive information from it:

```
$ biip /tmp/info.txt
─── /tmp/info.txt ───
Hi, I am "user"
Current Directory: ~/foo/bar/baz
My Secret Key: ••••⚿•
My Email: •••@•••
My IPs:
- ••:••:••:••:••:••:••:••
- ••.••.••.••
Connect via ftp://••••:••••@example.com
Auth token is ••••🌐•
My MAC address is ••:••:••:••:••:••.
```

Other ways to run:

- From stdin: `cat /tmp/info.txt | biip`
- Interactive paste: run `biip`, paste content, then press `Ctrl-D`.

## What does it scrub?
Biip can scrub:

 1. **Unix (Linux/Mac) username**: It removes any mention of a user's Unix username.
 2. **Home directory**: It replaces paths referring to the home directory with `~`.
 3. **URL Credentials**: Scrubs usernames and passwords from URLs (e.g., `https://user:pass@...`).
 4. **Email Addresses**: Replaces emails with `•••@•••`.
 5. **IP Addresses**: Redacts public IPv4 and IPv6 addresses (skips local/private addresses).
 6. **MAC Addresses**: Replaces MAC addresses.
 7. **Phone Numbers**: Redacts common phone number formats.
 8. **Credit Card Numbers**: Redacts common credit card number patterns.
 9. **JSON Web Tokens (JWTs)**: Finds and redacts JWTs.
 10. **API Keys**: Redacts common API key formats from providers like AWS, OpenAI, etc.
 11. **UUIDs**: Replaces UUIDs with a redacted pattern.
 12. **Keys / Passwords from environment**: It replaces the values for any potentially sensitive environment variables with: `••••⚿•`.
 13. **Custom patterns (BIIP_*)**: Any environment variable whose name starts with `BIIP` (e.g., `BIIP_PERSONAL_PATTERNS`, `BIIP_SENSITIVE`) has its value redacted with `••••⚙•`.

## How is it useful?

### LLM Context
When sharing code with LLMs for AI assistance, running it through `biip` would
be beneficial to strip out any sensitive info. Like this:

```bash
fd -t f | xargs biip | pbcopy
```

This will copy your entire codebase to clipboard, excluding large files and
redact sensitive information. On Linux, use `xclip` (for X11) and `wl-copy` (for
wayland) instead of `pbcopy`.

To exclude files (like LICENSE, Cargo.lock, .svg, etc.) which could unnecessarily
bloat context, use `.fdignore`.

> Note: When reading files via arguments (including `xargs biip`), `biip`
> automatically skips binary files. You usually don't need to exclude image
> formats explicitly.

### Copying .env
`biip` considers `.env`, so it'll remember to not share any sensitive keys even
if .env's content was in the stdin.
So, `biip` would redact (keys, secrets etc) from the output:

```sh
$ cat .env | biip
S3_KEY="••••⚿•"
S3_SECRET="••••⚿•"
OPENAI_API_KEY="••••☁️•"
BIIP_PERSONAL_PATTERNS="••••⚙•"
BIIP_SENSITIVE="••••⚙•"
```
