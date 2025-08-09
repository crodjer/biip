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
- fe80::aaa:8888:ffff:9999
- 192.168.42.42
```

`biip` can redact some sensitive information from it:
```
$ cat /tmp/info.txt | biip
Hi, I am "user"
Current Directory: ~/foo/bar/baz
My Key: ••••••••
My Email: •••@•••
My IPs:
- IPv6<••:••:••:••:••:••:••:••>
- IPv4<••.••.••.••>
```

## What does it scrub?
Biip can scrub:

 1. Unix (Linux/Mac) username
    It removes any mention of a user's Unix username from the supplied text,
    replacing it with `user`.
 2. Home directory
    It replaces paths referring to the home directory with `~`.
 3. Emails
    It replaces any email addresses in the text with a pattern: `•••@•••`.
 4. IP Addresses
    It replaces IPv4 and IPv6 addresses with: `IPv4<••.••.••.••>` and
    `IPv6<••:••:••:••:••:••:••:••>` respectively.
 5. Keys / Passwords from environment.
    It replaces the contents for any potentially sensitive environment variables
    with: `••••••••`. It looks for any environment variables that may have
    these keywords in the name:
    - username
    - password
    - email
    - secret
    - token
    - key

## How is it useful?

### LLM Context
When sharing code with LLMs for AI assistance, running it through `biip` would
be beneficial to strip out any sensitive info. Like this:

```bash
fd --size -8K | xargs tail -n +1 | biip | pbcopy
```

This will copy your entire codebase to clipboard, excluding large files and
redact sensitive information. On Linux, use `xclip` (for X11) and `wl-copy` (for
wayland) instead of `pbcopy`.

### Copying .env
`biip` considers `.env`, so it'll remember to not share any sensitive keys even
if .env's content was in the stdin.
So, `biip` would redact (keys, secrets etc) from the output:
```sh
$ cat .env | biip
S3_KEY="••••••••"
S3_SECRET="••••••••"
ANTHROPIC_API_KEY="••••••••"
OPENAI_API_KEY="••••••••"
```
