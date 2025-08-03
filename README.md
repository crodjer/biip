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

`biip` can redact all the sensitive information:
```
$ cat /tmp/info.txt | biip
Hi, I am "user"
Current Directory: ~/foo/bar/baz
My Key: **secret**
My Email: ****@****
My IPs:
- ***:****:***
- ***.***.***.***
```

## What does it scrub?
Biip can scrub:

 1. Unix (Linux/Mac) username
    It removes any mention of a user's Unix username from the supplied text,
    replacing it with `user`.
 2. Home directory
    It replaces paths referring to the home directory with `~`.
 3. Emails
    It replaces any email addresses in the text with a pattern: `***@***`.
 4. IP Addresses
    It replaces IPv4 and IPv6 addresses with: `***.***.***.***` and
    `***:****:***` respectively.
 5. Keys / Passwords from environment.
    It replaces the contents for any potentially sensitive environment variables
    with: `**secret**`. It looks for any environment variables that may have
    these keywords in the name:
    - username
    - password
    - email
    - secret
    - token
    - key

## How is it useful?
It is useful when you are sharing a large amount of text, but cannot vet it
thoroughly enough to look for sensitive information. For instance, when sharing
text / logs etc with LLMs or sharing the whole code base with LLM for analysis,
it may make sense to run it through `biip`. Like this:

```bash
git ls-files |
 grep -vE 'LICENSE|.gitignore|.lock|.png|.jpg|.svg' |
 xargs tail -n +1 | biip | pbcopy
```
This will copy your entire codebase to clipboard, excluding certain files, and
redact sensitive information. On Linux, use `xclip` (For X11) and `wl-copy` (For
Wayland) instead of `pbcopy`.
