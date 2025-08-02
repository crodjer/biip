# biip
`biip` (Beep + PII) is a tool and library to scrub PII from text.

## What is `biip`?
`biip` is a library / executable to scrub various PII data from text:

 1. Unix (Linux/Mac) username
 2. Home directory
 3. Emails
 4. IP Addresses
 5. Keys / Passwords from .env

## How does it work?

- Simply pipe text to `biip` to have it scrub away the PII.
- Ask `biip -c` to read the clipboard, scrub the data and then write it again to
  the clipboard.
