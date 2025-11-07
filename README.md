# kdbx-pwned-passwords

This command line tool parses a Keepass format (.kdbx) database and checks all
the passwords within it against [Troy Hunt's Pwned Passwords][pwned] tool,
specifically using its [k-anonymity API][api] so as not to expose any full
password hashes.

## A note on security

I've intentionally written the code to be reasonably straightforward, since this
is (briefly) dealing with unencrypted passwords before hashing them (and
truncating the hashes) to send off to the Pwned Passwords API. I suggest anyone
who wants to use this does at least a cursory audit of the code to ensure
they're happy that their passwords aren't going to be sent off to the æther.

(It's just over 200 lines of actual code, so it really shouldn't take very long
to check.)

## Building

This is a bog standard Rust program, so a good old:

```bash
cargo build --release
```

will get you a nice `target/release/kdbx-pwned-passwords` binary to run.

## Usage

For a password-protected Keepass database, this is all you need to run:

```bash
target/release/kdbx-pwned-passwords ~/my-database.kdbx
```

You'll be prompted for your password to unlock the database, and then the
passwords (well, technically, five character prefixes of their SHA-1 hashes)
will be queried against Pwned Passwords.

If you use a keyfile, the tool takes a `-k` option with a path to the keyfile. I
haven't actually tested this, but the underlying [`kdbx-rs` crate][crate] at
least suggests that it should work.

## Maintenance status

This is basically a tiny one-off tool that I wrote for my own purposes. I'm
publishing it in case someone else finds it useful, but I probably won't really
support this in any meaningful way, so please don't be offended if I straight up
ignore issues and PRs for the most part.

Feel free to fork and develop it, though!

[api]: https://haveibeenpwned.com/API/v3?ref=troyhunt.com#PwnedPasswords
[crate]: https://crates.io/crates/kdbx-rs
[pwned]: https://haveibeenpwned.com/Passwords
