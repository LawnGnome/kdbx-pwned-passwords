use std::{collections::BTreeSet, path::PathBuf};

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use kdbx_rs::{CompositeKey, database::Group, errors::FailedUnlock};
use rpassword::prompt_password;
use sha1_smol::Sha1;

use crate::{client::Client, digests::Digests, error::Error};

mod client;
mod digests;
mod error;

#[derive(Parser)]
#[command(about, version)]
struct Opt {
    /// Keyfile to unlock the password database with.
    #[arg(short, long)]
    keyfile: Option<PathBuf>,

    /// Keepass database to parse.
    #[arg()]
    database: PathBuf,
}

fn main() -> Result<(), Error> {
    let Opt { keyfile, database } = Opt::parse();

    // First, we load and unlock the database.
    let bar = ProgressBar::no_length()
        .with_style(ProgressStyle::with_template("Loading database {msg}...")?)
        .with_message(database.display().to_string());

    let locked = kdbx_rs::open(&database)?;

    let key = match keyfile {
        Some(path) => CompositeKey::new(
            None,
            Some(std::fs::read(&path).map_err(move |e| Error::Keyfile { e, path })?),
        ),
        None => {
            let password = prompt_password(format!("Password for {}: ", database.display()))
                .map_err(Error::PasswordRead)?;

            CompositeKey::from_password(&password)
        }
    };

    let unlocked = locked.unlock(&key).map_err(|FailedUnlock(_, e)| e)?;
    bar.finish();

    // Second, we iterate through the entries in the database to gather the passwords in SHA-1
    // digest form, ready to be fed to Pwned Passwords.
    let bar = ProgressBar::no_length()
        .with_style(ProgressStyle::with_template("Gathering entries: {pos}")?);
    let mut digests = Digests::default();
    parse_group(&mut digests, &bar, unlocked.root(), &[]);
    bar.finish();

    // Third, we actually query Pwned Passwords for the digests.
    let bar = ProgressBar::new(digests.len() as u64).with_style(ProgressStyle::with_template(
        "Checking against Pwned Passwords: {wide_bar} {pos}/{len} ETA: {eta}",
    )?);
    let client = Client::new()?;
    let mut matches = BTreeSet::new();
    for (prefix, inner) in digests.into_iter() {
        let hashes = client.get(&prefix)?;

        for (hash, names) in inner.into_iter() {
            if hashes.contains(hash.as_str()) {
                matches.extend(names.into_iter());
            }
        }

        bar.inc(1);
    }
    bar.finish();

    // Fourth, and finally, we report any matches.
    if matches.is_empty() {
        println!("No matching passwords found in the Pwned Passwords database!");
    } else {
        println!("These passwords were found in the Pwned Passwords database:");
        println!();
        for name in matches.into_iter() {
            println!("{name}");
        }
    }

    Ok(())
}

fn parse_group(digests: &mut Digests, bar: &ProgressBar, group: &Group, path: &[&str]) {
    let mut path = path.to_vec();
    path.push(group.name());

    for entry in group.entries() {
        if let Some(password) = entry.password() {
            let name = format!(
                "{} -> {}",
                path.join(" -> "),
                entry.title().unwrap_or("(untitled)"),
            );

            digests.upsert(Sha1::from(password).digest(), name);
        }

        bar.inc(1);
    }

    for group in group.groups() {
        parse_group(digests, bar, group, &path);
    }
}
