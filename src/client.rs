use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader},
    time::Duration,
};

use itertools::Itertools;
use reqwest::{StatusCode, blocking::ClientBuilder};

use crate::error::Error;

pub struct Client {
    client: reqwest::blocking::Client,
}

impl Client {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            client: ClientBuilder::new()
                .user_agent(concat!(
                    env!("CARGO_PKG_NAME"),
                    "/",
                    env!("CARGO_PKG_VERSION")
                ))
                .build()
                .map_err(Error::ClientBuild)?,
        })
    }

    pub fn get(&self, prefix: &str) -> Result<BTreeSet<String>, Error> {
        loop {
            let response = self
                .client
                .get(format!("https://api.pwnedpasswords.com/range/{prefix}"))
                .send()
                .map_err(Error::RequestSend)?;

            match response.status() {
                StatusCode::TOO_MANY_REQUESTS => {
                    // Grab the retry-after header and sleep.
                    let retry_after_secs = response
                        .headers()
                        .get("retry-after")
                        .ok_or(Error::RetryAfterMissing)?
                        .to_str()
                        .map_err(|_| Error::RetryAfterMalformed)?
                        .parse::<u64>()
                        .map_err(|_| Error::RetryAfterMalformed)?;

                    std::thread::sleep(Duration::from_secs(retry_after_secs + 1));
                }
                StatusCode::OK => {
                    // Iterate over the lines in the response, parse out the counts that we don't
                    // care about, make lowercase to match sha1_smol's output, and return.
                    return BufReader::new(response)
                        .lines()
                        .map(|result| result.map_err(Error::ResponseRead))
                        .filter_map_ok(|line| {
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                None
                            } else {
                                Some(trimmed.to_string())
                            }
                        })
                        .map_ok(|line| -> Result<String, Error> {
                            let (hash, _count) =
                                line.split_once(':').ok_or(Error::ResponseMalformed)?;

                            // The returned hashes are only partial, so we have to prepend the
                            // prefix back to match them as full hashes.
                            Ok(format!("{prefix}{}", hash.to_ascii_lowercase()))
                        })
                        .flatten()
                        .collect();
                }
                status => return Err(Error::ResponseStatus(status)),
            }
        }
    }
}
