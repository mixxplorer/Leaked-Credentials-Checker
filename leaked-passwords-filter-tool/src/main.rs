use clap::Parser;
use lcc_lib::{
    constants::{DEFAULT_FILTER_FILE, DEFAULT_PASSWORD_HASH_FILE},
    password_filter::PasswordHashFile,
};
use rand::prelude::*;

use anyhow::Result;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "CLI toolchain to build and test password filter. Currently, only Have I been pwned password hashes are utilized"
)]
pub struct CliArguments {
    #[clap(default_value = DEFAULT_PASSWORD_HASH_FILE, help = "Path to password hash file, e.g. for checking entries or re-building the filter.")]
    hash_file: String,

    #[clap(default_value = DEFAULT_FILTER_FILE, help = "Path to read and write the filter to. If re-building filter is requested, this file gets overwritten.")]
    filter_file: String,

    #[clap(short, long, help = "(Re-)Build filter from hash file.")]
    build_filter: bool,

    #[clap(short, long, action = clap::ArgAction::SetFalse, help = "Run tests against filter. Checking for false positives and false negatives.")]
    test_filter: bool,

    #[clap(flatten)]
    log_level: clap_verbosity_flag::Verbosity<clap_verbosity_flag::InfoLevel>,
}

fn test_filter(filter: lcc_lib::password_filter::PasswordFilter, password_hash_file: PasswordHashFile) -> Result<()> {
    {
        log::info!("Testing for false negatives...");
        for key in password_hash_file.iter()? {
            assert!(filter.contains(&key));
        }
        log::info!("All checked! No false negative encountered!");
    }

    {
        // bits per entry
        let bpe = (filter.len() as f64) * 32.0 / (password_hash_file.length as f64);
        log::info!("Bits per entry = {}", bpe);
    }
    {
        log::info!("Checking false positive rate...");
        const TEST_ITERATIONS: u64 = 10_000_000_000;
        let mut rng = rand::thread_rng();
        let instant_fp = std::time::Instant::now();
        // false positive rate
        let false_positives: usize = (0..TEST_ITERATIONS).map(|_| rng.gen()).filter(|n| filter.contains(n)).count();
        let elapsed_fp = instant_fp.elapsed();
        log::info!(
            "Elapsed: {:.2?}, {:.10?} µs per entry",
            elapsed_fp,
            elapsed_fp.as_micros() as f64 / (TEST_ITERATIONS as f64)
        );

        let rand_positive_rate: f64 = (false_positives * 100) as f64 / (TEST_ITERATIONS) as f64;
        let expected_rand_positive_rate: f64 = (password_hash_file.length * 100) as f64 / (2_i128.pow(64)) as f64;
        log::error!(
            "Random positive rate is {}%, while expected rate is {}%. Difference is {}%",
            rand_positive_rate,
            expected_rand_positive_rate,
            rand_positive_rate - expected_rand_positive_rate
        );
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = CliArguments::parse();

    simple_logger::SimpleLogger::new()
        .with_level(args.log_level.log_level().unwrap().to_level_filter())
        .with_utc_timestamps()
        .init()
        .unwrap();

    log::info!("Starting reading of {}...", args.hash_file);
    let password_hash_file = lcc_lib::password_filter::PasswordHashFile::from_file_name(args.hash_file.clone())?;
    log::info!("Reading of {} finished! Length of file is {}", args.hash_file, password_hash_file.iter()?.len());

    let instant_filter = std::time::Instant::now();
    let filter = {
        if args.build_filter {
            log::info!("Starting construction of filter...");

            lcc_lib::password_filter::construct_filter(&password_hash_file)?
        } else {
            log::info!("Starting loading of filter from {}...", args.filter_file);
            lcc_lib::password_filter::load_filter(&args.filter_file)?
        }
    };
    log::info!("Filter loaded in {:.2?}", instant_filter.elapsed());
    if args.build_filter {
        log::info!("Saving filter to {}", args.filter_file);
        lcc_lib::password_filter::save_filter(&filter, args.filter_file)?;
    }

    if args.test_filter {
        test_filter(filter, password_hash_file)?;
    }

    Ok(())
}
