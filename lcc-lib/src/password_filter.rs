use anyhow::{bail, Context, Result};
use itertools::Itertools;
use xorf::Filter;

use crate::{constants::BinaryFilterType, util};

pub struct PasswordHashFile {
    pub file_name: String,
    pub length: usize,
}

impl PasswordHashFile {
    pub fn from_file_name(file_name: String) -> Result<Self> {
        let file = std::io::BufReader::with_capacity(1024 * 1024 * 64, std::fs::File::open(&file_name)?);
        let lines = std::io::BufRead::lines(file).map_while(Result::ok).dedup();
        let length = lines.count();

        Ok(Self { file_name, length })
    }

    pub fn iter(&self) -> Result<PasswordHashFileIterator> {
        PasswordHashFileIterator::from_file_name_with_length(self.file_name.clone(), self.length, 0)
    }
}

pub struct PasswordHashFileIterator {
    file_name: String,
    iterator: Box<dyn Iterator<Item = u64>>,
    length: usize,
    lines_consumed: usize,
}

pub fn hash_string_to_filter_item(input: &String) -> Result<u64> {
    if input.len() < 16 {
        bail!("Given hash string '{}' too short (< 16 chars)", input)
    }
    Ok(u64::from_str_radix(&input[0..16], 16)?)
}

impl PasswordHashFileIterator {
    fn from_file_name_with_length(file_name: String, length: usize, skip_lines: usize) -> Result<Self> {
        let reader = std::io::BufReader::new(std::fs::File::open(&file_name)?);
        let lines = std::io::BufRead::lines(reader);

        let filtered = lines
            .map_while(Result::ok)
            .map(|line: String| hash_string_to_filter_item(&line))
            .map_while(Result::ok)
            .dedup()
            .skip(skip_lines);
        Ok(PasswordHashFileIterator {
            file_name,
            iterator: Box::new(filtered),
            length,
            lines_consumed: 0,
        })
    }
}

impl Clone for PasswordHashFileIterator {
    fn clone(&self) -> Self {
        Self::from_file_name_with_length(self.file_name.clone(), self.length, self.lines_consumed).unwrap()
    }
}

impl Iterator for PasswordHashFileIterator {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        self.lines_consumed += 1;
        self.iterator.next()
    }
}

impl ExactSizeIterator for PasswordHashFileIterator {
    fn len(&self) -> usize {
        self.length
    }
}

#[derive(bincode::Encode, bincode::Decode)]
pub struct PasswordFilter {
    filter: BinaryFilterType,
    pub licenses: Vec<util::License>,
}

impl PasswordFilter {
    pub fn contains(&self, key: &u64) -> bool {
        self.filter.contains(key)
    }

    pub fn len(&self) -> usize {
        self.filter.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub fn construct_filter(password_hash_file: &PasswordHashFile) -> Result<PasswordFilter> {
    let filter = BinaryFilterType::try_from_iterator(password_hash_file.iter()?)
        .map_err(|op| anyhow::anyhow!(op.to_string()))
        .context("Constructing xor filter failed!")?;
    Ok(PasswordFilter {
        filter,
        licenses: vec![
            util::License {
                part: "XOR filter".to_string(),
                author: "Mixxplorer GmbH".to_string(),
                owner_url: "https://mixxplorer.de".to_string(),
                project_url: "https://rechenknecht.net/mixxplorer/lcc/lcc".to_string(),
                license: "MIT".to_string(),
            },
            util::License {
                part: "Leaked passwords".to_string(),
                author: "Have I Been Pwned".to_string(),
                owner_url: "https://haveibeenpwned.com".to_string(),
                project_url: "https://haveibeenpwned.com/API/v3".to_string(),
                license: "Creative Commons Attribution 4.0 International License.".to_string(),
            },
        ],
    })
}

pub fn save_filter(filter: &PasswordFilter, filter_file: String) -> Result<()> {
    let mut filter_file_fp = std::io::BufWriter::new(std::fs::File::create(filter_file)?);
    bincode::encode_into_std_write(filter, &mut filter_file_fp, bincode::config::standard())?;
    Ok(())
}

pub fn load_filter(filter_file: &String) -> Result<PasswordFilter> {
    let mut filter_file_fp = std::io::BufReader::with_capacity(1024 * 1024 * 64, std::fs::File::open(filter_file)?);
    Ok(bincode::decode_from_std_read(&mut filter_file_fp, bincode::config::standard())?)
}
