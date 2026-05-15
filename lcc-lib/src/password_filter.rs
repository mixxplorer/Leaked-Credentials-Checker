use anyhow::Context;
use itertools::Itertools;
use xorf::Filter;

fn map_password_hash_lines(lines: Box<dyn Iterator<Item = std::io::Result<String>>>) -> impl Iterator<Item = u64> {
    lines
        .map_while(Result::ok)
        .map(|line: String| hash_string_to_filter_items(&line))
        .filter_map(Result::ok)
        .flatten()
        .dedup()
}

fn generate_file_names(base_path: std::path::PathBuf) -> impl Iterator<Item = std::path::PathBuf> {
    (0..256).flat_map(move |first| {
        let base_path = base_path.clone();
        (0..256).flat_map(move |second| {
            let base_path = base_path.clone();
            let first_path = format!("{first:02x}");
            let second_path = format!("{second:02x}");
            (0..16).map(move |third| {
                let third_path = format!("{third:01x}");
                base_path
                    .join("sha1")
                    .join(&first_path)
                    .join(&second_path)
                    .join(format!("{first_path}{second_path}{third_path}.gz"))
            })
        })
    })
}

pub struct PasswordHashPath {
    pub base_path: std::path::PathBuf,
    pub length: usize,
}

impl PasswordHashPath {
    pub fn from_directory_path(base_path: &std::path::Path) -> anyhow::Result<Self> {
        let file_names = generate_file_names(base_path.to_path_buf());

        let lines: Box<dyn Iterator<Item = std::io::Result<String>>> = Box::new(
            file_names
                .map(
                    |name| -> anyhow::Result<std::io::Lines<std::io::BufReader<flate2::read::GzDecoder<std::fs::File>>>> {
                        let file = std::fs::File::open(name.clone())?;
                        Ok(std::io::BufRead::lines(std::io::BufReader::with_capacity(
                            1024 * 1024 * 64,
                            flate2::read::GzDecoder::new(file),
                        )))
                    },
                )
                .filter_map(Result::ok)
                .flatten(),
        );

        let length = map_password_hash_lines(lines).count();

        Ok(Self {
            base_path: base_path.to_path_buf(),
            length,
        })
    }

    pub fn iter(&self) -> anyhow::Result<PasswordHashFileIterator> {
        PasswordHashFileIterator::from_base_path_with_length(&self.base_path, self.length, 0)
    }
}

pub struct PasswordHashFileIterator {
    pub base_path: std::path::PathBuf,
    iterator: Box<dyn Iterator<Item = u64>>,
    length: usize,
    lines_consumed: usize,
}

pub fn hash_string_to_filter_items(input: &String) -> anyhow::Result<Vec<u64>> {
    if input.len() < 16 {
        anyhow::bail!("Given hash string '{}' too short (< 16 chars)", input)
    }
    Ok(vec![u64::from_str_radix(&input[0..16], 16)?])
}

impl PasswordHashFileIterator {
    fn from_base_path_with_length(base_path: &std::path::Path, length: usize, skip_lines: usize) -> anyhow::Result<Self> {
        let file_names = generate_file_names(base_path.to_path_buf());

        let lines: Box<dyn Iterator<Item = std::io::Result<String>>> = Box::new(
            file_names
                .map(
                    |name| -> anyhow::Result<std::io::Lines<std::io::BufReader<flate2::read::GzDecoder<std::fs::File>>>> {
                        let file = std::fs::File::open(name.clone())?;
                        Ok(std::io::BufRead::lines(std::io::BufReader::with_capacity(
                            1024 * 1024 * 64,
                            flate2::read::GzDecoder::new(file),
                        )))
                    },
                )
                .filter_map(Result::ok)
                .flatten(),
        );

        let filtered = map_password_hash_lines(lines).skip(skip_lines);
        Ok(PasswordHashFileIterator {
            iterator: Box::new(filtered),
            length,
            lines_consumed: 0,
            base_path: base_path.to_path_buf(),
        })
    }
}

impl Clone for PasswordHashFileIterator {
    fn clone(&self) -> Self {
        Self::from_base_path_with_length(&self.base_path, self.length, self.lines_consumed).unwrap()
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
    filter: crate::constants::BinaryFilterType,
    pub licenses: Vec<crate::util::License>,
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

pub fn construct_filter(password_hash_file: &PasswordHashPath) -> anyhow::Result<PasswordFilter> {
    let filter = crate::constants::BinaryFilterType::try_from_iterator(password_hash_file.iter()?)
        .map_err(|op| anyhow::anyhow!(op.to_string()))
        .context("Constructing xor filter failed!")?;
    Ok(PasswordFilter {
        filter,
        licenses: vec![
            crate::util::License {
                part: "XOR filter".to_string(),
                author: "Mixxplorer GmbH".to_string(),
                owner_url: "https://mixxplorer.de".to_string(),
                project_url: "https://rechenknecht.net/mixxplorer/lcc/lcc".to_string(),
                license: "MIT".to_string(),
            },
            crate::util::License {
                part: "Leaked passwords".to_string(),
                author: "Have I Been Pwned".to_string(),
                owner_url: "https://haveibeenpwned.com".to_string(),
                project_url: "https://haveibeenpwned.com/API/v3".to_string(),
                license: "Creative Commons Attribution 4.0 International License.".to_string(),
            },
        ],
    })
}

pub fn save_filter(filter: &PasswordFilter, filter_file: String) -> anyhow::Result<()> {
    let mut filter_file_fp = std::io::BufWriter::new(std::fs::File::create(filter_file)?);
    bincode::encode_into_std_write(filter, &mut filter_file_fp, bincode::config::standard())?;
    Ok(())
}

pub fn load_filter(filter_file: &String) -> anyhow::Result<PasswordFilter> {
    let mut filter_file_fp = std::io::BufReader::with_capacity(1024 * 1024 * 64, std::fs::File::open(filter_file)?);
    Ok(bincode::decode_from_std_read(&mut filter_file_fp, bincode::config::standard())?)
}
