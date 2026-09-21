use anyhow::Context;
use xorf::Filter;

#[derive(Clone, Debug)]
pub struct PasswordHashPath<LengthSet>
where
    LengthSet: crate::types::AttributeState,
{
    pub base_path: std::path::PathBuf,
    length: Option<usize>,
    test_mode: bool,
    length_set: std::marker::PhantomData<LengthSet>,
}

impl PasswordHashPath<crate::types::AttributeNotSet> {
    pub fn from_directory_path(base_path: &std::path::Path, test_mode: bool) -> anyhow::Result<Self> {
        Ok(Self {
            base_path: base_path.to_path_buf(),
            length: None,
            test_mode,
            length_set: std::marker::PhantomData,
        })
    }

    /// Calculates number of entries of password hash path
    pub fn populate_length(self) -> anyhow::Result<PasswordHashPath<crate::types::AttributeSet>> {
        let length = {
            let (error_count, lines) = self.get_password_iterator_hashes();
            let count = lines.count();

            let locked_error_count = error_count
                .lock()
                .map_err(|err| anyhow::anyhow!("Unable to obtain error count lock: {:?}", err))?;
            if *locked_error_count > 0 {
                anyhow::bail!("Encountered {} errors during hash file reading.", locked_error_count);
            }
            count
        };

        Ok(PasswordHashPath {
            base_path: self.base_path,
            length: Some(length),
            test_mode: self.test_mode,
            length_set: std::marker::PhantomData,
        })
    }
}

impl PasswordHashPath<crate::types::AttributeSet> {
    /// Returns the number of hash entries in path
    pub fn len(&self) -> usize {
        self.length.unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> anyhow::Result<PasswordHashFileIterator> {
        PasswordHashFileIterator::from_password_hash_path_with_length(self.clone(), 0)
    }
}

impl<LengthSet> PasswordHashPath<LengthSet>
where
    LengthSet: crate::types::AttributeState + Send + Sync + 'static,
{
    fn generate_file_names(base_path: std::path::PathBuf) -> impl Iterator<Item = (std::path::PathBuf, String)> {
        (0..0x100).flat_map(move |first| {
            let base_path = base_path.clone();
            (0..0x100).flat_map(move |second| {
                let base_path = base_path.clone();
                let first_path = format!("{first:02x}");
                let second_path = format!("{second:02x}");
                (0..0x10).map(move |third| {
                    let third_path = format!("{third:01x}");
                    let hash_start = format!("{first_path}{second_path}{third_path}");
                    (
                        base_path.join("sha1").join(&first_path).join(&second_path).join(format!("{hash_start}.gz")),
                        hash_start,
                    )
                })
            })
        })
    }

    /// Returns password hashes, shortened and formatted for bincode filter as a rayon parallel iterator
    pub fn get_password_iterator_hashes(&self) -> (std::sync::Arc<std::sync::Mutex<u64>>, Box<impl Iterator<Item = u64> + 'static>) {
        let base_path = self.base_path.clone();

        Self::get_password_iterator_hashes_static(base_path, self.test_mode)
    }

    /// Returns password hashes, shortened and formatted for bincode filter as a rayon parallel iterator, internal static version
    fn get_password_iterator_hashes_static(
        base_path: std::path::PathBuf,
        test_mode: bool,
    ) -> (std::sync::Arc<std::sync::Mutex<u64>>, Box<impl Iterator<Item = u64>>) {
        let file_names = Self::generate_file_names(base_path.to_path_buf());

        let error_count = std::sync::Arc::new(std::sync::Mutex::<u64>::new(0));
        let error_count_map_1 = error_count.clone();
        let error_count_map_2 = error_count.clone();

        let lines = Box::new(
            file_names
                .map(
                    move |(path, hash_start)| -> anyhow::Result<(std::io::Lines<std::io::BufReader<flate2::read::GzDecoder<std::fs::File>>>, String)> {
                        let file_res = std::fs::File::open(path.clone());
                        if !test_mode && let Err(ref err) = file_res {
                            log::error!("File open error: {:?} for {:?}", err, path);
                            *error_count_map_1.lock().unwrap() += 1;
                        }
                        Ok((
                            std::io::BufRead::lines(std::io::BufReader::with_capacity(1024, flate2::read::GzDecoder::new(file_res?))),
                            hash_start,
                        ))
                    },
                )
                .filter_map(Result::ok)
                .flat_map(move |(lines, hash_start)| {
                    lines
                        .into_iter()
                        .map(|line_res| {
                            if let Err(ref error) = line_res {
                                log::error!("File line parsing error: {:?}", error);
                                *error_count_map_2.lock().unwrap() += 1;
                                return line_res;
                            }
                            Ok(format!("{hash_start}{}", line_res.unwrap()))
                        })
                        .filter_map(Result::ok)
                        .collect::<Vec<String>>()
                }),
        );

        let lines = lines.map(|line: String| hash_string_to_filter_items(&line)).filter_map(Result::ok).flatten();

        (error_count, Box::new(lines))
    }
}

pub struct PasswordHashFileIterator {
    pub path: PasswordHashPath<crate::types::AttributeSet>,
    iterator: Box<dyn Iterator<Item = u64>>,
    lines_consumed: usize,
}

pub fn hash_string_to_filter_items(input: &String) -> anyhow::Result<Vec<u64>> {
    if input.len() < 16 {
        anyhow::bail!("Given hash string '{}' too short (< 16 chars)", input)
    }
    Ok(vec![u64::from_str_radix(&input[0..16], 16)?])
}

impl PasswordHashFileIterator {
    fn from_password_hash_path_with_length(path: PasswordHashPath<crate::types::AttributeSet>, skip_lines: usize) -> anyhow::Result<Self> {
        // ignore errors here, as they were checked during line/entry counting
        let (_errors, filtered_iterator) = path.get_password_iterator_hashes();

        Ok(PasswordHashFileIterator {
            iterator: Box::new(filtered_iterator.skip(skip_lines)),
            lines_consumed: 0,
            path,
        })
    }
}

impl Clone for PasswordHashFileIterator {
    fn clone(&self) -> Self {
        Self::from_password_hash_path_with_length(self.path.clone(), self.lines_consumed).unwrap()
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
        self.path.len()
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

pub fn construct_filter(password_hash_file: &PasswordHashPath<crate::types::AttributeSet>) -> anyhow::Result<PasswordFilter> {
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
