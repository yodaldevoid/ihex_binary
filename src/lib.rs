use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use ihex::{Reader, ReaderError, Record};
use log::*;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("IO error when opening file")]
    FailedOpen(#[source] io::Error),
    #[error("IO error when reading file")]
    FailedRead(#[source] io::Error),
    #[error("Error while unpacking IHEX into array")]
    Unpacking(#[from] UnpackingError),
}

pub fn load_file<P: AsRef<Path>>(
    path: P,
    binary_size: usize,
    base_offset: usize,
) -> Result<(Vec<u8>, usize), LoadError> {
    let mut file = File::open(path).map_err(LoadError::FailedOpen)?;
    let mut file_buf = Vec::new();
    file.read_to_end(&mut file_buf)
        .map_err(LoadError::FailedRead)?;

    let file_str = String::from_utf8_lossy(&file_buf[..]);
    Reader::new(&file_str)
        .to_vec(binary_size, base_offset)
        .map_err(LoadError::from)
}

#[derive(Debug, PartialEq, Error)]
pub enum UnpackingError {
    #[error("Error while parsing IHEX records")]
    Parsing(#[from] ReaderError),
    #[error("Address ({0}) greater than binary size ({1})")]
    AddressTooHigh(usize, usize),
}

pub trait ReaderExt {
    fn to_vec(
        self,
        binary_size: usize,
        base_offset: usize,
    ) -> Result<(Vec<u8>, usize), UnpackingError>;
    fn to_array<const N: usize>(
        self,
        base_offset: usize,
    ) -> Result<([u8; N], usize), UnpackingError>;
}

impl<I> ReaderExt for I
where
    I: Iterator<Item = Result<Record, ReaderError>>,
{
    fn to_vec(
        mut self,
        binary_size: usize,
        base_offset: usize,
    ) -> Result<(Vec<u8>, usize), UnpackingError> {
        let mut binary = vec![0xFF; binary_size];
        let used_bytes = unpack_records(&mut self, &mut binary, base_offset)?;
        Ok((binary, used_bytes))
    }

    fn to_array<const N: usize>(
        mut self,
        base_offset: usize,
    ) -> Result<([u8; N], usize), UnpackingError> {
        let mut binary = [0xFF; N];
        let used_bytes = unpack_records(&mut self, &mut binary, base_offset)?;
        Ok((binary, used_bytes))
    }
}

fn unpack_records(
    records: &mut impl Iterator<Item = Result<Record, ReaderError>>,
    binary: &mut [u8],
    base_offset: usize,
) -> Result<usize, UnpackingError> {
    let mut base_address = 0;
    let mut used_bytes = 0;

    for rec in records {
        match rec {
            Ok(rec) => {
                debug!("base_address=0x{:04X} rec={:?}", base_address, rec);
                match rec {
                    Record::Data { offset, value } => {
                        let end_addr = base_address + offset as usize + value.len();
                        if end_addr > binary.len() {
                            return Err(UnpackingError::AddressTooHigh(end_addr, binary.len()));
                        }

                        used_bytes += value.len();
                        for (n, b) in value.iter().enumerate() {
                            binary[base_address + offset as usize + n] = *b;
                        }
                    }
                    Record::ExtendedSegmentAddress(base) => {
                        base_address = ((base as usize) << 4) - base_offset
                    }
                    Record::ExtendedLinearAddress(base) => {
                        base_address = ((base as usize) << 16) - base_offset
                    }
                    Record::EndOfFile => break,
                    // Defines the start location for our program. This doesn't concern us so we
                    // ignore it.
                    Record::StartLinearAddress(_) | Record::StartSegmentAddress { .. } => {}
                }
            }
            Err(err) => return Err(UnpackingError::Parsing(err)),
        }
    }

    Ok(used_bytes)
}
