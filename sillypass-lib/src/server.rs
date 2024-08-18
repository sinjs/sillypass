use std::{
    fs::File,
    io::{self, Read},
};

use anyhow::{Context, Result};

pub fn write_database<R: Read>(path: &str, mut contents: R) -> Result<()> {
    let mut file = File::create(path)?;
    io::copy(&mut contents, &mut file)?;

    Ok(())
}

pub fn get_database<'a>(path: &str) -> Result<Box<dyn Read>> {
    let file = File::open(path)?;
    Ok(Box::new(file))
}
