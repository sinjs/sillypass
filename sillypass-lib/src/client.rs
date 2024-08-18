use std::{
    fs::File,
    io::{Cursor, Read},
    path::Path,
};

use anyhow::{anyhow, Result};
use keepass::{
    db::{Entry, Group, Value},
    Database, DatabaseKey,
};
use reqwest::Client;

pub struct SillypassDatabase {
    url: String,
    db: Database,
    key: DatabaseKey,
}

pub struct SillypassEntry {
    title: Option<String>,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
}

impl SillypassDatabase {
    pub async fn open(url: String, key: DatabaseKey) -> Result<Self> {
        let response = reqwest::get(&url).await?;

        // Buffer the response body
        let body = response.bytes().await?;
        let mut cursor = Cursor::new(body.to_vec());

        // Initialize the database
        let db = Database::open(&mut cursor, key.clone())?;

        Ok(Self { url, db, key })
    }

    pub fn get_root(&self) -> &Group {
        &self.db.root
    }

    pub fn insert_entry_into(input: SillypassEntry, group: &mut Group) {
        let mut entry = Entry::new();

        if let Some(title) = input.title {
            entry
                .fields
                .insert("Title".to_string(), Value::Unprotected(title));
        };

        if let Some(username) = input.username {
            entry
                .fields
                .insert("UserName".to_string(), Value::Unprotected(username));
        };

        if let Some(password) = input.password {
            entry.fields.insert(
                "Password".to_string(),
                Value::Protected(password.as_bytes().into()),
            );
        }

        if let Some(url) = input.url {
            entry
                .fields
                .insert("URL".to_string(), Value::Unprotected(url));
        }

        group.add_child(entry)
    }

    pub fn insert_entry(&mut self, input: SillypassEntry) {
        let root = &mut self.db.root;
        SillypassDatabase::insert_entry_into(input, root);
    }

    pub async fn save(&self) -> Result<()> {
        let client = Client::new();

        let mut buffer = Cursor::new(Vec::new());
        self.db.save(&mut buffer, self.key.clone())?;

        let buffer = buffer;
        let body = reqwest::Body::from(buffer.into_inner());

        let response = client.post(&self.url).body(body).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Server returned status {}",
                response.status().as_str()
            ));
        }

        Ok(())
    }
}
