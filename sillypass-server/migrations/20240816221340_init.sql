CREATE TABLE users (
  id SERIAL NOT NULL PRIMARY KEY,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,

  UNIQUE(email)
);

CREATE TABLE vaults (
  id UUID NOT NULL PRIMARY KEY,
  user_id SERIAL NOT NULL,
  secret_access_key TEXT,
  
  UNIQUE(user_id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
