CREATE TABLE posts (
  id VARCHAR(255) PRIMARY KEY,
  content TEXT
);

CREATE TABLE comments (
  id SERIAL PRIMARY KEY, 
  postId VARCHAR(255),
  userId VARCHAR(255),
  content TEXT,
  FOREIGN KEY (postId) REFERENCES posts(id)
);