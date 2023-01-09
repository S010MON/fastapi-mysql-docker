CREATE DATABASE IF NOT EXISTS auth;
USE auth;

CREATE TABLE users (
    id INT AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    hashed_password VARCHAR(255),
    disabled BOOLEAN,
    PRIMARY KEY (id)
    );