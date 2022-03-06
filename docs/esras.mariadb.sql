DROP TABLE IF EXISTS e_client_session;
DROP TABLE IF EXISTS e_client_redirect_uri;
DROP TABLE IF EXISTS e_client;
DROP TABLE IF EXISTS session;
DROP TABLE IF EXISTS profile;

CREATE TABLE profile (
  p_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  p_sub VARCHAR(128) NOT NULL,
  p_name VARCHAR(256)
);
CREATE INDEX i_p_username ON profile(p_sub);

CREATE TABLE session (
  s_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  p_id INT(11),
  s_session_hash VARCHAR(128) NOT NULL,
  s_state VARCHAR(128) NOT NULL,
  s_nonce VARCHAR(128) NOT NULL,
  s_refresh_token MEDIUMBLOB,
  s_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  s_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  s_token_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  s_enabled TINYINT(1) DEFAULT 1,
  FOREIGN KEY(p_id) REFERENCES profile(p_id) ON DELETE CASCADE
);

CREATE TABLE e_client (
  ec_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  p_id INT(11) NOT NULL,
  ec_name VARCHAR(128),
  ec_enabled TINYINT DEFAULT 1,
  ec_client_id VARCHAR(128),
  ec_client_secret VARCHAR(128),
  ec_registration_access_token VARCHAR(128),
  ec_registration_client_uri VARCHAR(512),
  ec_registration MEDIUMBLOB,
  FOREIGN KEY(p_id) REFERENCES profile(p_id) ON DELETE CASCADE
);

CREATE TABLE e_client_redirect_uri (
  ecru_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  ec_id INT(11) NOT NULL,
  ecru_redirect_uri VARCHAR(512),
  FOREIGN KEY(ec_id) REFERENCES e_client(ec_id) ON DELETE CASCADE
);

CREATE TABLE e_client_session (
  ecs_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  s_id INT(11) NOT NULL,
  ec_id INT(11) NOT NULL,
  ecs_state VARCHAR(128),
  ecs_session MEDIUMBLOB,
  FOREIGN KEY(s_id) REFERENCES session(s_id) ON DELETE CASCADE,
  FOREIGN KEY(ec_id) REFERENCES e_client(ec_id) ON DELETE CASCADE
);
CREATE INDEX i_ecs_state ON e_client_session(ecs_state);
