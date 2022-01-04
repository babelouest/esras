DROP TABLE IF EXISTS e_client_redirect_uri;
DROP TABLE IF EXISTS e_client;
DROP TABLE IF EXISTS e_profile;

CREATE TABLE e_profile (
  ep_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  ep_sub VARCHAR(128) NOT NULL,
  ep_name VARCHAR(256)
);
CREATE INDEX i_ep_username ON e_profile(ep_sub);

CREATE TABLE e_client (
  ec_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  ep_id INT(11) NOT NULL,
  ec_name VARCHAR(128),
  ec_status TINYINT DEFAULT 0,
  ec_client_id VARCHAR(128),
  ec_secret VARCHAR(128),
  ec_management_at VARCHAR(128),
  ec_registration MEDIUMBLOB,
  FOREIGN KEY(ep_id) REFERENCES e_profile(ep_id) ON DELETE CASCADE
);

CREATE TABLE e_client_redirect_uri (
  ecru_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  ec_id INT(11) NOT NULL,
  ecru_redirect_uri VARCHAR(512),
  FOREIGN KEY(ec_id) REFERENCES e_client(ec_id) ON DELETE CASCADE
);
