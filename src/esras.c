/**
 *
 * esras: OAuth2/OIDC client program to test or validate OAuth2/OIDC AS
 * for multiple users, with database persistence - AKA idwcc on steroids
 *
 * Copyright 2022 Nicolas Mora <mail@babelouest.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation;
 * version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <getopt.h>
#include <signal.h>
#include <ctype.h>
#include <libconfig.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "esras.h"

pthread_mutex_t global_handler_close_lock;
pthread_cond_t  global_handler_close_cond;

/**
 *
 * Main function
 *
 * Initialize config structure, parse the arguments and the config file
 * Then run the webservice
 *
 */
int main (int argc, char ** argv) {
  struct config_elements * config = o_malloc(sizeof(struct config_elements));
  int res;
  struct _i_session i_session;

  srand(time(NULL));
  if (config == NULL) {
    fprintf(stderr, "Memory error - config\n");
    return 1;
  }

  // Init config structure with default values
  config->config_file = NULL;
  config->port = ESRAS_DEFAULT_PORT;
  config->api_prefix = o_strdup(ESRAS_DEFAULT_PREFIX);
  config->index_url = o_strdup(ESRAS_DEFAULT_INDEX);
  config->log_mode = Y_LOG_MODE_NONE;
  config->log_level = Y_LOG_LEVEL_NONE;
  config->log_file = NULL;
  config->conn = NULL;
  config->instance = o_malloc(sizeof(struct _u_instance));
  config->allow_origin = NULL;
  config->static_file_config = o_malloc(sizeof(struct _u_compressed_inmemory_website_config));
  config->j_server_config = NULL;
  config->j_server_jwks = NULL;
  config->client_redirect_uri = NULL;
  config->register_scope = NULL;
  config->use_secure_connection = 0;
  config->secure_connection_key_file = NULL;
  config->secure_connection_pem_file = NULL;
  config->session_key = NULL;
  config->session_expiration = ESRAS_DEFAULT_SESSION_EXPIRATION;
  config->session_extend = 0;
  config->cookie_domain = NULL;
  config->cookie_secure = 1;
  config->oidc_server_remote_config = NULL;
  config->oidc_scope = NULL;
  config->oidc_name_claim = NULL;
  config->oidc_is_jwt_access_token = 0;
  config->client_id = NULL;
  config->test_client_redirect_uri = NULL;
  config->test_client_ciba_notification_endpoint = NULL;
  config->test_callback_page = o_strdup("callback.html");
  config->client_secret = NULL;
  config->client_secret_key = NULL;
  config->client_auth_method = I_TOKEN_AUTH_METHOD_SECRET_BASIC;
  config->client_token_auth_method = I_AUTH_METHOD_GET;
  config->client_sign_alg = NULL;
  if (config->instance == NULL || config->static_file_config == NULL) {
    fprintf(stderr, "Memory error - config->instance || config->static_file_config\n");
    o_free(config);
    return 1;
  }

  if (pthread_mutex_init(&global_handler_close_lock, NULL) ||
      pthread_cond_init(&global_handler_close_cond, NULL)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "init - Error initializing global_handler_close_lock or global_handler_close_cond");
  }
  // Catch end signals to make a clean exit
  signal (SIGQUIT, exit_handler);
  signal (SIGINT, exit_handler);
  signal (SIGTERM, exit_handler);
  signal (SIGHUP, exit_handler);

  if (u_init_compressed_inmemory_website_config(config->static_file_config) != U_OK) {
    fprintf(stderr, "Error u_init_compressed_inmemory_website_config\n");
    exit_server(&config, ESRAS_ERROR);
  }
  u_map_put(&config->static_file_config->mime_types, "*", "application/octet-stream");

  if (i_init_session(&i_session) != I_OK) {
    fprintf(stderr, "Error i_init_session\n");
    print_help(stderr);
    exit_server(&config, ESRAS_ERROR);
  }

  // First we parse command line arguments
  if (!build_config_from_args(argc, argv, config)) {
    fprintf(stderr, "Error reading command-line parameters\n");
    print_help(stderr);
    exit_server(&config, ESRAS_ERROR);
  }

  // Then we parse configuration file
  // They have lower priority than command line parameters
  if (!build_config_from_file(config)) {
    fprintf(stderr, "Error config file\n");
    exit_server(&config, ESRAS_ERROR);
  }

  // Check if all mandatory configuration variables are present and correctly typed
  if (!check_config(config)) {
    fprintf(stderr, "Error initializing configuration\n");
    exit_server(&config, ESRAS_ERROR);
  }

  if (!y_init_logs(ESRAS_LOG_NAME, config->log_mode, config->log_level, config->log_file, "Starting Esras Server")) {
    fprintf(stderr, "Error initializing logs\n");
    exit_server(&config, ESRAS_ERROR);
  }

  if (!config->oidc_server_verify_cert) {
    i_set_int_parameter(&i_session, I_OPT_REMOTE_CERT_FLAG, I_REMOTE_VERIFY_NONE);
  }
  if (i_set_str_parameter(&i_session, I_OPT_OPENID_CONFIG_ENDPOINT, config->oidc_server_remote_config) != I_OK || i_get_openid_config(&i_session) != I_OK) {
    fprintf(stderr, "Error initializing i_session\n");
    exit_server(&config, ESRAS_ERROR);
  } else {
    y_log_message(Y_LOG_LEVEL_INFO, "Loading OpenID Config Endpoint %s", config->oidc_server_remote_config);
  }
  if ((config->j_server_config = i_get_server_configuration(&i_session)) == NULL ||
      (config->j_server_jwks = i_get_server_jwks(&i_session)) == NULL) {
    fprintf(stderr, "Error exporting session\n");
    exit_server(&config, ESRAS_ERROR);
  }
  i_clean_session(&i_session);

  ulfius_init_instance(config->instance, config->port, NULL, NULL);

  // Everything is under the protection of the session
  ulfius_add_endpoint_by_val(config->instance, "*", NULL, "*", ESRAS_CALLBACK_PRIORITY_AUTHENTICATION, &callback_esras_check_session, config);

  // Except for the callback
  ulfius_add_endpoint_by_val(config->instance, "GET", NULL, "/callback", ESRAS_CALLBACK_PRIORITY_ZERO, &callback_esras_callback_url, config);

  // At this point, we declare all API endpoints and configure
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/profile", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_profile, config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/profile", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_delete_session, config);

  // Client CRUD
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/client", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_list_client, config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/client", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_add_client, config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/client/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_set_client, config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/client/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_disable_client, config);

  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/oidc_config", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_oidc_config, config);

  // Client execution
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/exec/session/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_get_session, config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/exec/session/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_set_session, config);
  ulfius_add_endpoint_by_val(config->instance, "DELETE", config->api_prefix, "/exec/session/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_delete_session, config);
  ulfius_add_endpoint_by_val(config->instance, "PUT", config->api_prefix, "/exec/generate/:client_id/:property", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_generate, config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/exec/auth/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_run_auth, config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/exec/par/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_run_par, config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/exec/callback", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_callback, config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/exec/callback", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_parse_callback, config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/exec/token/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_run_token, config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/exec/userinfo/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_run_userinfo, config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/exec/introspection/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_run_introspect, config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/exec/revocation/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_run_revoke, config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/exec/device/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_run_device_auth, config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/exec/ciba/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_exec_run_ciba_auth, config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/notification/ciba", ESRAS_CALLBACK_PRIORITY_ZERO, &callback_esras_ciba_notification, config);
  ulfius_add_endpoint_by_val(config->instance, "GET", config->api_prefix, "/notification/ciba/:client_id", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_get_ciba_notification, config);
  ulfius_add_endpoint_by_val(config->instance, "POST", config->api_prefix, "/exec/rar/:client_id/:type", ESRAS_CALLBACK_PRIORITY_APPLICATION, &callback_esras_rar_add_type, config);

  // Other endpoints
  if (config->static_file_config->files_path != NULL) {
    ulfius_add_endpoint_by_val(config->instance, "GET", config->static_file_config->url_prefix, "*", ESRAS_CALLBACK_PRIORITY_FILE, &callback_static_compressed_inmemory_website, (void*)config->static_file_config);
  }
  ulfius_add_endpoint_by_val(config->instance, "OPTIONS", NULL, "*", ESRAS_CALLBACK_PRIORITY_ZERO, &callback_esras_options, (void*)config);
  ulfius_add_endpoint_by_val(config->instance, "*", config->api_prefix, "*", ESRAS_CALLBACK_PRIORITY_COMPRESSION, &callback_http_compression, NULL);
  ulfius_add_endpoint_by_val(config->instance, "GET", NULL, "*", ESRAS_CALLBACK_PRIORITY_POST_FILE, &callback_404_if_necessary, NULL);
  ulfius_set_default_endpoint(config->instance, &callback_default, (void*)config);

  // Set default headers
  u_map_put(config->instance->default_headers, "Access-Control-Allow-Origin", config->allow_origin);
  u_map_put(config->instance->default_headers, "Access-Control-Allow-Credentials", "true");
  u_map_put(config->instance->default_headers, "Cache-Control", "no-store");
  u_map_put(config->instance->default_headers, "Pragma", "no-cache");
  u_map_put(config->instance->default_headers, "X-Frame-Options", "deny");

  y_log_message(Y_LOG_LEVEL_INFO, "Start Esras on port %d, prefix: %s, secure: %s, scope %s, index url: %s", config->instance->port, config->api_prefix, config->use_secure_connection?"true":"false", config->oidc_scope, config->index_url);

  if (config->use_secure_connection) {
    char * key_file = get_file_content(config->secure_connection_key_file);
    char * pem_file = get_file_content(config->secure_connection_pem_file);
    if (key_file != NULL && pem_file != NULL) {
      res = ulfius_start_secure_framework(config->instance, key_file, pem_file);
    } else {
      res = U_ERROR_PARAMS;
    }
    o_free(key_file);
    o_free(pem_file);
  } else {
    res = ulfius_start_framework(config->instance);
  }
  if (res == U_OK) {
    // Wait until stop signal is broadcasted
    pthread_mutex_lock(&global_handler_close_lock);
    pthread_cond_wait(&global_handler_close_cond, &global_handler_close_lock);
    pthread_mutex_unlock(&global_handler_close_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error starting esras webservice");
    exit_server(&config, ESRAS_ERROR);
  }
  if (pthread_mutex_destroy(&global_handler_close_lock) ||
      pthread_cond_destroy(&global_handler_close_cond)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error destroying global_handler_close_lock or global_handler_close_cond");
  }
  exit_server(&config, ESRAS_STOP);
  return 0;
}

/**
 * Exit properly the server by closing opened connections, databases and files
 */
void exit_server(struct config_elements ** config, int exit_value) {

  if (config != NULL && *config != NULL) {
    // Cleaning data
    o_free((*config)->config_file);
    o_free((*config)->api_prefix);
    o_free((*config)->index_url);
    o_free((*config)->log_file);
    o_free((*config)->session_key);
    o_free((*config)->allow_origin);
    o_free((*config)->cookie_domain);
    o_free((*config)->secure_connection_key_file);
    o_free((*config)->secure_connection_pem_file);
    o_free((*config)->oidc_server_remote_config);
    o_free((*config)->oidc_scope);
    o_free((*config)->oidc_name_claim);
    o_free((*config)->client_id);
    o_free((*config)->client_redirect_uri);
    o_free((*config)->client_secret);
    o_free((*config)->client_sign_alg);
    r_jwk_free((*config)->client_secret_key);

    o_free((*config)->static_file_config->files_path);
    o_free((*config)->static_file_config->url_prefix);
    u_clean_compressed_inmemory_website_config((*config)->static_file_config);
    o_free((*config)->static_file_config);
    h_close_db((*config)->conn);
    h_clean_connection((*config)->conn);
    ulfius_stop_framework((*config)->instance);
    ulfius_clean_instance((*config)->instance);
    json_decref((*config)->j_server_config);
    json_decref((*config)->j_server_jwks);
    o_free((*config)->test_client_redirect_uri);
    o_free((*config)->test_client_ciba_notification_endpoint);
    o_free((*config)->test_callback_page);
    o_free((*config)->register_scope);
    o_free((*config)->instance);

    o_free(*config);
    (*config) = NULL;
  }
  y_close_logs();
  exit(exit_value);
}

/**
 * Initialize the application configuration based on the command line parameters
 */
int build_config_from_args(int argc, char ** argv, struct config_elements * config) {
  int next_option;
  const char * short_options = "c:p:m:l:f:h::v::";
  char * tmp = NULL, * to_free = NULL, * one_log_mode = NULL;
  static const struct option long_options[]= {
    {"config-file", optional_argument, NULL, 'c'},
    {"port", optional_argument, NULL, 'p'},
    {"url-prefix", optional_argument, NULL, 'u'},
    {"log-mode", optional_argument, NULL, 'm'},
    {"log-level", optional_argument, NULL, 'l'},
    {"log-file", optional_argument, NULL, 'f'},
    {"help", optional_argument, NULL, 'h'},
    {"version", optional_argument, NULL, 'v'},
    {NULL, 0, NULL, 0}
  };

  if (config != NULL) {
    do {
      next_option = getopt_long(argc, argv, short_options, long_options, NULL);

      switch (next_option) {
        case 'c':
          if (optarg != NULL) {
            if ((config->config_file = o_strdup(optarg)) == NULL) {
              fprintf(stderr, "Error allocating config->config_file, exiting\n");
              exit_server(&config, ESRAS_STOP);
            }
          } else {
            fprintf(stderr, "Error!\nNo config file specified\n");
            return 0;
          }
          break;
        case 'p':
          if (optarg != NULL) {
            config->port = strtol(optarg, NULL, 10);
          } else {
            fprintf(stderr, "Error!\nNo TCP Port number specified\n");
            return 0;
          }
          break;
        case 'u':
          if (optarg != NULL) {
            o_free(config->api_prefix);
            if ((config->api_prefix = o_strdup(optarg)) == NULL) {
              fprintf(stderr, "Error allocating config->api_prefix, exiting\n");
              exit_server(&config, ESRAS_STOP);
            }
          } else {
            fprintf(stderr, "Error!\nNo URL prefix specified\n");
            return 0;
          }
          break;
        case 'm':
          if (optarg != NULL) {
            if ((tmp = o_strdup(optarg)) == NULL) {
              fprintf(stderr, "Error allocating log_mode, exiting\n");
              exit_server(&config, ESRAS_STOP);
            }
            one_log_mode = strtok(tmp, ",");
            while (one_log_mode != NULL) {
              if (0 == strncmp("console", one_log_mode, o_strlen("console"))) {
                config->log_mode |= Y_LOG_MODE_CONSOLE;
              } else if (0 == strncmp("syslog", one_log_mode, o_strlen("syslog"))) {
                config->log_mode |= Y_LOG_MODE_SYSLOG;
              } else if (0 == strncmp("file", one_log_mode, o_strlen("file"))) {
                config->log_mode |= Y_LOG_MODE_FILE;
              }
              one_log_mode = strtok(NULL, ",");
            }
            o_free(to_free);
          } else {
            fprintf(stderr, "Error!\nNo mode specified\n");
            return 0;
          }
          break;
        case 'l':
          if (optarg != NULL) {
            if (0 == strncmp("NONE", optarg, o_strlen("NONE"))) {
              config->log_level = Y_LOG_LEVEL_NONE;
            } else if (0 == strncmp("ERROR", optarg, o_strlen("ERROR"))) {
              config->log_level = Y_LOG_LEVEL_ERROR;
            } else if (0 == strncmp("WARNING", optarg, o_strlen("WARNING"))) {
              config->log_level = Y_LOG_LEVEL_WARNING;
            } else if (0 == strncmp("INFO", optarg, o_strlen("INFO"))) {
              config->log_level = Y_LOG_LEVEL_INFO;
            } else if (0 == strncmp("DEBUG", optarg, o_strlen("DEBUG"))) {
              config->log_level = Y_LOG_LEVEL_DEBUG;
            }
          } else {
            fprintf(stderr, "Error!\nNo log level specified\n");
            return 0;
          }
          break;
        case 'f':
          if (optarg != NULL) {
            o_free(config->log_file);
            if ((config->log_file = o_strdup(optarg)) == NULL) {
              fprintf(stderr, "Error allocating config->log_file, exiting\n");
              exit_server(&config, ESRAS_STOP);
            }
          } else {
            fprintf(stderr, "Error!\nNo log file specified\n");
            return 0;
          }
          break;
        case 'h':
        case 'v':
				  print_help(stdout);
          exit_server(&config, ESRAS_STOP);
          break;
      }

    } while (next_option != -1);

    // If none exists, exit failure
    if (config->config_file == NULL) {
      fprintf(stderr, "No configuration file found, please specify a configuration file path\n");
      return 0;
    }

    return 1;
  } else {
    return 0;
  }

}

/**
 * Initialize the application configuration based on the config file content
 * Read the config file, get mandatory variables and devices
 */
int build_config_from_file(struct config_elements * config) {

  config_t cfg;
  config_setting_t * root, * database, * mime_type_list, * mime_type, * oidc_cfg;
  const char * str_value, * str_value_2, * one_log_mode, * db_type, * db_sqlite_path, * db_mariadb_host = NULL, * db_mariadb_user = NULL, * db_pg_conninfo = NULL,
             * db_mariadb_password = NULL, * db_mariadb_dbname = NULL, * extension = NULL, * mime_type_value = NULL, * cur_log_file = NULL;
  int int_value = 0, db_mariadb_port = 0, i = 0, compress = 0, ret;
  char * file_content = NULL;

  config_init(&cfg);

  if (!config_read_file(&cfg, config->config_file)) {
    fprintf(stderr, "Error parsing config file %s\nOn line %d error: %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
    config_destroy(&cfg);
    ret = 0;
  } else {
    ret = 1;
    do {
      root = config_root_setting(&cfg);

      if (config_lookup_int(&cfg, "port", &int_value) == CONFIG_TRUE) {
        config->port = (uint)int_value;
      }

      if (config_lookup_string(&cfg, "index_url", &str_value) == CONFIG_TRUE) {
        o_free(config->index_url);
        if ((config->index_url = o_strdup(str_value)) == NULL) {
          fprintf(stderr, "Error setting config->redirect_uri, exiting\n");
          ret = 0;
          break;
        }
      }

      if (config_lookup_string(&cfg, "api_prefix", &str_value) == CONFIG_TRUE) {
        o_free(config->api_prefix);
        if ((config->api_prefix = o_strdup(str_value)) == NULL) {
          fprintf(stderr, "Error setting config->api_prefix, exiting\n");
          ret = 0;
          break;
        }
      }

      if (config_lookup_string(&cfg, "allow_origin", &str_value) == CONFIG_TRUE) {
        if ((config->allow_origin = o_strdup(str_value)) == NULL) {
          fprintf(stderr, "Error setting config->allow_origin, exiting\n");
          ret = 0;
          break;
        }
      }

      if (config_lookup_string(&cfg, "session_key", &str_value) == CONFIG_TRUE) {
        if ((config->session_key = o_strdup(str_value)) == NULL) {
          fprintf(stderr, "Error setting config->session_key, exiting\n");
          ret = 0;
          break;
        }
      }

      if (config_lookup_string(&cfg, "cookie_domain", &str_value) == CONFIG_TRUE) {
        o_free(config->cookie_domain);
        config->cookie_domain = o_strdup(str_value);
        if (config->cookie_domain == NULL) {
          fprintf(stderr, "Error allocating config->cookie_domain, exiting\n");
          ret = 0;
          break;
        }
      }

      if (config_lookup_int(&cfg, "cookie_secure", &int_value) == CONFIG_TRUE) {
        config->cookie_secure = (uint)int_value;
      }

      if (config_lookup_string(&cfg, "log_mode", &str_value) == CONFIG_TRUE) {
        one_log_mode = strtok((char *)str_value, ",");
        while (one_log_mode != NULL) {
          if (0 == o_strncmp("console", one_log_mode, o_strlen("console"))) {
            config->log_mode |= Y_LOG_MODE_CONSOLE;
          } else if (0 == o_strncmp("syslog", one_log_mode, o_strlen("syslog"))) {
            config->log_mode |= Y_LOG_MODE_SYSLOG;
          } else if (0 == o_strncmp("file", one_log_mode, o_strlen("file"))) {
            config->log_mode |= Y_LOG_MODE_FILE;
            // Get log file path
            if (config_lookup_string(&cfg, "log_file", &cur_log_file)) {
              o_free(config->log_file);
              if ((config->log_file = o_strdup(cur_log_file)) == NULL) {
                fprintf(stderr, "Error allocating config->log_file, exiting\n");
                ret = 0;
                break;
              }
            }
          }
          one_log_mode = strtok(NULL, ",");
        }
      }

      if (config_lookup_string(&cfg, "log_level", &str_value) == CONFIG_TRUE) {
        if (0 == o_strncmp("NONE", str_value, o_strlen("NONE"))) {
          config->log_level = Y_LOG_LEVEL_NONE;
        } else if (0 == o_strncmp("ERROR", str_value, o_strlen("ERROR"))) {
          config->log_level = Y_LOG_LEVEL_ERROR;
        } else if (0 == o_strncmp("WARNING", str_value, o_strlen("WARNING"))) {
          config->log_level = Y_LOG_LEVEL_WARNING;
        } else if (0 == o_strncmp("INFO", str_value, o_strlen("INFO"))) {
          config->log_level = Y_LOG_LEVEL_INFO;
        } else if (0 == o_strncmp("DEBUG", str_value, o_strlen("DEBUG"))) {
          config->log_level = Y_LOG_LEVEL_DEBUG;
        }
      }

      if (config_lookup_int(&cfg, "session_expiration", &int_value) == CONFIG_TRUE) {
        config->session_expiration = (time_t)int_value;
      }

      if (config_lookup_bool(&cfg, "session_extend", &int_value) == CONFIG_TRUE) {
        config->session_extend = int_value;
      }

      if (config_lookup_bool(&cfg, "use_secure_connection", &int_value) == CONFIG_TRUE) {
        if (config_lookup_string(&cfg, "secure_connection_key_file", &str_value) == CONFIG_TRUE &&
            config_lookup_string(&cfg, "secure_connection_pem_file", &str_value_2) == CONFIG_TRUE) {
          config->use_secure_connection = int_value;
          config->secure_connection_key_file = o_strdup(str_value);
          config->secure_connection_pem_file = o_strdup(str_value_2);
        } else {
          fprintf(stderr, "Error secure connection is active but certificate is not valid, exiting\n");
          ret = 0;
          break;
        }
      }

      database = config_setting_get_member(root, "database");
      if (database != NULL) {
        if (config_setting_lookup_string(database, "type", &db_type) == CONFIG_TRUE) {
          if (0 == o_strcmp(db_type, "sqlite3")) {
            if (config_setting_lookup_string(database, "path", &db_sqlite_path) == CONFIG_TRUE) {
              config->conn = h_connect_sqlite(db_sqlite_path);
              if (config->conn == NULL) {
                fprintf(stderr, "Error opening sqlite database %s, exiting\n", db_sqlite_path);
                ret = 0;
                break;
              } else {
                if (h_execute_query_sqlite(config->conn, "PRAGMA foreign_keys = ON;") != H_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "Error executing sqlite3 query 'PRAGMA foreign_keys = ON;, exiting'");
                  ret = 0;
                  break;
                }
              }
            } else {
              fprintf(stderr, "Error - no sqlite database specified\n");
              ret = 0;
              break;
            }
          } else if (0 == o_strcmp(db_type, "mariadb")) {
            config_setting_lookup_string(database, "host", &db_mariadb_host);
            config_setting_lookup_string(database, "user", &db_mariadb_user);
            config_setting_lookup_string(database, "password", &db_mariadb_password);
            config_setting_lookup_string(database, "dbname", &db_mariadb_dbname);
            config_setting_lookup_int(database, "port", &db_mariadb_port);
            config->conn = h_connect_mariadb(db_mariadb_host, db_mariadb_user, db_mariadb_password, db_mariadb_dbname, db_mariadb_port, NULL);
            if (config->conn == NULL) {
              fprintf(stderr, "Error opening mariadb database %s\n", db_mariadb_dbname);
              ret = 0;
              break;
            } else {
              if (h_execute_query_mariadb(config->conn, "SET sql_mode='PIPES_AS_CONCAT';", NULL) != H_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "Error executing mariadb query 'SET sql_mode='PIPES_AS_CONCAT';', exiting");
                ret = 0;
                break;
              }
            }
          } else if (0 == o_strcmp(db_type, "postgre")) {
            config_setting_lookup_string(database, "conninfo", &db_pg_conninfo);
            config->conn = h_connect_pgsql(db_pg_conninfo);
            if (config->conn == NULL) {
              fprintf(stderr, "Error opening postgre database %s, exiting\n", db_pg_conninfo);
              ret = 0;
              break;
            }
          } else {
            fprintf(stderr, "Error - database type unknown\n");
            ret = 0;
            break;
          }
        } else {
          fprintf(stderr, "Error - no database type found\n");
          ret = 0;
          break;
        }
      } else {
        fprintf(stderr, "Error - no database setting found\n");
        ret = 0;
        break;
      }

      if (config_lookup_string(&cfg, "app_files_path", &str_value) == CONFIG_TRUE) {
        config->static_file_config->files_path = o_strdup(str_value);
        if (config->static_file_config->files_path == NULL) {
          fprintf(stderr, "Error allocating config->static_file_config->files_path, exiting\n");
          ret = 0;
          break;
        }
      }

      // Populate mime types u_map
      mime_type_list = config_lookup(&cfg, "app_files_mime_types");
      if (mime_type_list != NULL) {
        for (i=0; i<config_setting_length(mime_type_list); i++) {
          mime_type = config_setting_get_elem(mime_type_list, i);
          if (mime_type != NULL) {
            if (config_setting_lookup_string(mime_type, "extension", &extension) == CONFIG_TRUE &&
                config_setting_lookup_string(mime_type, "mime_type", &mime_type_value) == CONFIG_TRUE) {
              u_map_put(&config->static_file_config->mime_types, extension, mime_type_value);
              if (config_setting_lookup_int(mime_type, "compress", &compress) == CONFIG_TRUE) {
                if (compress && u_add_mime_types_compressed(config->static_file_config, mime_type_value) != U_OK) {
                  fprintf(stderr, "Error setting mime_type %s to compressed list, exiting\n", mime_type_value);
                  ret = 0;
                  break;
                }
              }
            }
          }
        }
      }

      if (config_lookup_string(&cfg, "test_client_redirect_uri", &str_value) == CONFIG_TRUE) {
        config->test_client_redirect_uri = o_strdup(str_value);
        if (config->test_client_redirect_uri == NULL) {
          fprintf(stderr, "Error allocating config->test_client_redirect_uri, exiting\n");
          ret = 0;
          break;
        }
      }

      if (config_lookup_string(&cfg, "test_client_ciba_notification_endpoint", &str_value) == CONFIG_TRUE) {
        config->test_client_ciba_notification_endpoint = o_strdup(str_value);
        if (config->test_client_ciba_notification_endpoint == NULL) {
          fprintf(stderr, "Error allocating config->test_client_ciba_notification_endpoint, exiting\n");
          ret = 0;
          break;
        }
      }

      if (config_lookup_string(&cfg, "test_callback_page", &str_value) == CONFIG_TRUE) {
        o_free(config->test_callback_page);
        config->test_callback_page = o_strdup(str_value);
        if (config->test_callback_page == NULL) {
          fprintf(stderr, "Error allocating config->test_callback_page, exiting\n");
          ret = 0;
          break;
        }
      }

      oidc_cfg = config_lookup(&cfg, "oidc");
      if (config_setting_lookup_string(oidc_cfg, "server_remote_config", &str_value) == CONFIG_TRUE) {
        if ((config->oidc_server_remote_config = o_strdup(str_value)) == NULL) {
          fprintf(stderr, "Error allocating config->oidc_server_remote_config, exiting\n");
          ret = 0;
          break;
        }
      }
      if (config_setting_lookup_bool(oidc_cfg, "server_remote_config_verify_cert", &int_value) == CONFIG_TRUE) {
        config->oidc_server_verify_cert = (unsigned int)int_value;
      }
      if (config_setting_lookup_string(oidc_cfg, "scope", &str_value) == CONFIG_TRUE) {
        if ((config->oidc_scope = o_strdup(str_value)) == NULL) {
          fprintf(stderr, "Error allocating config->oidc_scope, exiting\n");
          ret = 0;
          break;
        }
      }
      if (config_setting_lookup_string(oidc_cfg, "name_claim", &str_value) == CONFIG_TRUE) {
        if ((config->oidc_name_claim = o_strdup(str_value)) == NULL) {
          fprintf(stderr, "Error allocating config->oidc_name_claim, exiting\n");
          ret = 0;
          break;
        }
      }
      if (config_setting_lookup_bool(oidc_cfg, "is_jwt_access_token", &int_value) == CONFIG_TRUE) {
        config->oidc_is_jwt_access_token = (unsigned int)int_value;
      }

      if (config_setting_lookup_string(oidc_cfg, "client_id", &str_value) == CONFIG_TRUE) {
        if ((config->client_id = o_strdup(str_value)) == NULL) {
          fprintf(stderr, "Error allocating config->client_id, exiting\n");
          ret = 0;
          break;
        }
      }
      if (config_setting_lookup_string(oidc_cfg, "client_redirect_uri", &str_value) == CONFIG_TRUE) {
        if ((config->client_redirect_uri = o_strdup(str_value)) == NULL) {
          fprintf(stderr, "Error allocating config->client_redirect_uri, exiting\n");
          ret = 0;
          break;
        }
      }
      if (config_setting_lookup_string(oidc_cfg, "client_secret", &str_value) == CONFIG_TRUE) {
        if ((config->client_secret = o_strdup(str_value)) == NULL) {
          fprintf(stderr, "Error allocating config->client_secret, exiting\n");
          ret = 0;
          break;
        }
      }
      if (config_setting_lookup_string(oidc_cfg, "client_secret_key", &str_value) == CONFIG_TRUE) {
        if ((file_content = get_file_content(str_value)) != NULL) {
          if ((config->client_secret_key = r_jwk_quick_import(R_IMPORT_JSON_STR, file_content)) == NULL) {
            fprintf(stderr, "Error setting client_secret_key file %s, exiting\n", str_value);
            ret = 0;
            break;
          }
        } else {
          fprintf(stderr, "Error invalid client_secret_key file %s, exiting\n", str_value);
          ret = 0;
          break;
        }
      }
      if (config_setting_lookup_string(oidc_cfg, "client_auth_method", &str_value) == CONFIG_TRUE) {
        if (0 == o_strcmp("auth_method_get", str_value)) {
          config->client_auth_method = I_AUTH_METHOD_GET;
        } else if (0 == o_strcmp("auth_method_post", str_value)) {
          config->client_auth_method = I_AUTH_METHOD_POST;
        } else if (0 == o_strcmp("jwt_sign", str_value)) {
          config->client_auth_method = I_AUTH_METHOD_JWT_SIGN_SECRET|I_AUTH_METHOD_JWT_SIGN_PRIVKEY;
        } else {
          fprintf(stderr, "Error invalid client_auth_method, exiting\n");
          ret = 0;
          break;
        }
      }
      if (config_setting_lookup_string(oidc_cfg, "client_token_auth_method", &str_value) == CONFIG_TRUE) {
        if (0 == o_strcmp("client_secret_basic", str_value)) {
          config->client_token_auth_method = I_TOKEN_AUTH_METHOD_SECRET_BASIC;
        } else if (0 == o_strcmp("client_secret_post", str_value)) {
          config->client_token_auth_method = I_TOKEN_AUTH_METHOD_SECRET_POST;
        } else if (0 == o_strcmp("jwt", str_value)) {
          config->client_token_auth_method = I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET|I_TOKEN_AUTH_METHOD_JWT_SIGN_PRIVKEY;
        } else {
          fprintf(stderr, "Error invalid client_token_auth_method, exiting\n");
          ret = 0;
          break;
        }
      }
      if (config_setting_lookup_string(oidc_cfg, "client_sign_alg", &str_value) == CONFIG_TRUE) {
        if ((config->client_sign_alg = o_strdup(str_value)) == NULL) {
          fprintf(stderr, "Error allocating config->client_sign_alg, exiting\n");
          ret = 0;
          break;
        }
      }
      if (config_setting_lookup_string(oidc_cfg, "client_register_scope", &str_value) == CONFIG_TRUE) {
        if ((config->register_scope = o_strdup(str_value)) == NULL) {
          fprintf(stderr, "Error allocating config->register_scope, exiting\n");
          ret = 0;
          break;
        }
      }

    } while (0);
    config_destroy(&cfg);
    o_free(file_content);
  }

  return ret;
}

/**
 * Print help message to output file specified
 */
void print_help(FILE * output) {
  fprintf(output, "\Esras - OAuth2/OIDC client program manager to test or validate OAuth2/OIDC Authentication Server, for multiple users, with database persistence.\n");
  fprintf(output, "\n");
  fprintf(output, "Version %s\n", _ESRAS_VERSION_);
  fprintf(output, "\n");
  fprintf(output, "Copyright 2022 Nicolas Mora <mail@babelouest.io>\n");
  fprintf(output, "\n");
  fprintf(output, "This program is free software; you can redistribute it and/or\n");
  fprintf(output, "modify it under the terms of the GNU GENERAL PUBLIC LICENSE\n");
  fprintf(output, "License as published by the Free Software Foundation;\n");
  fprintf(output, "version 3 of the License.\n");
  fprintf(output, "\n");
  fprintf(output, "Command-line options:\n");
  fprintf(output, "\n");
  fprintf(output, "-c --config-file=PATH\n");
  fprintf(output, "\tPath to configuration file\n");
  fprintf(output, "-p --port=PORT\n");
  fprintf(output, "\tPort to listen to\n");
  fprintf(output, "-u --url-prefix=PREFIX\n");
  fprintf(output, "\tAPI URL prefix\n");
  fprintf(output, "-m --log-mode=MODE\n");
  fprintf(output, "\tLog Mode\n");
  fprintf(output, "\tconsole, syslog or file\n");
  fprintf(output, "\tIf you want multiple modes, separate them with a comma \",\"\n");
  fprintf(output, "\tdefault: console\n");
  fprintf(output, "-l --log-level=LEVEL\n");
  fprintf(output, "\tLog level\n");
  fprintf(output, "\tNONE, ERROR, WARNING, INFO, DEBUG\n");
  fprintf(output, "\tdefault: ERROR\n");
  fprintf(output, "-f --log-file=PATH\n");
  fprintf(output, "\tPath for log file if log mode file is specified\n");
  fprintf(output, "-h --help\n");
  fprintf(output, "-v --version\n");
  fprintf(output, "\tPrint this message\n\n");
}

/**
 * handles signal catch to exit properly when ^C is used for example
 * I don't like global variables but it looks fine to people who designed this
 */
void exit_handler(int signal) {
  y_log_message(Y_LOG_LEVEL_INFO, "Hutch caught a stop or kill signal (%d), exiting", signal);
  pthread_mutex_lock(&global_handler_close_lock);
  pthread_cond_signal(&global_handler_close_cond);
  pthread_mutex_unlock(&global_handler_close_lock);
}

/**
 * Check if all mandatory configuration parameters are present and correct
 * Initialize some parameters with default value if not set
 */
int check_config(struct config_elements * config) {
  int ret = 1;

  do {
    if (!config->port || config->port > 65535) {
      fprintf(stderr, "Invalid port number, exiting\n");
      ret = 0;
      break;
    }

    if (!o_strlen(config->index_url)) {
      fprintf(stderr, "index_url missing, exiting\n");
      ret = 0;
      break;
    }

    if (!o_strlen(config->oidc_server_remote_config)) {
      fprintf(stderr, "oidc parameters invalid, exiting\n");
      ret = 0;
      break;
    }

    if (!o_strlen(config->client_id)) {
      fprintf(stderr, "client_id missing, exiting\n");
      ret = 0;
      break;
    }

    if (!o_strlen(config->test_client_redirect_uri)) {
      fprintf(stderr, "test_client_redirect_uri missing, exiting\n");
      ret = 0;
      break;
    }

    if (!o_strlen(config->test_client_ciba_notification_endpoint)) {
      fprintf(stderr, "test_client_ciba_notification_endpoint missing, exiting\n");
      ret = 0;
      break;
    }

    if (!o_strlen(config->client_redirect_uri)) {
      fprintf(stderr, "client_redirect_uri missing, exiting\n");
      ret = 0;
      break;
    }

    if (!o_strlen(config->client_secret) && config->client_secret_key == NULL) {
      fprintf(stderr, "client_secret or client_secret_key required, exiting\n");
      ret = 0;
      break;
    }

    if (!o_strlen(config->register_scope)) {
      fprintf(stderr, "register_scope missing, exiting\n");
      ret = 0;
      break;
    }

    if ((config->client_auth_method == (I_AUTH_METHOD_JWT_SIGN_SECRET|I_AUTH_METHOD_JWT_SIGN_PRIVKEY) || config->client_token_auth_method == (I_TOKEN_AUTH_METHOD_JWT_SIGN_SECRET|I_TOKEN_AUTH_METHOD_JWT_SIGN_PRIVKEY)) && config->client_sign_alg == NULL) {
      fprintf(stderr, "client_sign_alg required, exiting\n");
      ret = 0;
      break;
    }
  } while (0);

  return ret;
}

/**
 * Return the source ip address of the request
 * Based on the header value "X-Forwarded-For" if set, which means the request is forwarded by a proxy
 * otherwise the call is direct, return the client_address
 */
const char * get_ip_source(const struct _u_request * request) {
  const char * ip_source = u_map_get(request->map_header, "X-Forwarded-For");

  if (ip_source == NULL) {
    struct sockaddr_in * in_source = (struct sockaddr_in *)request->client_address;
    if (in_source != NULL) {
      ip_source = inet_ntoa(in_source->sin_addr);
    } else {
      ip_source = "NOT_FOUND";
    }
  }

  return ip_source;
};

/**
 *
 * Read the content of a file and return it as a char *
 * returned value must be free'd after use
 *
 */
char * get_file_content(const char * file_path) {
  char * buffer = NULL;
  size_t length, res;
  FILE * f;

  f = fopen (file_path, "rb");
  if (f) {
    fseek (f, 0, SEEK_END);
    length = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = o_malloc((length+1)*sizeof(char));
    if (buffer) {
      res = fread (buffer, 1, length, f);
      if (res != length) {
        fprintf(stderr, "fread warning, reading %zu while expecting %zu", res, length);
      }
      // Add null character at the end of buffer, just in case
      buffer[length] = '\0';
    }
    fclose (f);
  }

  return buffer;
}

/**
 * Check if the result json object has a "result" element that is equal to value
 */
int check_result_value(json_t * result, const int value) {
  return (json_is_integer(json_object_get(result, "result")) &&
          json_integer_value(json_object_get(result, "result")) == value);
}

int generate_hash(const char * data, char * output) {
  gnutls_datum_t key_data;
  int ret = 0;
  unsigned char hash[32];
  size_t hash_len = 32, output_len = 0;

  if (data != NULL) {
    key_data.data = (unsigned char *)data;
    key_data.size = o_strlen(data);

    if (gnutls_fingerprint(GNUTLS_DIG_SHA256, &key_data, hash, &hash_len) == GNUTLS_E_SUCCESS) {
      if (o_base64_encode(hash, hash_len, (unsigned char *)output, &output_len)) {
        output[output_len] = '\0';
        ret = 1;
      }
    }
  }
  return ret;
}

/**
 *
 * Generates a random long integer between 0 and max
 *
 */
unsigned char random_at_most(unsigned char max, int nonce) {
  unsigned char
  num_bins = (unsigned char) max + 1,
  num_rand = (unsigned char) 0xff,
  bin_size = num_rand / num_bins,
  defect   = num_rand % num_bins;

  unsigned char x[1];
  do {
    gnutls_rnd(nonce?GNUTLS_RND_NONCE:GNUTLS_RND_KEY, x, sizeof(x));
  }
  // This is carefully written not to overflow
  while (num_rand - defect <= (unsigned char)x[0]);

  // Truncated division is intentional
  return x[0]/bin_size;
}

/**
 * Generates a random string and store it in str
 */
char * rand_string(char * str, size_t str_size) {
  return rand_string_from_charset(str, str_size, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
}

/**
 * Generates a random string and store it in str
 */
char * rand_string_from_charset(char * str, size_t str_size, const char * charset) {
  size_t n;

  if (str_size && str != NULL) {
    for (n = 0; n < str_size; n++) {
      str[n] = charset[random_at_most((o_strlen(charset)) - 2, 0)];
    }
    str[str_size] = '\0';
    return str;
  } else {
    return NULL;
  }
}

int i_session_setup_connection(struct config_elements * config, struct _i_session * i_session) {
  if (i_set_server_configuration(i_session, config->j_server_config) == I_OK &&
      i_set_server_jwks(i_session, config->j_server_jwks) == I_OK &&
      i_set_parameter_list(i_session, I_OPT_CLIENT_ID, config->client_id,
                                      I_OPT_REDIRECT_URI, config->client_redirect_uri,
                                      I_OPT_CLIENT_SECRET, config->client_secret,
                                      I_OPT_AUTH_METHOD, config->client_auth_method,
                                      I_OPT_TOKEN_METHOD, config->client_token_auth_method,
                                      I_OPT_SCOPE, config->oidc_scope,
                                      I_OPT_SCOPE_APPEND, "openid",
                                      I_OPT_NONE) == I_OK) {
    return E_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "i_session_setup_connection - Error initializing i_session");
    return E_ERROR;
  }
}

int i_session_setup_registration(struct config_elements * config, struct _i_session * i_session) {
  if (i_set_server_configuration(i_session, config->j_server_config) == I_OK &&
      i_set_server_jwks(i_session, config->j_server_jwks) == I_OK &&
      i_set_parameter_list(i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CLIENT_CREDENTIALS,
                                      I_OPT_CLIENT_ID, config->client_id,
                                      I_OPT_CLIENT_SECRET, config->client_secret,
                                      I_OPT_AUTH_METHOD, config->client_auth_method,
                                      I_OPT_TOKEN_METHOD, config->client_token_auth_method,
                                      I_OPT_SCOPE, config->register_scope,
                                      I_OPT_NONE) == I_OK) {
    return E_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "i_session_setup_connection - Error initializing i_session");
    return E_ERROR;
  }
}
