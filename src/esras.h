/**
 *
 * esras: OAuth2/OIDC client program to test or validate OAuth2/OIDC AS
 * for multiple users, with database persistence - AKA idwcc on steroids
 * 
 * Declarations for constants and prototypes
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

#ifndef __ESRAS_H_
#define __ESRAS_H_

#define _ESRAS_VERSION_ "0.0.1"

/** Angharad libraries **/
#include <yder.h>
#include <ulfius.h>
#include <hoel.h>
#include <rhonabwy.h>
#include <iddawc.h>

#include "static_compressed_inmemory_website_callback.h"
#include "http_compression_callback.h"

#define ESRAS_DEFAULT_PORT               3777
#define ESRAS_DEFAULT_PREFIX             "api"
#define ESRAS_DEFAULT_INDEX              "index.html"
#define ESRAS_DEFAULT_SESSION_EXPIRATION 604800
#define ESRAS_SESSION_LENGTH             128
#define ESRAS_LOG_NAME                   "ESRAS"
#define ESRAS_DEFAULT_TOKEN_EXPIRE       3600

#define ESRAS_TABLE_PROFILE             "e_profile"
#define ESRAS_TABLE_SESSION             "e_session"
#define ESRAS_TABLE_CLIENT              "e_client"
#define ESRAS_TABLE_CLIENT_REDIRECT_URI "e_client_redirect_uri"

#define ESRAS_STOP     0
#define ESRAS_ERROR    1

#define ESRAS_CALLBACK_PRIORITY_ZERO           0
#define ESRAS_CALLBACK_PRIORITY_AUTHENTICATION 1
#define ESRAS_CALLBACK_PRIORITY_APPLICATION    2
#define ESRAS_CALLBACK_PRIORITY_FILE           3
#define ESRAS_CALLBACK_PRIORITY_POST_FILE      4
#define ESRAS_CALLBACK_PRIORITY_COMPRESSION    5

#define E_OK                 0
#define E_ERROR              1
#define E_ERROR_UNAUTHORIZED 2
#define E_ERROR_PARAM        3
#define E_ERROR_DB           4
#define E_ERROR_MEMORY       5
#define E_ERROR_NOT_FOUND	   6

#define SWITCH_DB_TYPE(T, M, S, P) \
        ((T)==HOEL_DB_TYPE_MARIADB?\
           (M):\
         (T)==HOEL_DB_TYPE_SQLITE?\
           (S):\
           (P)\
        )

/** Macro to avoid compiler warning when some parameters are unused and that's ok **/
#define UNUSED(x) (void)(x)

struct config_elements {
  char                                         * config_file;
  unsigned int                                   port;
  char                                         * api_prefix;
  char                                         * index_url;
  unsigned long                                  log_mode;
  unsigned long                                  log_level;
  char                                         * log_file;
  char                                         * allow_origin;
  unsigned int                                   use_secure_connection;
  char                                         * secure_connection_key_file;
  char                                         * secure_connection_pem_file;
  char                                         * session_key;
  time_t                                         session_expiration;
  char                                         * cookie_domain;
  unsigned int                                   cookie_secure;
  char                                         * oidc_server_remote_config;
  char                                         * oidc_server_auth_endpoint;
  char                                         * oidc_server_token_endpoint;
  unsigned int                                   oidc_server_verify_cert;
  char                                         * oidc_server_public_jwks;
  char                                         * oidc_scope;
  char                                         * oidc_iss;
  char                                         * oidc_realm;
  char                                         * oidc_aud;
  time_t                                         oidc_dpop_max_iat;
  char                                         * oidc_name_claim;
  unsigned int                                   oidc_is_jwt_access_token;
  char                                         * client_id;
  char                                         * client_redirect_uri;
  char                                         * client_secret;
  jwk_t                                        * client_secret_key;
  unsigned int                                   client_auth_method;
  unsigned int                                   client_token_auth_method;
  char                                         * client_sign_alg;
  struct _h_connection                         * conn;
  struct _u_instance                           * instance;
	struct _u_compressed_inmemory_website_config * static_file_config;
  struct _i_session                            * i_session;
  pthread_mutex_t                                i_session_lock;
};

// Main functions and misc functions
int  build_config_from_args(int argc, char ** argv, struct config_elements * config);
int  build_config_from_file(struct config_elements * config);
int  check_config(struct config_elements * config);
void exit_handler(int handler);
void exit_server(struct config_elements ** config, int exit_value);
void print_help(FILE * output);
const char * get_filename_ext(const char *path);
char * get_file_content(const char * file_path);
char * url_decode(char *str);
char * url_encode(char *str);
const char * get_ip_source(const struct _u_request * request);
int generate_hash(const char * data, char * output);
char * rand_string(char * str, size_t str_size);
char * rand_string_from_charset(char * str, size_t str_size, const char * charset);

int check_result_value(json_t * result, const int value);

json_t * check_session(struct config_elements * config, const char * session_id);
json_t * init_session(struct config_elements * config, const char * cur_session_id, int create);
int validate_session_code(struct config_elements * config, const char * session_id, const char * state, const char * code);

json_t * list_client(struct config_elements * config, json_int_t ep_id);

int callback_esras_options (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_default (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_404_if_necessary (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_esras_check_session (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_esras_callback_url (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_esras_profile (const struct _u_request * request, struct _u_response * response, void * user_data);

int callback_esras_list_client (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_esras_add_client (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_esras_set_client (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_esras_disable_client (const struct _u_request * request, struct _u_response * response, void * user_data);

#endif
