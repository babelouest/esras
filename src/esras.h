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
#include <ulfius.h>
#include <yder.h>
#include <hoel.h>

#include "iddawc_resource.h"
#include "static_compressed_inmemory_website_callback.h"
#include "http_compression_callback.h"

#define ESRAS_DEFAULT_PORT   3777
#define ESRAS_DEFAULT_PREFIX "api"
#define ESRAS_LOG_NAME       "ESRAS"

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
  char                                         * external_url;
  char                                         * api_prefix;
  unsigned long                                  log_mode;
  unsigned long                                  log_level;
  char                                         * log_file;
  char                                         * allow_origin;
  unsigned int                                   use_secure_connection;
  char                                         * secure_connection_key_file;
  char                                         * secure_connection_pem_file;
  char                                         * oidc_server_remote_config;
  unsigned int                                   oidc_server_remote_config_verify_cert;
  char                                         * oidc_server_public_jwks;
  char                                         * oidc_scope;
  char                                         * oidc_iss;
  char                                         * oidc_realm;
  char                                         * oidc_aud;
  time_t                                         oidc_dpop_max_iat;
  struct _h_connection                         * conn;
  struct _u_instance                           * instance;
  struct _iddawc_resource_config               * iddawc_resource_config;
	struct _u_compressed_inmemory_website_config * static_file_config;
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

int check_result_value(json_t * result, const int value);

int callback_esras_options (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_esras_server_configuration (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_default (const struct _u_request * request, struct _u_response * response, void * user_data);
int callback_404_if_necessary (const struct _u_request * request, struct _u_response * response, void * user_data);

#endif
