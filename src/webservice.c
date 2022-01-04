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

#include "esras.h"

/**
 * OPTIONS callback function
 * Send mandatory parameters for browsers to call REST APIs
 */
int callback_esras_options (const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  UNUSED(user_data);
  ulfius_set_response_properties(response, U_OPT_STATUS, 200,
                                           U_OPT_HEADER_PARAMETER, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS",
                                           U_OPT_HEADER_PARAMETER, "Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Bearer, Authorization",
                                           U_OPT_HEADER_PARAMETER, "Access-Control-Max-Age", "1800",
                                           U_OPT_NONE);
  return U_CALLBACK_COMPLETE;
}

/**
 * api description endpoint
 * send the location of prefixes
 */
int callback_esras_server_configuration (const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  struct config_elements * config = (struct config_elements *)user_data;
  return U_CALLBACK_CONTINUE;
};

int callback_default (const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  UNUSED(user_data);
  json_t * json_body = json_pack("{ssss}", "error", "resource not found", "message", "no resource available at this address");
  ulfius_set_json_body_response(response, 404, json_body);
  json_decref(json_body);
  return U_CALLBACK_CONTINUE;
}

int callback_404_if_necessary (const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(user_data);
  if (!request->callback_position) {
    response->status = 404;
  }
  return U_CALLBACK_COMPLETE;
}
