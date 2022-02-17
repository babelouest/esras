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

int callback_esras_check_session (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  int ret = U_CALLBACK_IGNORE;
  json_t * j_session = check_session(config, u_map_get(request->map_cookie, config->session_key)), * j_result;
  char expires[129];
  time_t now;
  struct tm ts;

  time(&now);
  now += config->session_expiration;
  gmtime_r(&now, &ts);
  strftime(expires, 128, "%a, %d %b %Y %T %Z", &ts);
  if (check_result_value(j_session, E_ERROR_UNAUTHORIZED) || check_result_value(j_session, E_ERROR_NOT_FOUND)) {
    j_result = init_session(config, u_map_get(request->map_cookie, config->session_key), check_result_value(j_session, E_ERROR_NOT_FOUND));
    if (check_result_value(j_result, E_OK)) {
      ulfius_add_cookie_to_response(response, config->session_key, json_string_value(json_object_get(json_object_get(j_result, "session"), "session_id")), expires, 0, config->cookie_domain, "/", config->cookie_secure, 0);
      u_map_put(response->map_header, "Location", json_string_value(json_object_get(json_object_get(j_result, "session"), "auth_url")));
      response->status = 302;

      // Uncomment this line if you're working on the frontend
      y_log_message(Y_LOG_LEVEL_DEBUG, "redirect %s", json_string_value(json_object_get(json_object_get(j_result, "session"), "auth_url")));

      ret = U_CALLBACK_COMPLETE;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_esras_check_session - Error init_session");
      ret = U_CALLBACK_ERROR;
    }
    json_decref(j_result);
  } else if (check_result_value(j_session, E_OK)) {
    ulfius_set_response_shared_data(response, json_incref(json_object_get(j_session, "session")), (void (*)(void *))&json_decref);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_esras_check_session - Error check_session");
    ret = U_CALLBACK_ERROR;
  }
  json_decref(j_session);
  return ret;
}

int callback_esras_delete_session (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  time_t now;
  struct tm ts;
  char expires[129];

  time(&now);
  gmtime_r(&now, &ts);
  strftime(expires, 128, "%a, %d %b %Y %T %Z", &ts);
  if (delete_session(config, u_map_get(request->map_cookie, config->session_key)) != E_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_dagda_delete_session - Error delete_session");
    response->status = 500;
  }
  ulfius_add_cookie_to_response(response, config->session_key, "", expires, 0, config->cookie_domain, "/", config->cookie_secure, 0);
  return U_CALLBACK_CONTINUE;
}

int callback_esras_callback_url (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  int res;

  if (o_strlen(u_map_get(request->map_url, "code")) &&
      o_strlen(u_map_get(request->map_url, "state")) &&
      o_strlen(u_map_get(request->map_cookie, config->session_key)) == ESRAS_SESSION_LENGTH) {
    if ((res = validate_session_code(config, u_map_get(request->map_cookie, config->session_key), u_map_get(request->map_url, "state"), u_map_get(request->map_url, "code"))) == E_OK) {
      u_map_put(response->map_header, "Location", config->index_url);
      response->status = 302;
    } else if (res == E_ERROR_UNAUTHORIZED) {
      ulfius_set_string_body_response(response, 400, "Invalid request");
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_esras_callback_url - Error validate_session_code");
      response->status = 500;
    }
  } else {
    ulfius_set_string_body_response(response, 400, "Invalid request");
  }
  return U_CALLBACK_COMPLETE;
}

int callback_esras_profile (const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  UNUSED(user_data);
  ulfius_set_json_body_response(response, 200, (json_t *)response->shared_data);
  return U_CALLBACK_CONTINUE;
}

int callback_esras_list_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_list_client = list_client(config, json_integer_value(json_object_get((json_t *)response->shared_data, "p_id")));

  if (check_result_value(j_list_client, E_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_list_client, "client"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_esras_list_client - Error list_client");
  }
  json_decref(j_list_client);
  return U_CALLBACK_CONTINUE;
}

int callback_esras_add_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_client = ulfius_get_json_body_request(request, NULL), * j_result;
  
  if (!pthread_mutex_lock(&config->i_session_lock)) {
    if (is_client_registration_valid(j_client) == I_OK) {
      j_result = register_client(config, j_client);
      if (check_result_value(j_result, E_OK)) {
        if (add_client(config, json_object_get(j_result, "registration"), json_integer_value(json_object_get((json_t *)response->shared_data, "p_id"))) != E_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_esras_add_client - Error add_client");
          response->status = 500;
        }
      } else if (check_result_value(j_result, E_ERROR_PARAM)) {
        response->status = 400;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_esras_add_client - Error register_client");
        response->status = 500;
      }
      json_decref(j_result);
    } else {
      response->status = 400;
    }
    pthread_mutex_unlock(&config->i_session_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_esras_add_client - Error pthread_mutex_lock");
    response->status = 500;
  }
  json_decref(j_client);

  return U_CALLBACK_CONTINUE;
}

int callback_esras_set_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_client = ulfius_get_json_body_request(request, NULL), * j_result, * j_client_database = get_client(config, u_map_get(request->map_url, "client_id"), json_integer_value(json_object_get((json_t *)response->shared_data, "p_id")));
  
  if (check_result_value(j_client_database, E_OK)) {
    if (is_client_registration_valid(j_client) == I_OK) {
      j_result = update_client_registration(config, json_object_get(j_client_database, "client"), j_client);
      if (check_result_value(j_result, E_OK)) {
        if (set_client(config, json_object_get(j_result, "registration"), json_integer_value(json_object_get(json_object_get(j_client_database, "client"), "ec_id"))) != E_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_esras_add_client - Error add_client");
          response->status = 500;
        }
      } else if (check_result_value(j_result, E_ERROR_PARAM)) {
        response->status = 400;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_esras_set_client - Error update_client_registration");
        response->status = 500;
      }
      json_decref(j_result);
    } else {
      response->status = 400;
    }
  } else if (check_result_value(j_client_database, E_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_esras_set_client - Error get_client");
    response->status = 500;
  }
  json_decref(j_client);
  json_decref(j_client_database);

  return U_CALLBACK_CONTINUE;
}

int callback_esras_disable_client (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct config_elements * config = (struct config_elements *)user_data;
  json_t * j_client_database = get_client(config, u_map_get(request->map_url, "client_id"), json_integer_value(json_object_get((json_t *)response->shared_data, "p_id")));
  int res;

  if (check_result_value(j_client_database, E_OK)) {
    if ((res = disable_client_registration(config, json_object_get(j_client_database, "client"))) == E_OK) {
      if (disable_client(config, json_integer_value(json_object_get(json_object_get(j_client_database, "client"), "ec_id"))) != E_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_esras_disable_client - Error disable_client");
        response->status = 500;
      }
    } else if (res == E_ERROR_PARAM) {
      response->status = 400;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_esras_disable_client - Error disable_client_registration");
      response->status = 500;
    }
  } else if (check_result_value(j_client_database, E_ERROR_NOT_FOUND)) {
    response->status = 404;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_esras_disable_client - Error get_client");
    response->status = 500;
  }
  json_decref(j_client_database);

  return U_CALLBACK_CONTINUE;
}
