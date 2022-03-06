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

json_int_t exec_get_session_id(struct config_elements * config, const char * session_id, json_int_t p_id) {
  json_t * j_query, * j_result;
  int res;
  json_int_t s_id = 0;
  char session_hash[64] = {0};
  
  if (generate_hash(session_id, session_hash)) {
    j_query = json_pack("{sss[s]s{sssI}}",
                        "table", ESRAS_TABLE_SESSION,
                        "columns",
                          "s_id",
                        "where",
                          "s_session_hash", session_hash,
                          "p_id", p_id);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        s_id = json_integer_value(json_object_get(json_array_get(j_result, 0), "s_id"));
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "exec_get_session_id - Error executing j_query");
    }
  }
  return s_id;
}

int exec_set_i_session(struct config_elements * config, const char * session_id, const char * client_id, json_int_t p_id, json_t * j_session) {
  json_t * j_query, * j_cur_session = exec_get_i_session(config, session_id, client_id, p_id), * j_client;
  char * str_session;
  json_int_t s_id;
  int ret, res;
  
  if (check_result_value(j_cur_session, E_OK)) {
    if (!json_is_object(j_session)) {
      j_query = json_pack("{sss{sO}}",
                          "table", ESRAS_TABLE_CLIENT_SESSION,
                          "where",
                            "ecs_id", json_object_get(j_cur_session, "ecs_id"));
      res = h_delete(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        ret = E_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "exec_set_i_session - Error executing j_query (1)");
        ret = E_ERROR;
      }
    } else {
      str_session = json_dumps(j_session, JSON_COMPACT);
      j_query = json_pack("{sss{ss*sO*}s{sO}}",
                          "table", ESRAS_TABLE_CLIENT_SESSION,
                          "set",
                            "ecs_session", str_session,
                            "ecs_state", json_object_get(j_session, "state"),
                          "where",
                            "ecs_id", json_object_get(j_cur_session, "ecs_id"));
      o_free(str_session);
      res = h_update(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        ret = E_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "exec_set_i_session - Error executing j_query (2)");
        ret = E_ERROR;
      }
    }
  } else if (check_result_value(j_cur_session, E_ERROR_NOT_FOUND)) {
    if (json_is_object(j_session)) {
      j_client = get_client(config, client_id, p_id);
      if (check_result_value(j_client, E_OK)) {
        s_id = exec_get_session_id(config, session_id, p_id);
        str_session = json_dumps(j_session, JSON_COMPACT);
        j_query = json_pack("{sss{ss*sO*sIsO}}",
                            "table", ESRAS_TABLE_CLIENT_SESSION,
                            "values",
                              "ecs_session", str_session,
                              "ecs_state", json_object_get(j_session, "state"),
                              "s_id", s_id,
                              "ec_id", json_object_get(json_object_get(j_client, "client"), "ec_id"));
        o_free(str_session);
        res = h_insert(config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          ret = E_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "exec_set_i_session - Error executing j_query (3)");
          ret = E_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "exec_set_i_session - Error get_client");
        ret = E_ERROR;
      }
      json_decref(j_client);
    } else {
      ret = E_OK;
    }
  } else if (check_result_value(j_cur_session, E_ERROR_UNAUTHORIZED)) {
    ret = E_ERROR_UNAUTHORIZED;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "exec_set_i_session - Error exec_get_i_session");
    ret = E_ERROR;
  }
  json_decref(j_cur_session);
  return ret;
}

json_t * exec_get_i_session(struct config_elements * config, const char * session_id, const char * client_id, json_int_t p_id) {
  json_t * j_query, * j_result, * j_client = get_client(config, client_id, p_id), * j_return, * j_session;
  json_int_t s_id = exec_get_session_id(config, session_id, p_id);
  int res;
  
  if (check_result_value(j_client, E_OK)) {
    j_query = json_pack("{sss[sss]s{sIsO}}",
                        "table", ESRAS_TABLE_CLIENT_SESSION,
                        "columns",
                          "ecs_id",
                          "ecs_session",
                          "ecs_state",
                        "where",
                          "s_id", s_id,
                          "ec_id", json_object_get(json_object_get(j_client, "client"), "ec_id"));
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        j_session = json_loads(json_string_value(json_object_get(json_array_get(j_result, 0), "ecs_session")), JSON_DECODE_ANY, NULL);
        if (j_session != NULL) {
          j_return = json_pack("{siso*sO*sIsOsOsO}", "result", E_OK, "session", j_session, "state", json_object_get(json_array_get(j_result, 0), "ecs_state"), "s_id", s_id, "ec_id", json_object_get(json_object_get(j_client, "client"), "ec_id"), "ecs_id", json_object_get(json_array_get(j_result, 0), "ecs_id"), "client", json_object_get(j_client, "client"));
        } else {
          j_return = json_pack("{sis{}sO*sIsOsOsO}", "result", E_OK, "session", "state", json_object_get(json_array_get(j_result, 0), "ecs_state"), "s_id", s_id, "ec_id", json_object_get(json_object_get(j_client, "client"), "ec_id"), "ecs_id", json_object_get(json_array_get(j_result, 0), "ecs_id"), "client", json_object_get(j_client, "client"));
        }
      } else {
        j_return = json_pack("{si}", "result", E_ERROR_NOT_FOUND);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "exec_get_i_session - Error executing j_query");
      j_return = json_pack("{si}", "result", E_ERROR_DB);
    }
  } else if (check_result_value(j_client, E_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", E_ERROR_UNAUTHORIZED);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "exec_get_i_session - Error get_client");
    j_return = json_pack("{si}", "result", E_ERROR);
  }
  json_decref(j_client);
  return j_return;
}

json_t * exec_get_i_session_from_state(struct config_elements * config, const char * session_id, const char * state, json_int_t p_id) {
  json_t * j_query, * j_result, * j_return, * j_session, * j_client;
  json_int_t s_id = exec_get_session_id(config, session_id, p_id);
  int res;
  
  j_query = json_pack("{sss[ssss]s{sIss}}",
                      "table", ESRAS_TABLE_CLIENT_SESSION,
                      "columns",
                        "ecs_id",
                        "ec_id",
                        "ecs_session",
                        "ecs_state",
                      "where",
                        "s_id", s_id,
                        "ecs_state", state);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      j_client = get_client_from_id(config, json_integer_value(json_object_get(json_array_get(j_result, 0), "ec_id")));
      if (check_result_value(j_client, E_OK)) {
        j_session = json_loads(json_string_value(json_object_get(json_array_get(j_result, 0), "ecs_session")), JSON_DECODE_ANY, NULL);
        if (j_session != NULL) {
          j_return = json_pack("{siso*sO*sIsOsO}",
                               "result", E_OK,
                               "session", j_session,
                               "state", json_object_get(json_array_get(j_result, 0), "ecs_state"),
                               "s_id", s_id,
                               "ecs_id", json_object_get(json_array_get(j_result, 0), "ecs_id"),
                               "client", json_object_get(j_client, "client"));
        } else {
          j_return = json_pack("{sis{}sO*sIsOsO}",
                               "result", E_OK,
                               "session",
                               "state", json_object_get(json_array_get(j_result, 0), "ecs_state"),
                               "s_id", s_id,
                               "ecs_id", json_object_get(json_array_get(j_result, 0), "ecs_id"),
                               "client", json_object_get(j_client, "client"));
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "exec_get_i_session_from_state - Error get_client_from_id");
        j_return = json_pack("{si}", "result", E_ERROR);
      }
      json_decref(j_client);
    } else {
      j_return = json_pack("{si}", "result", E_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "exec_get_i_session_from_state - Error executing j_query");
    j_return = json_pack("{si}", "result", E_ERROR_DB);
  }
  return j_return;
}

int exec_generate(struct config_elements * config, const char * session_id, const char * client_id, json_int_t p_id, const char * property) {
  json_t * j_saved_session = exec_get_i_session(config, session_id, client_id, p_id), * j_export_session;
  struct _i_session i_session;
  int ret;
  
  if (check_result_value(j_saved_session, E_OK)) {
    if (i_init_session(&i_session) == I_OK) {
      if (i_import_session_json_t(&i_session, json_object_get(j_saved_session, "session")) == I_OK) {
        if (0 == o_strcmp("nonce", property)) {
          i_set_int_parameter(&i_session, I_OPT_NONCE_GENERATE, 32);
        } else if (0 == o_strcmp("state", property)) {
          i_set_int_parameter(&i_session, I_OPT_STATE_GENERATE, 16);
        } else if (0 == o_strcmp("jti", property)) {
          i_set_int_parameter(&i_session, I_OPT_TOKEN_JTI_GENERATE, 16);
        } else if (0 == o_strcmp("pkce", property)) {
          i_set_int_parameter(&i_session, I_OPT_PKCE_CODE_VERIFIER_GENERATE, 43);
        } else if (0 == o_strcmp("client_notification_token", property)) {
          i_set_int_parameter(&i_session, I_OPT_CIBA_CLIENT_NOTIFICATION_TOKEN_GENERATE, 23);
        }
        j_export_session = i_export_session_json_t(&i_session);
        ret = exec_set_i_session(config, session_id, client_id, p_id, j_export_session);
        json_decref(j_export_session);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "exec_generate - Error i_import_session_json_t");
        ret = E_ERROR;
      }
      i_clean_session(&i_session);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "exec_generate - Error i_init_session");
      ret = E_ERROR;
    }
  } else if (check_result_value(j_saved_session, E_ERROR_UNAUTHORIZED)) {
    ret = E_ERROR_UNAUTHORIZED;
  } else if (check_result_value(j_saved_session, E_ERROR_NOT_FOUND)) {
    ret = E_ERROR_NOT_FOUND;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "exec_generate - Error exec_get_i_session");
    ret = E_ERROR;
  }
  json_decref(j_saved_session);
  return ret;
}

json_t * exec_run_auth(struct config_elements * config, const char * session_id, const char * client_id, json_int_t p_id) {
  json_t * j_saved_session = exec_get_i_session(config, session_id, client_id, p_id), * j_return, * j_session = NULL;
  struct _i_session i_session;
  char * str_request = NULL, * str_response = NULL;
  
  if (check_result_value(j_saved_session, E_OK)) {
    if (json_string_length(json_object_get(j_saved_session, "state"))) {
      if (i_init_session(&i_session) == I_OK) {
        if (i_import_session_json_t(&i_session, json_object_get(j_saved_session, "session")) == I_OK) {
          if (i_set_server_configuration(&i_session, config->j_server_config) == I_OK &&
              i_set_server_jwks(&i_session, config->j_server_jwks) == I_OK &&
              i_import_session_from_registration(&i_session, json_object_get(json_object_get(j_saved_session, "client"), "registration")) == I_OK &&
              i_set_parameter_list(&i_session, I_OPT_REDIRECT_URI, config->test_client_redirect_uri,
                                               I_OPT_SAVE_HTTP_REQUEST_RESPONSE, 1,
                                               I_OPT_ERROR, NULL,
                                               I_OPT_ERROR_DESCRIPTION, NULL,
                                               I_OPT_ERROR_URI, NULL,
                                               I_OPT_NONE) == I_OK) {
            if (i_get_int_parameter(&i_session, I_OPT_AUTH_METHOD) & I_AUTH_METHOD_POST) {
              if (i_run_auth_request(&i_session) == I_OK) {
                if ((j_session = i_export_session_json_t(&i_session)) != NULL &&
                    exec_set_i_session(config, session_id, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID), p_id, j_session) == E_OK) {
                  str_request = ulfius_export_request_http(i_session.saved_request);
                  str_response = ulfius_export_response_http(i_session.saved_response);
                  j_return = json_pack("{sis{ssss*ss*}}", "result", E_OK, "auth", "url", i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO), "request", str_request, "response", str_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_auth - Error saving session");
                  j_return = json_pack("{si}", "result", E_ERROR);
                }
                json_decref(j_session);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_auth - Error i_run_auth_request");
                j_return = json_pack("{si}", "result", E_ERROR);
              }
              o_free(str_request);
              o_free(str_response);
            } else {
              if (i_build_auth_url_get(&i_session) == I_OK) {
                j_return = json_pack("{sis{ss}}", "result", E_OK, "auth", "url", i_get_str_parameter(&i_session, I_OPT_REDIRECT_TO));
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_auth - Error i_build_auth_url_get");
                j_return = json_pack("{si}", "result", E_ERROR);
              }
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_auth - Error setting client parameters");
            j_return = json_pack("{si}", "result", E_ERROR);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_auth - Error i_import_session_json_t");
          j_return = json_pack("{si}", "result", E_ERROR);
        }
        i_clean_session(&i_session);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_auth - Error i_init_session");
        j_return = json_pack("{si}", "result", E_ERROR);
      }
    } else {
      j_return = json_pack("{si}", "result", E_ERROR_PARAM);
    }
  } else if (check_result_value(j_saved_session, E_ERROR_UNAUTHORIZED)) {
    j_return = json_pack("{si}", "result", E_ERROR_UNAUTHORIZED);
  } else if (check_result_value(j_saved_session, E_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", E_ERROR_NOT_FOUND);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_auth - Error exec_get_i_session");
    j_return = json_pack("{si}", "result", E_ERROR);
  }
  return j_return;
}

json_t * exec_parse_callback(struct config_elements * config, const char * session_id, const char * redirect_to, const char * state, json_int_t p_id) {
  json_t * j_saved_session = exec_get_i_session_from_state(config, session_id, state, p_id), * j_return, * j_session = NULL;
  struct _i_session i_session;

  if (check_result_value(j_saved_session, E_OK)) {
    if (i_init_session(&i_session) == I_OK) {
      if (i_import_session_json_t(&i_session, json_object_get(j_saved_session, "session")) == I_OK) {
        if (i_set_server_configuration(&i_session, config->j_server_config) == I_OK &&
            i_set_server_jwks(&i_session, config->j_server_jwks) == I_OK &&
            i_import_session_from_registration(&i_session, json_object_get(json_object_get(j_saved_session, "client"), "registration")) == I_OK &&
            i_set_parameter_list(&i_session, I_OPT_REDIRECT_URI, config->test_client_redirect_uri,
                                             I_OPT_REDIRECT_TO, redirect_to,
                                             I_OPT_SAVE_HTTP_REQUEST_RESPONSE, 1,
                                             I_OPT_ERROR, NULL,
                                             I_OPT_ERROR_DESCRIPTION, NULL,
                                             I_OPT_ERROR_URI, NULL,
                                             I_OPT_NONE) == I_OK &&
            i_parse_redirect_to(&i_session) == I_OK) {
          if ((j_session = i_export_session_json_t(&i_session)) != NULL &&
              exec_set_i_session(config, session_id, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID), p_id, j_session) == E_OK) {
            j_return = json_pack("{siss}", "result", E_OK, "client_id", i_get_str_parameter(&i_session, I_OPT_CLIENT_ID));
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "exec_parse_callback - Error saving session");
            j_return = json_pack("{si}", "result", E_ERROR);
          }
          json_decref(j_session);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "exec_parse_callback - Error parsing redirect_to");
          j_return = json_pack("{si}", "result", E_ERROR);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "exec_parse_callback - Error i_import_session_json_t");
        j_return = json_pack("{si}", "result", E_ERROR);
      }
      i_clean_session(&i_session);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "exec_parse_callback - Error i_init_session");
      j_return = json_pack("{si}", "result", E_ERROR);
    }
  } else if (check_result_value(j_saved_session, E_ERROR_UNAUTHORIZED)) {
    j_return = json_pack("{si}", "result", E_ERROR_UNAUTHORIZED);
  } else if (check_result_value(j_saved_session, E_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", E_ERROR_NOT_FOUND);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "exec_parse_callback - Error exec_get_i_session_from_state");
    j_return = json_pack("{si}", "result", E_ERROR);
  }
  json_decref(j_saved_session);
  return j_return;
}

json_t * exec_run_token(struct config_elements * config, const char * session_id, const char * client_id, json_int_t p_id) {
  json_t * j_saved_session = exec_get_i_session(config, session_id, client_id, p_id), * j_return, * j_session = NULL;
  struct _i_session i_session;
  char * str_request = NULL, * str_response = NULL;
  int res;
  
  if (check_result_value(j_saved_session, E_OK)) {
    if (json_string_length(json_object_get(j_saved_session, "state"))) {
      if (i_init_session(&i_session) == I_OK) {
        if (i_import_session_json_t(&i_session, json_object_get(j_saved_session, "session")) == I_OK) {
          if (i_set_server_configuration(&i_session, config->j_server_config) == I_OK &&
              i_set_server_jwks(&i_session, config->j_server_jwks) == I_OK &&
              i_import_session_from_registration(&i_session, json_object_get(json_object_get(j_saved_session, "client"), "registration")) == I_OK &&
              i_set_parameter_list(&i_session, I_OPT_REDIRECT_URI, config->test_client_redirect_uri,
                                               I_OPT_SAVE_HTTP_REQUEST_RESPONSE, 1,
                                               I_OPT_ERROR, NULL,
                                               I_OPT_ERROR_DESCRIPTION, NULL,
                                               I_OPT_TOKEN_JTI_GENERATE, 16,
                                               I_OPT_ERROR_URI, NULL,
                                               I_OPT_NONE) == I_OK) {
            if ((res = i_run_token_request(&i_session)) == I_OK) {
              if ((j_session = i_export_session_json_t(&i_session)) != NULL &&
                  exec_set_i_session(config, session_id, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID), p_id, j_session) == E_OK) {
                if ((str_request = ulfius_export_request_http(i_session.saved_request)) != NULL && (str_response = ulfius_export_response_http(i_session.saved_response)) != NULL) {
                  j_return = json_pack("{sis{ssss}}", "result", E_OK, "token", "request", str_request, "response", str_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_token - Error exporting request or response");
                  j_return = json_pack("{si}", "result", E_ERROR);
                }
                o_free(str_request);
                o_free(str_response);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_token - Error saving session");
                j_return = json_pack("{si}", "result", E_ERROR);
              }
              json_decref(j_session);
            } else if (res == I_ERROR_PARAM || res == I_ERROR_UNAUTHORIZED) {
              if ((j_session = i_export_session_json_t(&i_session)) != NULL &&
                  exec_set_i_session(config, session_id, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID), p_id, j_session) == E_OK) {
                if ((str_request = ulfius_export_request_http(i_session.saved_request)) != NULL && (str_response = ulfius_export_response_http(i_session.saved_response)) != NULL) {
                  j_return = json_pack("{sis{ssss}}", "result", E_ERROR_PARAM, "token", "request", str_request, "response", str_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_token - Error exporting request or response");
                  j_return = json_pack("{si}", "result", E_ERROR);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_token - Error saving session");
                j_return = json_pack("{si}", "result", E_ERROR);
              }
              json_decref(j_session);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_token - Error i_run_token_request");
              j_return = json_pack("{si}", "result", E_ERROR);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_token - Error setting client parameters");
            j_return = json_pack("{si}", "result", E_ERROR);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_token - Error i_import_session_json_t");
          j_return = json_pack("{si}", "result", E_ERROR);
        }
        i_clean_session(&i_session);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_token - Error i_init_session");
        j_return = json_pack("{si}", "result", E_ERROR);
      }
    } else {
      j_return = json_pack("{si}", "result", E_ERROR_PARAM);
    }
  } else if (check_result_value(j_saved_session, E_ERROR_UNAUTHORIZED)) {
    j_return = json_pack("{si}", "result", E_ERROR_UNAUTHORIZED);
  } else if (check_result_value(j_saved_session, E_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", E_ERROR_NOT_FOUND);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_token - Error exec_get_i_session");
    j_return = json_pack("{si}", "result", E_ERROR);
  }
  return j_return;
}

json_t * exec_run_userinfo(struct config_elements * config, const char * session_id, const char * client_id, int get_jwt, json_int_t p_id) {
  json_t * j_saved_session = exec_get_i_session(config, session_id, client_id, p_id), * j_return, * j_session = NULL;
  struct _i_session i_session;
  char * str_request = NULL, * str_response = NULL;
  int res;
  
  if (check_result_value(j_saved_session, E_OK)) {
    if (json_string_length(json_object_get(j_saved_session, "state"))) {
      if (i_init_session(&i_session) == I_OK) {
        if (i_import_session_json_t(&i_session, json_object_get(j_saved_session, "session")) == I_OK) {
          if (i_set_server_configuration(&i_session, config->j_server_config) == I_OK &&
              i_set_server_jwks(&i_session, config->j_server_jwks) == I_OK &&
              i_import_session_from_registration(&i_session, json_object_get(json_object_get(j_saved_session, "client"), "registration")) == I_OK &&
              i_set_parameter_list(&i_session, I_OPT_REDIRECT_URI, config->test_client_redirect_uri,
                                               I_OPT_SAVE_HTTP_REQUEST_RESPONSE, 1,
                                               I_OPT_ERROR, NULL,
                                               I_OPT_ERROR_DESCRIPTION, NULL,
                                               I_OPT_ERROR_URI, NULL,
                                               I_OPT_TOKEN_JTI_GENERATE, 16,
                                               I_OPT_NONE) == I_OK) {
            if ((res = i_get_userinfo(&i_session, get_jwt)) == I_OK) {
              if ((j_session = i_export_session_json_t(&i_session)) != NULL &&
                  exec_set_i_session(config, session_id, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID), p_id, j_session) == E_OK) {
                if ((str_request = ulfius_export_request_http(i_session.saved_request)) != NULL && (str_response = ulfius_export_response_http(i_session.saved_response)) != NULL) {
                  j_return = json_pack("{sis{ssss}}", "result", E_OK, "userinfo", "request", str_request, "response", str_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_userinfo - Error exporting request or response ok");
                  j_return = json_pack("{si}", "result", E_ERROR);
                }
                o_free(str_request);
                o_free(str_response);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_userinfo - Error saving session");
                j_return = json_pack("{si}", "result", E_ERROR);
              }
              json_decref(j_session);
            } else if (res == I_ERROR_PARAM || res == I_ERROR_UNAUTHORIZED) {
              if ((j_session = i_export_session_json_t(&i_session)) != NULL &&
                  exec_set_i_session(config, session_id, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID), p_id, j_session) == E_OK) {
                if ((str_request = ulfius_export_request_http(i_session.saved_request)) != NULL && (str_response = ulfius_export_response_http(i_session.saved_response)) != NULL) {
                  j_return = json_pack("{sis{ssss}}", "result", E_ERROR_PARAM, "userinfo", "request", str_request, "response", str_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_userinfo - Error exporting request or response error");
                  j_return = json_pack("{si}", "result", E_ERROR);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_userinfo - Error saving session");
                j_return = json_pack("{si}", "result", E_ERROR);
              }
              json_decref(j_session);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_userinfo - Error i_get_userinfo");
              j_return = json_pack("{si}", "result", E_ERROR);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_userinfo - Error setting client parameters");
            j_return = json_pack("{si}", "result", E_ERROR);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_userinfo - Error i_import_session_json_t");
          j_return = json_pack("{si}", "result", E_ERROR);
        }
        i_clean_session(&i_session);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_userinfo - Error i_init_session");
        j_return = json_pack("{si}", "result", E_ERROR);
      }
    } else {
      j_return = json_pack("{si}", "result", E_ERROR_PARAM);
    }
  } else if (check_result_value(j_saved_session, E_ERROR_UNAUTHORIZED)) {
    j_return = json_pack("{si}", "result", E_ERROR_UNAUTHORIZED);
  } else if (check_result_value(j_saved_session, E_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", E_ERROR_NOT_FOUND);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_userinfo - Error exec_get_i_session");
    j_return = json_pack("{si}", "result", E_ERROR);
  }
  return j_return;
}

json_t * exec_run_introspection(struct config_elements * config, const char * session_id, const char * client_id, int get_jwt, json_int_t p_id) {
  json_t * j_saved_session = exec_get_i_session(config, session_id, client_id, p_id), * j_return, * j_session = NULL, * j_result = NULL;
  struct _i_session i_session;
  char * str_request = NULL, * str_response = NULL;
  int res;
  
  if (check_result_value(j_saved_session, E_OK)) {
    if (json_string_length(json_object_get(j_saved_session, "state"))) {
      if (i_init_session(&i_session) == I_OK) {
        if (i_import_session_json_t(&i_session, json_object_get(j_saved_session, "session")) == I_OK) {
          if (i_set_server_configuration(&i_session, config->j_server_config) == I_OK &&
              i_set_server_jwks(&i_session, config->j_server_jwks) == I_OK &&
              i_import_session_from_registration(&i_session, json_object_get(json_object_get(j_saved_session, "client"), "registration")) == I_OK &&
              i_set_parameter_list(&i_session, I_OPT_REDIRECT_URI, config->test_client_redirect_uri,
                                               I_OPT_SAVE_HTTP_REQUEST_RESPONSE, 1,
                                               I_OPT_ERROR, NULL,
                                               I_OPT_ERROR_DESCRIPTION, NULL,
                                               I_OPT_ERROR_URI, NULL,
                                               I_OPT_TOKEN_JTI_GENERATE, 16,
                                               I_OPT_NONE) == I_OK) {
            if ((res = i_get_token_introspection(&i_session, &j_result, I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET, get_jwt)) == I_OK) {
              if ((j_session = i_export_session_json_t(&i_session)) != NULL &&
                  exec_set_i_session(config, session_id, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID), p_id, j_session) == E_OK) {
                if ((str_request = ulfius_export_request_http(i_session.saved_request)) != NULL && (str_response = ulfius_export_response_http(i_session.saved_response)) != NULL) {
                  j_return = json_pack("{sis{sOssss}}", "result", E_OK, "introspection", "result", j_result, "request", str_request, "response", str_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_introspection - Error exporting request or response ok");
                  j_return = json_pack("{si}", "result", E_ERROR);
                }
                o_free(str_request);
                o_free(str_response);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_introspection - Error saving session");
                j_return = json_pack("{si}", "result", E_ERROR);
              }
              json_decref(j_session);
            } else if (res == I_ERROR_PARAM || res == I_ERROR_UNAUTHORIZED) {
              if ((j_session = i_export_session_json_t(&i_session)) != NULL &&
                  exec_set_i_session(config, session_id, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID), p_id, j_session) == E_OK) {
                if ((str_request = ulfius_export_request_http(i_session.saved_request)) != NULL && (str_response = ulfius_export_response_http(i_session.saved_response)) != NULL) {
                  j_return = json_pack("{sis{ssss}}", "result", E_ERROR_PARAM, "introspection", "request", str_request, "response", str_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_introspection - Error exporting request or response error");
                  j_return = json_pack("{si}", "result", E_ERROR);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_introspection - Error saving session");
                j_return = json_pack("{si}", "result", E_ERROR);
              }
              json_decref(j_session);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_introspection - Error i_get_token_introspection");
              j_return = json_pack("{si}", "result", E_ERROR);
            }
            json_decref(j_result);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_introspection - Error setting client parameters");
            j_return = json_pack("{si}", "result", E_ERROR);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_introspection - Error i_import_session_json_t");
          j_return = json_pack("{si}", "result", E_ERROR);
        }
        i_clean_session(&i_session);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_introspection - Error i_init_session");
        j_return = json_pack("{si}", "result", E_ERROR);
      }
    } else {
      j_return = json_pack("{si}", "result", E_ERROR_PARAM);
    }
  } else if (check_result_value(j_saved_session, E_ERROR_UNAUTHORIZED)) {
    j_return = json_pack("{si}", "result", E_ERROR_UNAUTHORIZED);
  } else if (check_result_value(j_saved_session, E_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", E_ERROR_NOT_FOUND);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_introspection - Error exec_get_i_session");
    j_return = json_pack("{si}", "result", E_ERROR);
  }
  return j_return;
}

json_t * exec_run_revocation(struct config_elements * config, const char * session_id, const char * client_id, json_int_t p_id) {
  json_t * j_saved_session = exec_get_i_session(config, session_id, client_id, p_id), * j_return, * j_session = NULL;
  struct _i_session i_session;
  char * str_request = NULL, * str_response = NULL;
  int res;
  
  if (check_result_value(j_saved_session, E_OK)) {
    if (json_string_length(json_object_get(j_saved_session, "state"))) {
      if (i_init_session(&i_session) == I_OK) {
        if (i_import_session_json_t(&i_session, json_object_get(j_saved_session, "session")) == I_OK) {
          if (i_set_server_configuration(&i_session, config->j_server_config) == I_OK &&
              i_set_server_jwks(&i_session, config->j_server_jwks) == I_OK &&
              i_import_session_from_registration(&i_session, json_object_get(json_object_get(j_saved_session, "client"), "registration")) == I_OK &&
              i_set_parameter_list(&i_session, I_OPT_REDIRECT_URI, config->test_client_redirect_uri,
                                               I_OPT_SAVE_HTTP_REQUEST_RESPONSE, 1,
                                               I_OPT_ERROR, NULL,
                                               I_OPT_ERROR_DESCRIPTION, NULL,
                                               I_OPT_ERROR_URI, NULL,
                                               I_OPT_TOKEN_JTI_GENERATE, 16,
                                               I_OPT_NONE) == I_OK) {
            if ((res = i_revoke_token(&i_session, I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET)) == I_OK) {
              if ((j_session = i_export_session_json_t(&i_session)) != NULL &&
                  exec_set_i_session(config, session_id, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID), p_id, j_session) == E_OK) {
                if ((str_request = ulfius_export_request_http(i_session.saved_request)) != NULL && (str_response = ulfius_export_response_http(i_session.saved_response)) != NULL) {
                  j_return = json_pack("{sis{ssss}}", "result", E_OK, "introspection", "request", str_request, "response", str_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_revocation - Error exporting request or response ok");
                  j_return = json_pack("{si}", "result", E_ERROR);
                }
                o_free(str_request);
                o_free(str_response);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_revocation - Error saving session");
                j_return = json_pack("{si}", "result", E_ERROR);
              }
              json_decref(j_session);
            } else if (res == I_ERROR_PARAM || res == I_ERROR_UNAUTHORIZED) {
              if ((j_session = i_export_session_json_t(&i_session)) != NULL &&
                  exec_set_i_session(config, session_id, i_get_str_parameter(&i_session, I_OPT_CLIENT_ID), p_id, j_session) == E_OK) {
                if ((str_request = ulfius_export_request_http(i_session.saved_request)) != NULL && (str_response = ulfius_export_response_http(i_session.saved_response)) != NULL) {
                  j_return = json_pack("{sis{ssss}}", "result", E_ERROR_PARAM, "introspection", "request", str_request, "response", str_response);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_revocation - Error exporting request or response error");
                  j_return = json_pack("{si}", "result", E_ERROR);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_revocation - Error saving session");
                j_return = json_pack("{si}", "result", E_ERROR);
              }
              json_decref(j_session);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_revocation - Error i_revoke_token");
              j_return = json_pack("{si}", "result", E_ERROR);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_revocation - Error setting client parameters");
            j_return = json_pack("{si}", "result", E_ERROR);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_revocation - Error i_import_session_json_t");
          j_return = json_pack("{si}", "result", E_ERROR);
        }
        i_clean_session(&i_session);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_revocation - Error i_init_session");
        j_return = json_pack("{si}", "result", E_ERROR);
      }
    } else {
      j_return = json_pack("{si}", "result", E_ERROR_PARAM);
    }
  } else if (check_result_value(j_saved_session, E_ERROR_UNAUTHORIZED)) {
    j_return = json_pack("{si}", "result", E_ERROR_UNAUTHORIZED);
  } else if (check_result_value(j_saved_session, E_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", E_ERROR_NOT_FOUND);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "exec_run_revocation - Error exec_get_i_session");
    j_return = json_pack("{si}", "result", E_ERROR);
  }
  return j_return;
}
