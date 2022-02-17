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

json_t * list_client(struct config_elements * config, json_int_t p_id) {
  json_t * j_query, * j_result, * j_result_ru, * j_return, * j_element = NULL, * j_element_ru = NULL;
  int res;
  size_t index = 0, index_ru = 0;

  j_query = json_pack("{sss[ssssssss]s{sI}}",
                      "table", ESRAS_TABLE_CLIENT,
                      "columns",
                        "ec_id",
                        "ec_name AS name",
                        "ec_enabled",
                        "ec_client_id AS client_id",
                        "ec_client_secret AS client_secret",
                        "ec_registration_access_token AS registration_access_token",
                        "ec_registration_client_uri AS registration_client_uri",
                        "ec_registration",
                      "where",
                        "p_id", p_id);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      json_object_set(j_element, "enabled", json_integer_value(json_object_get(j_element, "ec_enabled"))?json_true():json_false());
      json_object_set_new(j_element, "registration", json_loads(json_string_value(json_object_get(j_element, "ec_registration")), JSON_DECODE_ANY, NULL));
      json_object_del(j_element, "ec_enabled");
      json_object_del(j_element, "ec_registration");
      j_query = json_pack("{sss[s]s{sO}}",
                          "table", ESRAS_TABLE_CLIENT_REDIRECT_URI,
                          "columns",
                            "ecru_redirect_uri",
                          "where",
                            "ec_id", json_object_get(j_element, "ec_id"));
      res = h_select(config->conn, j_query, &j_result_ru, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        json_object_set_new(j_element, "redirect_uris", json_array());
        json_array_foreach(j_result_ru, index_ru, j_element_ru) {
          json_array_append(json_object_get(j_element, "redirect_uris"), json_object_get(j_element_ru, "ecru_redirect_uri"));
        }
        json_decref(j_result_ru);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "list_client - Error executing j_query for client %s", json_string_value(json_object_get(j_element, "name")));
      }
    }
    j_return = json_pack("{siso}", "result", E_OK, "client", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "list_client - Error executing j_query");
    j_return = json_pack("{si}", "result", E_ERROR_DB);
  }
  return j_return;
}

json_t * get_client(struct config_elements * config, const char * client_id, json_int_t p_id) {
  json_t * j_query, * j_result, * j_result_ru, * j_return, * j_element_ru = NULL;
  int res;
  size_t index_ru = 0;

  j_query = json_pack("{sss[ssssssss]s{sIss}}",
                      "table", ESRAS_TABLE_CLIENT,
                      "columns",
                        "ec_id",
                        "ec_name AS name",
                        "ec_enabled",
                        "ec_client_id AS client_id",
                        "ec_client_secret AS client_secret",
                        "ec_registration_access_token AS registration_access_token",
                        "ec_registration_client_uri AS registration_client_uri",
                        "ec_registration",
                      "where",
                        "p_id", p_id,
                        "ec_client_id", client_id);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      json_object_set(json_array_get(j_result, 0), "enabled", json_integer_value(json_object_get(json_array_get(j_result, 0), "ec_enabled"))?json_true():json_false());
      json_object_set_new(json_array_get(j_result, 0), "registration", json_loads(json_string_value(json_object_get(json_array_get(j_result, 0), "ec_registration")), JSON_DECODE_ANY, NULL));
      json_object_del(json_array_get(j_result, 0), "ec_enabled");
      json_object_del(json_array_get(j_result, 0), "ec_registration");
      j_query = json_pack("{sss[s]s{sO}}",
                          "table", ESRAS_TABLE_CLIENT_REDIRECT_URI,
                          "columns",
                            "ecru_redirect_uri",
                          "where",
                            "ec_id", json_object_get(json_array_get(j_result, 0), "ec_id"));
      res = h_select(config->conn, j_query, &j_result_ru, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        json_object_set_new(json_array_get(j_result, 0), "redirect_uris", json_array());
        json_array_foreach(j_result_ru, index_ru, j_element_ru) {
          json_array_append(json_object_get(json_array_get(j_result, 0), "redirect_uris"), json_object_get(j_element_ru, "ecru_redirect_uri"));
        }
        json_decref(j_result_ru);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "list_client - Error executing j_query for client %s", json_string_value(json_object_get(json_array_get(j_result, 0), "name")));
      }
      j_return = json_pack("{sisO}", "result", E_OK, "client", json_array_get(j_result, 0));
    } else {
      j_return = json_pack("{si}", "result", E_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "list_client - Error executing j_query");
    j_return = json_pack("{si}", "result", E_ERROR_DB);
  }
  return j_return;
}

int add_client(struct config_elements * config, json_t * j_client, json_int_t p_id) {
  json_t * j_query, * j_ec_id, * j_element = NULL;
  int res, ret;
  char * registration = json_dumps(j_client, JSON_COMPACT);
  size_t index = 0;

  j_query = json_pack("{sss{sIsO*sO*sO*sO*sO*ss}}",
                      "table", ESRAS_TABLE_CLIENT,
                      "values",
                        "p_id", p_id,
                        "ec_name", json_object_get(j_client, "name"),
                        "ec_client_id", json_object_get(j_client, "client_id"),
                        "ec_client_secret", json_object_get(j_client, "client_secret"),
                        "ec_registration_access_token", json_object_get(j_client, "registration_access_token"),
                        "ec_registration_client_uri", json_object_get(j_client, "registration_client_uri"),
                        "ec_registration", registration);
  res = h_insert(config->conn, j_query, NULL);
  o_free(registration);
  json_decref(j_query);
  if (res == H_OK) {
    j_ec_id = h_last_insert_id(config->conn);
    if (j_ec_id != NULL) {
      j_query = json_pack("{sss[]}", "table", ESRAS_TABLE_CLIENT_REDIRECT_URI, "values");
      json_array_foreach(json_object_get(j_client, "redirect_uris"), index, j_element) {
        json_array_append_new(json_object_get(j_query, "values"), json_pack("{sOsO}", "ec_id", j_ec_id, "ecru_redirect_uri", j_element));
      }
      res = h_insert(config->conn, j_query, NULL);
      json_decref(j_query);
      json_decref(j_ec_id);
      if (res == H_OK) {
        ret = E_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_client - Error executing j_query (2)");
        ret = E_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_client - Error h_last_insert_id");
      ret = E_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "add_client - Error executing j_query (1)");
    ret = E_ERROR_DB;
  }
  return ret;
}

int set_client(struct config_elements * config, json_t * j_client, json_int_t ec_id) {
  json_t * j_query, * j_element = NULL;
  int res, ret;
  char * registration = json_dumps(j_client, JSON_COMPACT);
  size_t index = 0;

  j_query = json_pack("{sss{sOss}s{sI}}",
                      "table", ESRAS_TABLE_CLIENT,
                      "set",
                        "ec_name", json_object_get(j_client, "name"),
                        "ec_registration", registration,
                      "where",
                        "ec_id", ec_id);
  res = h_update(config->conn, j_query, NULL);
  o_free(registration);
  json_decref(j_query);
  if (res == H_OK) {
    j_query = json_pack("{sss{sI}}", "table", ESRAS_TABLE_CLIENT_REDIRECT_URI, "where", "ec_id", ec_id);
    res = h_delete(config->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      j_query = json_pack("{sss[]}", "table", ESRAS_TABLE_CLIENT_REDIRECT_URI, "values");
      json_array_foreach(json_object_get(j_client, "redirect_uris"), index, j_element) {
        json_array_append_new(json_object_get(j_query, "values"), json_pack("{sIsO}", "ec_id", ec_id, "ecru_redirect_uri", j_element));
      }
      res = h_insert(config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        ret = E_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_client - Error executing j_query (3)");
        ret = E_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "set_client - Error executing j_query (2)");
      ret = E_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_client - Error executing j_query (1)");
    ret = E_ERROR_DB;
  }
  return ret;
}

int disable_client(struct config_elements * config, json_int_t ec_id) {
  json_t * j_query;
  int res, ret;

  j_query = json_pack("{sss{si}s{sI}}",
                      "table", ESRAS_TABLE_CLIENT,
                      "set",
                        "ec_enabled", 0,
                      "where",
                        "ec_id", ec_id);
  res = h_update(config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = E_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "disable_client - Error executing j_query");
    ret = E_ERROR_DB;
  }
  return ret;
}

int is_client_registration_valid(json_t * j_client) {
  int ret = I_OK;
  
  do {
    if (!json_is_object(j_client)) {
      ret = I_ERROR_PARAM;
      break;
    }
    
    if (!json_array_size(json_object_get(j_client, "redirect_uris"))) {
      ret = I_ERROR_PARAM;
      break;
    }
  } while (0);
  return ret;
}

json_t * register_client(struct config_elements * config, json_t * j_client) {
  time_t now;
  json_t * j_return = NULL, * j_registration;
  int res;
  
  time(&now);
  if (config->register_access_token_expiration < now) {
    if (i_set_parameter_list(config->i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CLIENT_CREDENTIALS,
                                                I_OPT_SCOPE, config->register_scope,
                                                I_OPT_NONE) == I_OK) {
      if ((res = i_run_token_request(config->i_session)) == I_OK) {
        o_free(config->register_access_token);
        config->register_access_token = o_strdup(i_get_str_parameter(config->i_session, I_OPT_ACCESS_TOKEN));
        config->register_access_token_expiration = now + i_get_int_parameter(config->i_session, I_OPT_EXPIRES_IN);
      } else if (res == I_ERROR_PARAM) {
        j_return = json_pack("{si}", "result", I_ERROR_PARAM);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "register_client - Error i_run_token_request");
        j_return = json_pack("{si}", "result", E_ERROR);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_client - Error i_set_parameter_list");
      j_return = json_pack("{si}", "result", E_ERROR);
    }
  }
  if (j_return == NULL) {
    if ((res = i_register_client(config->i_session, j_client, 0, &j_registration)) == I_OK) {
      j_return = json_pack("{siso}", "result", E_OK, "registration", j_registration);
    } else if (res == I_ERROR_PARAM) {
      j_return = json_pack("{si}", "result", I_ERROR_PARAM);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "register_client - Error i_register_client %d", res);
      j_return = json_pack("{si}", "result", E_ERROR);
    }
  }
  return j_return;
}

json_t * update_client_registration(struct config_elements * config, json_t * j_client_database, json_t * j_registration) {
  json_t * j_return, * j_update_registration = NULL;
  struct _i_session i_session;
  int res;
  
  if (i_init_session(&i_session) == I_OK) {
    if (i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, json_string_value(json_object_get(j_client_database, "registration_access_token")),
                                         I_OPT_REGISTRATION_CLIENT_URI, json_string_value(json_object_get(j_client_database, "registration_client_uri")),
                                         I_OPT_REGISTRATION_ENDPOINT, i_get_str_parameter(config->i_session, I_OPT_REGISTRATION_ENDPOINT),
                                         I_OPT_CLIENT_ID, json_string_value(json_object_get(j_client_database, "client_id")),
                                         I_OPT_NONE) == I_OK) {
      if ((res = i_manage_registration_client(&i_session, j_registration, 0, &j_update_registration)) == I_OK) {
        j_return = json_pack("{siso}", "result", E_OK, "registration", j_update_registration);
      } else if (res == I_ERROR_PARAM) {
        j_return = json_pack("{si}", "result", I_ERROR_PARAM);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "update_client_registration - Error i_manage_registration_client");
        j_return = json_pack("{si}", "result", E_ERROR);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "update_client_registration - Error i_set_str_parameter");
      j_return = json_pack("{si}", "result", E_ERROR);
    }
    i_clean_session(&i_session);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "update_client_registration - Error i_init_session");
    j_return = json_pack("{si}", "result", E_ERROR);
  }
  return j_return;
}

int disable_client_registration(struct config_elements * config, json_t * j_client_database) {
  struct _i_session i_session;
  int ret, res;
  
  if (i_init_session(&i_session) == I_OK) {
    if (i_set_parameter_list(&i_session, I_OPT_ACCESS_TOKEN, json_string_value(json_object_get(j_client_database, "registration_access_token")),
                                         I_OPT_REGISTRATION_CLIENT_URI, json_string_value(json_object_get(j_client_database, "registration_client_uri")),
                                         I_OPT_REGISTRATION_ENDPOINT, i_get_str_parameter(config->i_session, I_OPT_REGISTRATION_ENDPOINT),
                                         I_OPT_CLIENT_ID, json_string_value(json_object_get(j_client_database, "client_id")),
                                         I_OPT_NONE) == I_OK) {
      if ((res = i_delete_registration_client(&i_session)) == I_OK) {
        ret = E_OK;
      } else if (res == I_ERROR_PARAM) {
        ret = E_ERROR_PARAM;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "update_client_registration - Error i_manage_registration_client");
        ret = E_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "update_client_registration - Error i_set_str_parameter");
      ret = E_ERROR;
    }
    i_clean_session(&i_session);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "update_client_registration - Error i_init_session");
    ret = E_ERROR;
  }
  return ret;
}
