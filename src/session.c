/**
 *
 * Dagda: Planificateur d'équipe
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

int verify_access_token(struct config_elements * config) {
  json_t * j_introspection = NULL;
  int ret;
  char ** scopes = NULL;

  if (config->oidc_is_jwt_access_token) {
    if (i_verify_jwt_access_token(config->i_session, config->oidc_aud) == I_OK) {
      j_introspection = json_incref(config->i_session->access_token_payload);
    }
  } else {
    if (i_set_str_parameter(config->i_session, I_OPT_TOKEN_TARGET, i_get_str_parameter(config->i_session, I_OPT_ACCESS_TOKEN)) == I_OK) {
      if (i_get_token_introspection(config->i_session, &j_introspection, I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET, 0) != I_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "verify_access_token - Error i_get_token_introspection");
      } else {
        if (json_object_get(j_introspection, "active") != json_true()) {
          json_decref(j_introspection);
          j_introspection = NULL;
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "verify_access_token - Error setting target token");
    }
  }
  if (j_introspection != NULL) {
    if (split_string(json_string_value(json_object_get(j_introspection, "scope")), " ", &scopes)) {
      ret = string_array_has_value((const char **)scopes, config->oidc_scope)?E_OK:E_ERROR_UNAUTHORIZED;
      free_string_array(scopes);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "verify_access_token - Error split_string");
      ret = E_ERROR;
    }
  } else {
    ret = E_ERROR_UNAUTHORIZED;
  }
  json_decref(j_introspection);
  return ret;
}

json_t * check_session(struct config_elements * config, const char * session_id) {
  json_t * j_return, * j_query, * j_result, * j_result_profile;
  int res;
  char * expire_clause, * expiration_clause, session_hash[64] = {0};
  time_t now, token_expire;

  if (o_strlen(session_id) == ESRAS_SESSION_LENGTH && generate_hash(session_id, session_hash)) {
    if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expire_clause = o_strdup("> NOW()");
    } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expire_clause = o_strdup("> NOW()");
    } else { // HOEL_DB_TYPE_SQLITE
      expire_clause = o_strdup("> (strftime('%s','now'))");
    }
    j_query = json_pack("{sss[ssss]s{sss{ssss}si}}",
                        "table", ESRAS_TABLE_SESSION,
                        "columns",
                          "p_id",
                          "s_id",
                          "s_refresh_token AS refresh_token",
                          SWITCH_DB_TYPE(config->conn->type, "UNIX_TIMESTAMP(s_token_expires_at) AS expires_at", "s_token_expires_at AS expires_at", "EXTRACT(EPOCH FROM s_token_expires_at)::integer AS expires_at"),
                        "where",
                          "s_session_hash", session_hash,
                          "s_expires_at",
                            "operator", "raw",
                            "value", expire_clause,
                          "s_enabled", 1);
    o_free(expire_clause);
    res = h_select(config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        j_query = json_pack("{sss[sss]s{sO}}",
                            "table", ESRAS_TABLE_PROFILE,
                            "columns",
                              "p_id",
                              "p_sub AS sub",
                              "p_name AS name",
                            "where",
                              "p_id", json_object_get(json_array_get(j_result, 0), "p_id"));
        res = h_select(config->conn, j_query, &j_result_profile, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          if (json_array_size(j_result_profile)) {
            time(&now);
            if (now > json_integer_value(json_object_get(json_array_get(j_result, 0), "expires_at"))) {
              if (!pthread_mutex_lock(&config->i_session_lock)) {
                if (json_string_length(json_object_get(json_array_get(j_result, 0), "refresh_token"))) {
                  if (i_set_parameter_list(config->i_session, I_OPT_REFRESH_TOKEN, json_string_value(json_object_get(json_array_get(j_result, 0), "refresh_token")),
                                                              I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_REFRESH_TOKEN,
                                                              I_OPT_NONE) == I_OK) {
                    if (i_run_token_request(config->i_session) == I_OK) {
                      if ((res = verify_access_token(config)) == E_OK) {
                        if (i_get_int_parameter(config->i_session, I_OPT_EXPIRES_IN)) {
                          token_expire = now + (time_t)i_get_int_parameter(config->i_session, I_OPT_EXPIRES_IN);
                        } else {
                          token_expire = now + ESRAS_DEFAULT_TOKEN_EXPIRE;
                        }
                        if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
                          expire_clause = msprintf("FROM_UNIXTIME(%u)", token_expire);
                        } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
                          expire_clause = msprintf("TO_TIMESTAMP(%u)", token_expire);
                        } else { // HOEL_DB_TYPE_SQLITE
                          expire_clause = msprintf("%u", token_expire);
                        }
                        j_query = json_pack("{sss{s{ss}ss*}s{sO}}",
                                            "table", ESRAS_TABLE_SESSION,
                                            "set",
                                              "s_token_expires_at",
                                                "raw", expire_clause,
                                              "s_refresh_token", i_get_str_parameter(config->i_session, I_OPT_REFRESH_TOKEN),
                                            "where",
                                              "s_id", json_object_get(json_array_get(j_result, 0), "s_id"));
                        if (config->session_extend) {
                          if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
                            expiration_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)config->session_expiration ));
                          } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
                            expiration_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)config->session_expiration ));
                          } else { // HOEL_DB_TYPE_SQLITE
                            expiration_clause = msprintf("%u", (now + (unsigned int)config->session_expiration ));
                          }
                          json_object_set_new(json_object_get(j_query, "set"), "s_expires_at", json_pack("{ss}", "raw", expiration_clause));
                          o_free(expiration_clause);
                        }
                        o_free(expire_clause);
                        res = h_update(config->conn, j_query, NULL);
                        json_decref(j_query);
                        if (res == H_OK) {
                          if (i_get_str_parameter(config->i_session, I_OPT_REVOCATION_ENDPOINT) != NULL) {
                            if (i_set_str_parameter(config->i_session, I_OPT_TOKEN_TARGET, i_get_str_parameter(config->i_session, I_OPT_ACCESS_TOKEN)) == I_OK) {
                              if (i_revoke_token(config->i_session, I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET) != I_OK) {
                                y_log_message(Y_LOG_LEVEL_ERROR, "check_session - Error i_revoke_token");
                              }
                            } else {
                              y_log_message(Y_LOG_LEVEL_ERROR, "check_session - Error setting target token");
                            }
                          }
                          j_return = json_pack("{sisOso}", "result", E_OK, "session", json_array_get(j_result_profile, 0), "extend", config->session_extend?json_true():json_false());
                        } else {
                          y_log_message(Y_LOG_LEVEL_ERROR, "check_session - Error executing j_query (4)");
                          j_return = json_pack("{si}", "result", E_ERROR_DB);
                        }
                      } else if (res == E_ERROR_UNAUTHORIZED) {
                        j_return = json_pack("{si}", "result", E_ERROR_UNAUTHORIZED);
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "check_session - Error verify_access_token");
                        j_return = json_pack("{si}", "result", E_ERROR);
                      }
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "check_session - Error i_run_token_request");
                      j_return = json_pack("{si}", "result", E_ERROR);
                    }
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "check_session - Error i_set_parameter_list");
                    j_return = json_pack("{si}", "result", E_ERROR);
                  }
                } else {
                  // No refresh token, need to run code flow again
                  j_return = json_pack("{si}", "result", E_ERROR_UNAUTHORIZED);
                }
                pthread_mutex_unlock(&config->i_session_lock);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "check_session - Error pthread_mutex_lock");
                j_return = json_pack("{si}", "result", E_ERROR);
              }
            } else {
              j_return = json_pack("{sisOso}", "result", E_OK, "session", json_array_get(j_result_profile, 0), "extend", json_false());
            }
          } else {
            j_return = json_pack("{si}", "result", E_ERROR_UNAUTHORIZED);
          }
          json_decref(j_result_profile);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "check_session - Error executing j_query (2)");
          j_return = json_pack("{si}", "result", E_ERROR_DB);
        }
      } else {
        j_return = json_pack("{si}", "result", E_ERROR_NOT_FOUND);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "check_session - Error executing j_query (1)");
      j_return = json_pack("{si}", "result", E_ERROR_DB);
    }
  } else {
    j_return = json_pack("{si}", "result", E_ERROR_NOT_FOUND);
  }
  return j_return;
}

json_t * init_session(struct config_elements * config, const char * cur_session_id, int create) {
  json_t * j_return, * j_query;
  char session_id[ESRAS_SESSION_LENGTH+1] = {0}, session_hash[64] = {0}, * expiration_clause;
  int res;
  time_t now;

  if (!pthread_mutex_lock(&config->i_session_lock)) {
    if (i_set_parameter_list(config->i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                I_OPT_NONCE_GENERATE, 32,
                                                I_OPT_STATE_GENERATE, 32,
                                                I_OPT_NONE) == I_OK) {
      if (i_build_auth_url_get(config->i_session) == I_OK) {
        if (create) {
          if (rand_string(session_id, ESRAS_SESSION_LENGTH) != NULL && generate_hash(session_id, session_hash)) {
            time(&now);
            if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
              expiration_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)config->session_expiration ));
            } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
              expiration_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)config->session_expiration ));
            } else { // HOEL_DB_TYPE_SQLITE
              expiration_clause = msprintf("%u", (now + (unsigned int)config->session_expiration ));
            }
            j_query = json_pack("{sss{sssssss{ss}}}",
                                "table", ESRAS_TABLE_SESSION,
                                "values",
                                  "s_session_hash", session_hash,
                                  "s_state", i_get_str_parameter(config->i_session, I_OPT_STATE),
                                  "s_nonce", i_get_str_parameter(config->i_session, I_OPT_NONCE),
                                  "s_expires_at",
                                    "raw", expiration_clause);
            o_free(expiration_clause);
            res = h_insert(config->conn, j_query, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              j_return = json_pack("{sis{ssss*}}", "result", E_OK, "session", "session_id", session_id, "auth_url", i_get_str_parameter(config->i_session, I_OPT_REDIRECT_TO));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "init_session - Error executing j_query");
              j_return = json_pack("{si}", "result", E_ERROR_DB);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "init_session - Error generating session id");
            j_return = json_pack("{si}", "result", E_ERROR);
          }
        } else {
          if (generate_hash(cur_session_id, session_hash)) {
            time(&now);
            if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
              expiration_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)config->session_expiration ));
            } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
              expiration_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)config->session_expiration ));
            } else { // HOEL_DB_TYPE_SQLITE
              expiration_clause = msprintf("%u", (now + (unsigned int)config->session_expiration ));
            }
            j_query = json_pack("{sss{sssss{ss}}s{ss}}",
                                "table", ESRAS_TABLE_SESSION,
                                "set",
                                  "s_state", i_get_str_parameter(config->i_session, I_OPT_STATE),
                                  "s_nonce", i_get_str_parameter(config->i_session, I_OPT_NONCE),
                                  "s_expires_at",
                                    "raw", expiration_clause,
                                  "where",
                                    "s_session_hash", session_hash);
            o_free(expiration_clause);
            res = h_update(config->conn, j_query, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              j_return = json_pack("{sis{ssss*}}", "result", E_OK, "session", "session_id", cur_session_id, "auth_url", i_get_str_parameter(config->i_session, I_OPT_REDIRECT_TO));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "init_session - Error executing j_query");
              j_return = json_pack("{si}", "result", E_ERROR_DB);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "init_session - Error generate_hash");
            j_return = json_pack("{si}", "result", E_ERROR);
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "init_session - Error i_build_auth_url_get");
        j_return = json_pack("{si}", "result", E_ERROR);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "init_session - Error i_set_parameter_list");
      j_return = json_pack("{si}", "result", E_ERROR);
    }
    pthread_mutex_unlock(&config->i_session_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "init_session - Error pthread_mutex_lock");
    j_return = json_pack("{si}", "result", E_ERROR);
  }
  return j_return;
}

int validate_session_code(struct config_elements * config, const char * session_id, const char * state, const char * code) {
  json_t * j_query, * j_result, * j_result_profile, * j_last_id;
  int res, ret;
  char session_hash[64] = {0}, * expire_clause;
  time_t now;

  if (!pthread_mutex_lock(&config->i_session_lock)) {
    if (o_strlen(session_id) && generate_hash(session_id, session_hash)) {
      if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expire_clause = o_strdup("> NOW()");
      } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expire_clause = o_strdup("> NOW()");
      } else { // HOEL_DB_TYPE_SQLITE
        expire_clause = o_strdup("> (strftime('%s','now'))");
      }
      j_query = json_pack("{sss[ss]s{sssss{ssss}si}}",
                          "table", ESRAS_TABLE_SESSION,
                          "columns",
                            "s_id",
                            "s_nonce AS nonce",
                          "where",
                            "s_state", state,
                            "s_session_hash", session_hash,
                            "s_expires_at",
                              "operator", "raw",
                              "value", expire_clause,
                            "s_enabled", 1);
      o_free(expire_clause);
      res = h_select(config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          if (i_set_parameter_list(config->i_session, I_OPT_RESPONSE_TYPE, I_RESPONSE_TYPE_CODE,
                                                      I_OPT_NONCE, json_string_value(json_object_get(json_array_get(j_result, 0), "nonce")),
                                                      I_OPT_STATE, state,
                                                      I_OPT_CODE, code,
                                                      I_OPT_NONE) == I_OK) {
            if (i_run_token_request(config->i_session) == I_OK &&
                json_string_length(json_object_get(config->i_session->id_token_payload, "sub"))) {
              if ((res = verify_access_token(config)) == E_OK) {
                j_query = json_pack("{sss[ss]s{ss}}",
                                    "table", ESRAS_TABLE_PROFILE,
                                    "columns",
                                      "p_id",
                                      "p_name AS name",
                                    "where",
                                      "p_sub", json_string_value(json_object_get(config->i_session->id_token_payload, "sub")));
                res = h_select(config->conn, j_query, &j_result_profile, NULL);
                json_decref(j_query);
                if (res == H_OK) {
                  if (json_array_size(j_result_profile)) {
                    time(&now);
                    if (i_get_int_parameter(config->i_session, I_OPT_EXPIRES_IN)) {
                      now += (time_t)i_get_int_parameter(config->i_session, I_OPT_EXPIRES_IN);
                    } else {
                      now += ESRAS_DEFAULT_TOKEN_EXPIRE;
                    }
                    if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
                      expire_clause = msprintf("FROM_UNIXTIME(%u)", now);
                    } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
                      expire_clause = msprintf("TO_TIMESTAMP(%u)", now);
                    } else { // HOEL_DB_TYPE_SQLITE
                      expire_clause = msprintf("%u", now);
                    }
                    j_query = json_pack("{sss{sOs{ss}ss*}s{sO}}",
                                        "table", ESRAS_TABLE_SESSION,
                                        "set",
                                          "p_id", json_object_get(json_array_get(j_result_profile, 0), "p_id"),
                                          "s_token_expires_at",
                                            "raw", expire_clause,
                                          "s_refresh_token", i_get_str_parameter(config->i_session, I_OPT_REFRESH_TOKEN),
                                        "where",
                                          "s_id", json_object_get(json_array_get(j_result, 0), "s_id"));
                    o_free(expire_clause);
                    res = h_update(config->conn, j_query, NULL);
                    json_decref(j_query);
                    if (res == H_OK) {
                      if (json_string_length(json_object_get(config->i_session->id_token_payload, config->oidc_name_claim))) {
                        j_query = json_pack("{sss{ss}s{sO}}",
                                            "table", ESRAS_TABLE_PROFILE,
                                            "set",
                                              "p_name", json_string_value(json_object_get(config->i_session->id_token_payload, config->oidc_name_claim)),
                                            "where",
                                              "p_id", json_object_get(json_array_get(j_result_profile, 0), "p_id"));
                        res = h_update(config->conn, j_query, NULL);
                        json_decref(j_query);
                        if (res == H_OK) {
                          ret = E_OK;
                        } else {
                          y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error executing j_query (5)");
                          ret = E_ERROR_DB;
                        }
                      } else {
                        ret = E_OK;
                      }
                      if (i_get_str_parameter(config->i_session, I_OPT_REVOCATION_ENDPOINT) != NULL) {
                        if (i_set_str_parameter(config->i_session, I_OPT_TOKEN_TARGET, i_get_str_parameter(config->i_session, I_OPT_ACCESS_TOKEN)) == I_OK) {
                          if (i_revoke_token(config->i_session, I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET) != I_OK) {
                            y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error i_revoke_token");
                          }
                        } else {
                          y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error setting target token");
                        }
                      }
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error executing j_query (6)");
                      ret = E_ERROR_DB;
                    }
                  } else {
                    j_query = json_pack("{sss{ssss*}}",
                                        "table", ESRAS_TABLE_PROFILE,
                                        "values",
                                          "p_sub", json_string_value(json_object_get(config->i_session->id_token_payload, "sub")),
                                          "p_name", json_string_value(json_object_get(config->i_session->id_token_payload, config->oidc_name_claim)));
                    res = h_insert(config->conn, j_query, NULL);
                    json_decref(j_query);
                    if (res == H_OK) {
                      j_last_id = h_last_insert_id(config->conn);
                      if (j_last_id != NULL) {
                        time(&now);
                        if (i_get_int_parameter(config->i_session, I_OPT_EXPIRES_IN)) {
                          now += (time_t)i_get_int_parameter(config->i_session, I_OPT_EXPIRES_IN);
                        } else {
                          now += ESRAS_DEFAULT_TOKEN_EXPIRE;
                        }
                        if (config->conn->type==HOEL_DB_TYPE_MARIADB) {
                          expire_clause = msprintf("FROM_UNIXTIME(%u)", now);
                        } else if (config->conn->type==HOEL_DB_TYPE_PGSQL) {
                          expire_clause = msprintf("TO_TIMESTAMP(%u)", now);
                        } else { // HOEL_DB_TYPE_SQLITE
                          expire_clause = msprintf("%u", now);
                        }
                        j_query = json_pack("{sss{sOs{ss}ss*}s{sO}}",
                                            "table", ESRAS_TABLE_SESSION,
                                            "set",
                                              "p_id", j_last_id,
                                              "s_token_expires_at",
                                                "raw", expire_clause,
                                              "s_refresh_token", i_get_str_parameter(config->i_session, I_OPT_REFRESH_TOKEN),
                                            "where",
                                              "s_id", json_object_get(json_array_get(j_result, 0), "s_id"));
                        res = h_update(config->conn, j_query, NULL);
                        json_decref(j_query);
                        if (res == H_OK) {
                          if (i_get_str_parameter(config->i_session, I_OPT_REVOCATION_ENDPOINT) != NULL) {
                            if (i_set_str_parameter(config->i_session, I_OPT_TOKEN_TARGET, i_get_str_parameter(config->i_session, I_OPT_ACCESS_TOKEN)) == I_OK) {
                              if (i_revoke_token(config->i_session, I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET) != I_OK) {
                                y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error i_revoke_token");
                              }
                            } else {
                              y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error setting target token");
                            }
                          }
                          ret = E_OK;
                        } else {
                          y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error executing j_query (4)");
                          ret = E_ERROR_DB;
                        }
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error h_last_insert_id");
                        ret = E_ERROR_DB;
                      }
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error executing j_query (3)");
                      ret = E_ERROR_DB;
                    }
                  }
                  json_decref(j_result_profile);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error executing j_query (2)");
                  ret = E_ERROR_DB;
                }
              } else if (res == E_ERROR_UNAUTHORIZED) {
                ret = E_ERROR_UNAUTHORIZED;
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error verify_access_token");
                ret = E_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error i_run_token_request");
              ret = E_ERROR_UNAUTHORIZED;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error i_set_parameter_list");
            ret = E_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Invalid session");
          ret = E_ERROR_UNAUTHORIZED;
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error executing j_query (1)");
        ret = E_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Error session");
      ret = E_ERROR_UNAUTHORIZED;
    }
    pthread_mutex_unlock(&config->i_session_lock);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_code - Error pthread_mutex_lock");
    ret = E_ERROR;
  }
  return ret;
}

int delete_session(struct config_elements * config, const char * session_id) {
  char session_hash[64] = {0};
  json_t * j_query, * j_result;
  int res, ret;
  
  if (generate_hash(session_id, session_hash)) {
    if (i_get_str_parameter(config->i_session, I_OPT_REVOCATION_ENDPOINT) != NULL) {
      if (!pthread_mutex_lock(&config->i_session_lock)) {
        j_query = json_pack("{sss[s]s{sssi}}",
                            "table", ESRAS_TABLE_SESSION,
                            "columns",
                              "s_refresh_token AS refresh_token",
                            "where",
                              "s_session_hash", session_hash,
                              "s_enabled", 1);
        res = h_select(config->conn, j_query, &j_result, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          if (i_get_str_parameter(config->i_session, I_OPT_REVOCATION_ENDPOINT) != NULL) {
            if (i_set_str_parameter(config->i_session, I_OPT_TOKEN_TARGET, json_string_value(json_object_get(json_array_get(j_result, 0), "refresh_token"))) == I_OK) {
              if (i_revoke_token(config->i_session, I_INTROSPECT_REVOKE_AUTH_CLIENT_TARGET) != I_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "delete_session - Error i_revoke_token");
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "delete_session - Error setting target token");
            }
          }
          json_decref(j_result);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "delete_session - Error executing j_query (1)");
        }
        pthread_mutex_unlock(&config->i_session_lock);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "delete_session - Error pthread_mutex_lock");
      }
    }
    j_query = json_pack("{sss{si}s{ss}}",
                        "table", ESRAS_TABLE_SESSION,
                        "set",
                          "s_enabled", 0,
                        "where",
                          "s_session_hash", session_hash);
    res = h_update(config->conn, j_query, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      ret = E_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "delete_session - Error executing j_query (2)");
      ret = E_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "delete_session - Error generate_hash");
    ret = E_ERROR;
  }
  return ret;
}
