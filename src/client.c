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

json_t * list_client(struct config_elements * config, json_int_t ep_id) {
  json_t * j_query, * j_result, * j_result_ru, * j_return, * j_element = NULL, * j_element_ru = NULL;
  int res;
  size_t index = 0, index_ru = 0;

  j_query = json_pack("{sss[sssssss]s{sI}}",
                      "table", ESRAS_TABLE_CLIENT,
                      "columns",
                        "ec_id",
                        "ec_name AS name",
                        "ec_display_name AS display_name",
                        "ec_enabled",
                        "ec_client_id AS client_id",
                        "ec_secret AS secret",
                        "ec_registration",
                      "where",
                        "ep_id", ep_id);
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
        json_object_set_new(j_element, "redirect_uri", json_array());
        json_array_foreach(j_result_ru, index_ru, j_element_ru) {
          json_array_append(json_object_get(j_element, "redirect_uri"), json_object_get(j_element_ru, "ecru_redirect_uri"));
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
