#ifndef UTIL_JSON_H
#define UTIL_JSON_H

/*
 * JSON Utility Functions
 *
 * Simple JSON parsing helpers for request body processing.
 * Not a full JSON parser - handles basic {"key":"value"} format.
 */

/*
 * json_unescape - Unescape JSON string escape sequences in-place
 *
 * Processes: \", \\, \t, \n, \r, \b, \f
 * Modifies string in-place (always shrinks or stays same size).
 *
 * Parameters:
 *   str - String to unescape (modified in place)
 */
void json_unescape(char *str);

/*
 * json_get_string - Extract string value from JSON body
 *
 * Very simple parser - only handles basic {"key":"value"} format.
 * Unescapes standard JSON escape sequences.
 *
 * Parameters:
 *   json - JSON string to parse
 *   key  - Key to search for
 *
 * Returns: Newly allocated string (caller must free), or NULL if not found
 */
char *json_get_string(const char *json, const char *key);

/*
 * json_get_int - Extract integer value from JSON body
 *
 * Parameters:
 *   json      - JSON string to parse
 *   key       - Key to search for
 *   out_value - Output: parsed integer value
 *
 * Returns: 0 on success, -1 if key not found or value not an integer
 */
int json_get_int(const char *json, const char *key, int *out_value);

/*
 * json_get_bool - Extract boolean value from JSON body
 *
 * Parses true, false, or null values.
 *
 * Parameters:
 *   json      - JSON string to parse
 *   key       - Key to search for
 *   out_value - Output: 1 for true, 0 for false/null
 *
 * Returns: 0 on success, -1 if key not found or value not a boolean
 */
int json_get_bool(const char *json, const char *key, int *out_value);

#endif /* UTIL_JSON_H */
