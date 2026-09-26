#include "../../../pf_build_config.h"
/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <stdio.h>

#include "picokeys.h"

#ifdef ENABLE_DIAGNOSTICS
int debug_log_errstr(const char *file_name, int line, const char *format, ...) {
    if (!file_name || !format) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    char message[DEBUG_LAST_ERROR_STRING_SIZE] = {0};
    int prefix_len = snprintf(message, sizeof(message), "%s:%d: ", file_name, line);
    if (prefix_len < 0 || (size_t)prefix_len >= sizeof(message)) {
        return PICOKEYS_WRONG_LENGTH;
    }

    va_list args;
    va_start(args, format);
    int message_len = vsnprintf(message + prefix_len, sizeof(message) - (size_t)prefix_len, format, args);
    va_end(args);
    if (message_len < 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    message[sizeof(message) - 1] = '\0';

    file_t *file = file_search(DEBUG_LAST_ERROR_FID);
    if (!file) {
        file = file_new(DEBUG_LAST_ERROR_FID);
    }
    if (!file) {
        return PICOKEYS_ERR_NO_MEMORY;
    }

    int ret = file_put_data(file, CONST_BYTE_ARRAY((const uint8_t *)message, sizeof(message)));
    if (ret == PICOKEYS_OK) {
        flash_commit();
    }
    return ret;
}
#endif
