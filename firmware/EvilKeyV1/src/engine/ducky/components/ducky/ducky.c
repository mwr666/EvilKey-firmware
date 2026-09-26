#include "../../../../pf_build_config.h"
#include "include/ducky.h"

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/ducky_hid_codes.h"
#include "ducky_keymap.h"

#define DUCKY_MAX_VARIABLES 64
#define DUCKY_MAX_CONSTANTS 32
#define DUCKY_MAX_FUNCTIONS 32
#define DUCKY_MAX_NAME 63
#define DUCKY_MAX_CALL_DEPTH 16

typedef struct {
    const char *data;
    size_t length;
} slice_t;

typedef struct {
    char name[DUCKY_MAX_NAME + 1];
    int64_t value;
    bool read_only;
} variable_t;

typedef struct {
    char name[DUCKY_MAX_NAME + 1];
    slice_t replacement;
} constant_t;

typedef struct {
    char name[DUCKY_MAX_NAME + 1];
    size_t first_line;
    size_t end_line;
} function_t;

typedef enum {
    RUN_FINISHED,
    RUN_RETURNED,
    RUN_STOPPED,
    RUN_FAILED,
} run_outcome_t;

typedef struct runtime runtime_t;

struct runtime {
    const char *script;
    size_t script_length;
    size_t *line_offsets;
    size_t line_count;
    bool *line_enabled;
    char *compiled_script;
    const ducky_io_t *io;
    ducky_config_t config;
    ducky_result_t result;

    uint32_t default_delay_ms;
    uint8_t held_modifiers;
    uint8_t held_keys[6];
    uint8_t mouse_buttons;
    uint8_t saved_lock_state;
    bool lock_state_saved;
    bool button_enabled;
    bool button_push_received;
    bool button_handler_active;
    bool button_wait_active;
    uint8_t current_attackmode;
    uint8_t saved_attackmode;
    bool attackmode_saved;
    ducky_attackmode_t attackmode_profile;
    ducky_attackmode_t saved_attackmode_profile;
    uint16_t os;

    variable_t variables[DUCKY_MAX_VARIABLES];
    size_t variable_count;
    constant_t constants[DUCKY_MAX_CONSTANTS];
    size_t constant_count;
    function_t functions[DUCKY_MAX_FUNCTIONS];
    size_t function_count;
    size_t button_first_line;
    size_t button_end_line;

    uint32_t execution_steps;
    unsigned call_depth;
    uint32_t fallback_random;
    uint16_t random_min;
    uint16_t random_max;
    uint16_t random_seed;
    uint16_t storage_activity_timeout_ms;
    bool storage_leds_enabled;
    bool continuous_storage_led;
    bool injecting_leds_enabled;
    bool exfil_leds_enabled;
    bool led_show_caps;
    bool led_show_num;
    bool led_show_scroll;
    uint16_t jitter_max;
    uint16_t button_debounce_ms;
    bool jitter_enabled;
    bool system_leds_enabled;
};

typedef struct {
    runtime_t *runtime;
    slice_t input;
    size_t position;
    size_t source_line;
    bool ok;
} expression_parser_t;

static run_outcome_t run_range(
    runtime_t *runtime,
    size_t first_line,
    size_t end_line,
    bool is_function,
    int64_t *return_value);

static slice_t trim(slice_t value)
{
    while (value.length > 0 && isspace((unsigned char)value.data[0])) {
        ++value.data;
        --value.length;
    }
    while (value.length > 0 && isspace((unsigned char)value.data[value.length - 1])) {
        --value.length;
    }
    return value;
}

static bool equal_case(slice_t value, const char *text)
{
    size_t length = strlen(text);
    if (value.length != length) {
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        if (toupper((unsigned char)value.data[i]) != toupper((unsigned char)text[i])) {
            return false;
        }
    }
    return true;
}

static slice_t first_word(slice_t line, slice_t *arguments)
{
    line = trim(line);
    size_t length = 0;
    while (length < line.length && !isspace((unsigned char)line.data[length])) {
        ++length;
    }
    /* DuckyScript sources commonly omit whitespace before control expressions. */
    if (length > 3 && toupper((unsigned char)line.data[0]) == 'I' &&
        toupper((unsigned char)line.data[1]) == 'F' && line.data[2] == '(') {
        length = 2;
    } else if (length > 6 &&
               toupper((unsigned char)line.data[0]) == 'W' &&
               toupper((unsigned char)line.data[1]) == 'H' &&
               toupper((unsigned char)line.data[2]) == 'I' &&
               toupper((unsigned char)line.data[3]) == 'L' &&
               toupper((unsigned char)line.data[4]) == 'E' && line.data[5] == '(') {
        length = 5;
    }
    slice_t word = {line.data, length};
    slice_t rest = {line.data + length, line.length - length};
    if (arguments != NULL) {
        *arguments = trim(rest);
    }
    return word;
}

static slice_t get_line_raw(const runtime_t *runtime, size_t line_number)
{
    if (line_number >= runtime->line_count) {
        return (slice_t){0};
    }
    size_t start = runtime->line_offsets[line_number];
    size_t end = runtime->line_offsets[line_number + 1];
    if (end > start && runtime->script[end - 1] == '\n') {
        --end;
    }
    if (end > start && runtime->script[end - 1] == '\r') {
        --end;
    }
    return (slice_t){runtime->script + start, end - start};
}

static slice_t get_line(const runtime_t *runtime, size_t line_number)
{
    slice_t line = trim(get_line_raw(runtime, line_number));
    if (line_number == 0U && line.length >= 3U &&
        (unsigned char)line.data[0] == 0xEFU &&
        (unsigned char)line.data[1] == 0xBBU &&
        (unsigned char)line.data[2] == 0xBFU) {
        line.data += 3;
        line.length -= 3U;
        line = trim(line);
    }
    return line;
}

static void set_error(runtime_t *runtime, ducky_status_t status, size_t line, const char *message)
{
    if (runtime->result.status != DUCKY_OK) {
        return;
    }
    runtime->result.status = status;
    runtime->result.line = line + 1;
    snprintf(runtime->result.message, sizeof(runtime->result.message), "%s", message);
}

static void set_error_word(
    runtime_t *runtime,
    ducky_status_t status,
    size_t line,
    const char *prefix,
    slice_t word)
{
    if (runtime->result.status != DUCKY_OK) {
        return;
    }
    runtime->result.status = status;
    runtime->result.line = line + 1;
    snprintf(
        runtime->result.message,
        sizeof(runtime->result.message),
        "%s%.*s",
        prefix,
        (int)(word.length > 60 ? 60 : word.length),
        word.data);
}

static bool execute_button_block(runtime_t *runtime);
static bool poll_async_button(runtime_t *runtime, size_t line);

static bool delay_ms(runtime_t *runtime, uint32_t milliseconds, size_t line)
{
    while (milliseconds > 0U) {
        uint32_t chunk = milliseconds > 10U ? 10U : milliseconds;
        if (runtime->io->delay_ms != NULL) {
            runtime->io->delay_ms(runtime->io->context, chunk);
        }
        milliseconds -= chunk;
        if (!poll_async_button(runtime, line)) return false;
    }
    return true;
}

static uint32_t random_u32(runtime_t *runtime)
{
    /* Hardware entropy seeds one per-payload generator. Keeping generation in
     * the runtime makes $_RANDOM_SEED deterministic and writable. */
    runtime->fallback_random = runtime->fallback_random * 1664525U + 1013904223U;
    return runtime->fallback_random;
}

static int variable_index(runtime_t *runtime, slice_t name)
{
    for (size_t i = 0; i < runtime->variable_count; ++i) {
        size_t existing_length = strlen(runtime->variables[i].name);
        if (name.length == existing_length &&
            memcmp(name.data, runtime->variables[i].name, name.length) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int constant_index(runtime_t *runtime, slice_t name)
{
    for (size_t i = 0; i < runtime->constant_count; ++i) {
        size_t existing_length = strlen(runtime->constants[i].name);
        if (name.length == existing_length &&
            memcmp(name.data, runtime->constants[i].name, name.length) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static bool valid_name(slice_t name, char prefix)
{
    if (name.length < 2 || name.length > DUCKY_MAX_NAME || name.data[0] != prefix) {
        return false;
    }
    if (!(isalpha((unsigned char)name.data[1]) || name.data[1] == '_')) {
        return false;
    }
    for (size_t i = 2; i < name.length; ++i) {
        if (!(isalnum((unsigned char)name.data[i]) || name.data[i] == '_')) {
            return false;
        }
    }
    return true;
}

static bool set_variable(
    runtime_t *runtime,
    slice_t name,
    int64_t value,
    bool define,
    bool read_only,
    size_t line)
{
    (void)define;
    if (value < 0 || value > UINT16_MAX) {
        set_error(runtime, DUCKY_PARSE_ERROR, line, "Variable value must be 0-65535");
        return false;
    }
    int index = variable_index(runtime, name);
    if (index >= 0) {
        /* Hak5 treats a repeated VAR declaration as re-initialization. This is
         * also required for VAR declarations inside repeatedly called functions. */
        if (runtime->variables[index].read_only) {
            set_error_word(runtime, DUCKY_PARSE_ERROR, line, "Cannot assign constant: ", name);
            return false;
        }
        runtime->variables[index].value = value;
        return true;
    }
    /* Assignment is also accepted as first initialization. Official Hak5
     * examples and payload extensions use both VAR $NAME and $NAME forms. */
    if (runtime->variable_count == DUCKY_MAX_VARIABLES) {
        set_error(runtime, DUCKY_LIMIT_EXCEEDED, line, "Too many variables");
        return false;
    }
    variable_t *variable = &runtime->variables[runtime->variable_count++];
    memcpy(variable->name, name.data, name.length);
    variable->name[name.length] = '\0';
    variable->value = value;
    variable->read_only = read_only;
    return true;
}

static bool valid_constant_name(slice_t name)
{
    size_t start = name.length > 0U && name.data[0] == '#' ? 1U : 0U;
    if (start == name.length || name.length > DUCKY_MAX_NAME ||
        !(isalpha((unsigned char)name.data[start]) || name.data[start] == '_')) {
        return false;
    }
    for (size_t i = start + 1U; i < name.length; ++i) {
        if (!(isalnum((unsigned char)name.data[i]) || name.data[i] == '_' ||
              name.data[i] == '-')) {
            return false;
        }
    }
    return true;
}

static bool define_constant(runtime_t *runtime, slice_t definition, size_t line)
{
    definition = trim(definition);
    size_t name_length = 0;
    if (name_length < definition.length && definition.data[name_length] == '#') {
        ++name_length;
    }
    while (name_length < definition.length &&
           (isalnum((unsigned char)definition.data[name_length]) ||
            definition.data[name_length] == '_' || definition.data[name_length] == '-')) {
        ++name_length;
    }
    slice_t name = {definition.data, name_length};
    slice_t replacement = trim((slice_t){
        definition.data + name_length,
        definition.length - name_length,
    });
    if (!valid_constant_name(name) || replacement.length == 0) {
        set_error(runtime, DUCKY_PARSE_ERROR, line, "DEFINE requires 'NAME replacement'");
        return false;
    }
    if (constant_index(runtime, name) >= 0) {
        set_error_word(runtime, DUCKY_PARSE_ERROR, line, "Constant already defined: ", name);
        return false;
    }
    if (runtime->constant_count == DUCKY_MAX_CONSTANTS) {
        set_error(runtime, DUCKY_LIMIT_EXCEEDED, line, "Too many constants");
        return false;
    }
    constant_t *constant = &runtime->constants[runtime->constant_count++];
    memcpy(constant->name, name.data, name.length);
    constant->name[name.length] = '\0';
    constant->replacement = replacement;
    return true;
}

static uint8_t runtime_led_options(const runtime_t *runtime)
{
    return (runtime->system_leds_enabled ? DUCKY_LED_OPT_SYSTEM : 0U) |
           (runtime->storage_leds_enabled ? DUCKY_LED_OPT_STORAGE : 0U) |
           (runtime->continuous_storage_led ? DUCKY_LED_OPT_CONTINUOUS_STORAGE : 0U) |
           (runtime->injecting_leds_enabled ? DUCKY_LED_OPT_INJECTING : 0U) |
           (runtime->exfil_leds_enabled ? DUCKY_LED_OPT_EXFIL : 0U) |
           (runtime->led_show_caps ? DUCKY_LED_OPT_SHOW_CAPS : 0U) |
           (runtime->led_show_num ? DUCKY_LED_OPT_SHOW_NUM : 0U) |
           (runtime->led_show_scroll ? DUCKY_LED_OPT_SHOW_SCROLL : 0U);
}

static void publish_runtime_options(runtime_t *runtime)
{
    if (runtime->io->runtime_options != NULL) {
        runtime->io->runtime_options(runtime->io->context,
            runtime_led_options(runtime), runtime->storage_activity_timeout_ms);
    }
}

static bool set_internal_variable(runtime_t *runtime, slice_t name, int64_t value, size_t line)
{
    if (value < 0 || value > UINT16_MAX) {
        set_error(runtime, DUCKY_PARSE_ERROR, line, "Internal variable value must be 0-65535");
        return false;
    }
    if (equal_case(name, "$_BUTTON_PUSH_RECEIVED")) {
        runtime->button_push_received = value != 0;
    } else if (equal_case(name, "$_BUTTON_ENABLED")) {
        runtime->button_enabled = value != 0;
    } else if (equal_case(name, "$_BUTTON_TIMEOUT")) {
        runtime->button_debounce_ms = (uint16_t)value;
    } else if (equal_case(name, "$_RANDOM_MIN")) {
        runtime->random_min = (uint16_t)value;
    } else if (equal_case(name, "$_RANDOM_MAX")) {
        runtime->random_max = (uint16_t)value;
    } else if (equal_case(name, "$_JITTER_ENABLED")) {
        runtime->jitter_enabled = value != 0;
    } else if (equal_case(name, "$_JITTER_MAX")) {
        runtime->jitter_max = (uint16_t)value;
    } else if (equal_case(name, "$_EXFIL_MODE_ENABLED")) {
        if (runtime->io->set_exfil_mode == NULL) {
            set_error(runtime, DUCKY_UNSUPPORTED, line, "Keystroke Reflection is unavailable");
            return false;
        }
        if (!runtime->io->set_exfil_mode(runtime->io->context, value != 0)) {
            set_error(runtime, DUCKY_IO_ERROR, line, "Keystroke Reflection transition failed");
            return false;
        }
    } else if (equal_case(name, "$_SYSTEM_LEDS_ENABLED")) {
        runtime->system_leds_enabled = value != 0;
        publish_runtime_options(runtime);
    } else if (equal_case(name, "$_STORAGE_LEDS_ENABLED")) {
        runtime->storage_leds_enabled = value != 0;
        publish_runtime_options(runtime);
    } else if (equal_case(name, "$_LED_CONTINUOUS_SHOW_STORAGE_ACTIVITY")) {
        runtime->continuous_storage_led = value != 0;
        publish_runtime_options(runtime);
    } else if (equal_case(name, "$_INJECTING_LEDS_ENABLED")) {
        runtime->injecting_leds_enabled = value != 0;
        publish_runtime_options(runtime);
    } else if (equal_case(name, "$_EXFIL_LEDS_ENABLED")) {
        runtime->exfil_leds_enabled = value != 0;
        publish_runtime_options(runtime);
    } else if (equal_case(name, "$_LED_SHOW_CAPS")) {
        runtime->led_show_caps = value != 0;
        publish_runtime_options(runtime);
    } else if (equal_case(name, "$_LED_SHOW_NUM")) {
        runtime->led_show_num = value != 0;
        publish_runtime_options(runtime);
    } else if (equal_case(name, "$_LED_SHOW_SCROLL")) {
        runtime->led_show_scroll = value != 0;
        publish_runtime_options(runtime);
    } else if (equal_case(name, "$_STORAGE_ACTIVITY_TIMEOUT")) {
        runtime->storage_activity_timeout_ms = (uint16_t)value;
        publish_runtime_options(runtime);
    } else if (equal_case(name, "$_RANDOM_SEED")) {
        runtime->random_seed = (uint16_t)value;
        runtime->fallback_random = ((uint32_t)(uint16_t)value << 16) | (uint16_t)value;
    } else if (equal_case(name, "$_HOST_CONFIGURATION_REQUEST_COUNT")) {
        if (value != 0 || runtime->io->reset_host_configuration_request_count == NULL ||
            !runtime->io->reset_host_configuration_request_count(runtime->io->context)) {
            set_error(runtime, DUCKY_UNSUPPORTED, line,
                      "$_HOST_CONFIGURATION_REQUEST_COUNT may only be reset to zero");
            return false;
        }
    } else if (equal_case(name, "$_OS")) {
        runtime->os = (uint16_t)value;
    } else {
        set_error_word(runtime, DUCKY_PARSE_ERROR, line, "Unknown or read-only internal variable: ", name);
        return false;
    }
    return true;
}

static void expression_skip_space(expression_parser_t *parser)
{
    while (parser->position < parser->input.length &&
           isspace((unsigned char)parser->input.data[parser->position])) {
        ++parser->position;
    }
}

static bool expression_match(expression_parser_t *parser, const char *text)
{
    expression_skip_space(parser);
    size_t length = strlen(text);
    if (parser->position + length > parser->input.length ||
        memcmp(parser->input.data + parser->position, text, length) != 0) {
        return false;
    }
    parser->position += length;
    return true;
}

static bool expression_match_keyword(expression_parser_t *parser, const char *text)
{
    expression_skip_space(parser);
    size_t length = strlen(text);
    if (parser->position + length > parser->input.length) {
        return false;
    }
    slice_t candidate = {parser->input.data + parser->position, length};
    if (!equal_case(candidate, text)) {
        return false;
    }
    size_t after = parser->position + length;
    if (after < parser->input.length &&
        (isalnum((unsigned char)parser->input.data[after]) || parser->input.data[after] == '_')) {
        return false;
    }
    parser->position = after;
    return true;
}

static function_t *find_function(runtime_t *runtime, slice_t name)
{
    for (size_t i = 0; i < runtime->function_count; ++i) {
        size_t length = strlen(runtime->functions[i].name);
        if (name.length == length && memcmp(name.data, runtime->functions[i].name, length) == 0) {
            return &runtime->functions[i];
        }
    }
    return NULL;
}

static bool run_function(runtime_t *runtime, function_t *function, int64_t *value)
{
    if (runtime->call_depth >= DUCKY_MAX_CALL_DEPTH) {
        set_error(runtime, DUCKY_LIMIT_EXCEEDED, function->first_line, "Function call depth exceeded");
        return false;
    }
    ++runtime->call_depth;
    *value = 0;
    run_outcome_t outcome = run_range(
        runtime,
        function->first_line + 1,
        function->end_line,
        true,
        value);
    --runtime->call_depth;
    return outcome == RUN_FINISHED || outcome == RUN_RETURNED;
}

static int64_t expression_parse_or(expression_parser_t *parser);

static uint16_t swap_usb_id(uint16_t value)
{
    return (uint16_t)((value >> 8) | (value << 8));
}

static int64_t expression_internal_variable(runtime_t *runtime, slice_t name, bool *found)
{
    *found = true;
    uint8_t leds = runtime->io->keyboard_leds != NULL
        ? runtime->io->keyboard_leds(runtime->io->context)
        : 0;
    if (equal_case(name, "$_CAPSLOCK_ON")) {
        return (leds & DUCKY_LED_CAPS_LOCK) != 0;
    }
    if (equal_case(name, "$_SAVED_CAPSLOCK_ON")) {
        return runtime->lock_state_saved && (runtime->saved_lock_state & DUCKY_LED_CAPS_LOCK) != 0;
    }
    if (equal_case(name, "$_SAVED_NUMLOCK_ON")) {
        return runtime->lock_state_saved && (runtime->saved_lock_state & DUCKY_LED_NUM_LOCK) != 0;
    }
    if (equal_case(name, "$_SAVED_SCROLLLOCK_ON")) {
        return runtime->lock_state_saved && (runtime->saved_lock_state & DUCKY_LED_SCROLL_LOCK) != 0;
    }
    if (equal_case(name, "$_RECEIVED_HOST_LOCK_LED_REPLY")) {
        return runtime->io->host_lock_reply_received != NULL &&
               runtime->io->host_lock_reply_received(runtime->io->context);
    }
    if (equal_case(name, "$_HOST_CONFIGURATION_REQUEST_COUNT")) {
        return runtime->io->host_configuration_request_count != NULL
            ? runtime->io->host_configuration_request_count(runtime->io->context) : 0;
    }
    if (equal_case(name, "$_NUMLOCK_ON")) {
        return (leds & DUCKY_LED_NUM_LOCK) != 0;
    }
    if (equal_case(name, "$_SCROLLLOCK_ON")) {
        return (leds & DUCKY_LED_SCROLL_LOCK) != 0;
    }
    if (equal_case(name, "$_BUTTON_ENABLED")) {
        return runtime->button_enabled;
    }
    if (equal_case(name, "$_BUTTON_PUSH_RECEIVED")) {
        return runtime->button_push_received;
    }
    if (equal_case(name, "$_BUTTON_USER_DEFINED")) {
        return runtime->button_first_line != SIZE_MAX;
    }
    if (equal_case(name, "$_BUTTON_TIMEOUT")) {
        return runtime->button_debounce_ms;
    }
    if (equal_case(name, "$_RANDOM_MIN")) {
        return runtime->random_min;
    }
    if (equal_case(name, "$_RANDOM_MAX")) {
        return runtime->random_max;
    }
    if (equal_case(name, "$_JITTER_ENABLED")) {
        return runtime->jitter_enabled;
    }
    if (equal_case(name, "$_JITTER_MAX")) {
        return runtime->jitter_max;
    }
    if (equal_case(name, "$_EXFIL_MODE_ENABLED")) {
        return runtime->io->exfil_mode_enabled != NULL &&
               runtime->io->exfil_mode_enabled(runtime->io->context);
    }
    if (equal_case(name, "$_SYSTEM_LEDS_ENABLED")) {
        return runtime->system_leds_enabled;
    }
    if (equal_case(name, "$_STORAGE_LEDS_ENABLED")) return runtime->storage_leds_enabled;
    if (equal_case(name, "$_LED_CONTINUOUS_SHOW_STORAGE_ACTIVITY")) return runtime->continuous_storage_led;
    if (equal_case(name, "$_INJECTING_LEDS_ENABLED")) return runtime->injecting_leds_enabled;
    if (equal_case(name, "$_EXFIL_LEDS_ENABLED")) return runtime->exfil_leds_enabled;
    if (equal_case(name, "$_LED_SHOW_CAPS")) return runtime->led_show_caps;
    if (equal_case(name, "$_LED_SHOW_NUM")) return runtime->led_show_num;
    if (equal_case(name, "$_LED_SHOW_SCROLL")) return runtime->led_show_scroll;
    if (equal_case(name, "$_STORAGE_ACTIVITY_TIMEOUT")) return runtime->storage_activity_timeout_ms;
    if (equal_case(name, "$_RANDOM_SEED")) return runtime->random_seed;
    if (equal_case(name, "$_RANDOM_LOWER_LETTER_KEYCODE") ||
        equal_case(name, "$_RANDOM_UPPER_LETTER_KEYCODE") ||
        equal_case(name, "$_RANDOM_LETTER_KEYCODE")) {
        return 0x04 + (random_u32(runtime) % 26U);
    }
    if (equal_case(name, "$_RANDOM_NUMBER_KEYCODE") ||
        equal_case(name, "$_RANDOM_SPECIAL_KEYCODE")) {
        uint32_t digit = random_u32(runtime) % 10U;
        return digit == 0U ? 0x27 : 0x1d + digit;
    }
    if (equal_case(name, "$_RANDOM_CHAR_KEYCODE")) {
        uint32_t choice = random_u32(runtime) % 46U;
        if (choice < 26U) return 0x04 + choice;
        choice %= 10U;
        return choice == 0U ? 0x27 : 0x1d + choice;
    }
    if (equal_case(name, "$_OS")) {
        return runtime->os;
    }
    if (equal_case(name, "$_CURRENT_VID")) {
        return runtime->io->current_vid != NULL ? swap_usb_id(runtime->io->current_vid(runtime->io->context)) : 0;
    }
    if (equal_case(name, "$_CURRENT_PID")) {
        return runtime->io->current_pid != NULL ? swap_usb_id(runtime->io->current_pid(runtime->io->context)) : 0;
    }
    if (equal_case(name, "$_CURRENT_ATTACKMODE")) {
        return runtime->io->current_attackmode != NULL
            ? runtime->io->current_attackmode(runtime->io->context) : runtime->current_attackmode;
    }
    if (equal_case(name, "$_RANDOM_INT")) {
        int64_t minimum = runtime->random_min;
        int64_t maximum = runtime->random_max;
        if (maximum < minimum) {
            int64_t swap = minimum;
            minimum = maximum;
            maximum = swap;
        }
        uint64_t range = (uint64_t)(maximum - minimum) + 1;
        return minimum + (int64_t)(random_u32(runtime) % range);
    }
    *found = false;
    return 0;
}

static int64_t expression_parse_primary(expression_parser_t *parser)
{
    expression_skip_space(parser);
    if (expression_match(parser, "(")) {
        int64_t value = expression_parse_or(parser);
        if (!expression_match(parser, ")")) {
            parser->ok = false;
        }
        return value;
    }

    size_t start = parser->position;
    if (start < parser->input.length &&
        isdigit((unsigned char)parser->input.data[start])) {
        int base = 10;
        if (start + 2 <= parser->input.length && parser->input.data[start] == '0' &&
            (parser->input.data[start + 1] == 'x' || parser->input.data[start + 1] == 'X')) {
            base = 16;
            parser->position += 2;
        }
        uint64_t value = 0;
        size_t digits = 0;
        while (parser->position < parser->input.length) {
            unsigned char character = (unsigned char)parser->input.data[parser->position];
            int digit = isdigit(character) ? character - '0'
                      : (base == 16 && character >= 'a' && character <= 'f') ? character - 'a' + 10
                      : (base == 16 && character >= 'A' && character <= 'F') ? character - 'A' + 10
                      : -1;
            if (digit < 0 || digit >= base) {
                break;
            }
            value = value * (unsigned)base + (unsigned)digit;
            ++parser->position;
            ++digits;
        }
        if (digits == 0 || value > INT64_MAX) {
            parser->ok = false;
        }
        return (int64_t)value;
    }

    if (start < parser->input.length &&
        (isalpha((unsigned char)parser->input.data[start]) ||
         parser->input.data[start] == '_' || parser->input.data[start] == '$' ||
         parser->input.data[start] == '#')) {
        ++parser->position;
        while (parser->position < parser->input.length &&
               (isalnum((unsigned char)parser->input.data[parser->position]) ||
                parser->input.data[parser->position] == '_')) {
            ++parser->position;
        }
        slice_t name = {
            parser->input.data + start,
            parser->position - start,
        };
        if (equal_case(name, "TRUE")) {
            return 1;
        }
        if (equal_case(name, "FALSE")) {
            return 0;
        }
        if (equal_case(name, "WINDOWS")) return 1;
        if (equal_case(name, "LINUX")) return 2;
        if (equal_case(name, "MACOS")) return 3;
        if (equal_case(name, "CHROMEOS")) return 4;
        if (equal_case(name, "ANDROID")) return 5;
        if (equal_case(name, "IOS")) return 6;
        expression_skip_space(parser);
        if (parser->position < parser->input.length && parser->input.data[parser->position] == '(') {
            ++parser->position;
            expression_skip_space(parser);
            if (parser->position >= parser->input.length || parser->input.data[parser->position] != ')') {
                parser->ok = false;
                return 0;
            }
            ++parser->position;
            function_t *function = find_function(parser->runtime, name);
            int64_t value = 0;
            if (function == NULL || !run_function(parser->runtime, function, &value)) {
                parser->ok = false;
            }
            return value;
        }

        bool found = false;
        int64_t internal = expression_internal_variable(parser->runtime, name, &found);
        if (found) {
            return internal;
        }
        int constant = constant_index(parser->runtime, name);
        if (constant >= 0) {
            expression_parser_t nested = {
                .runtime = parser->runtime,
                .input = parser->runtime->constants[constant].replacement,
                .source_line = parser->source_line,
                .ok = true,
            };
            int64_t value = expression_parse_or(&nested);
            expression_skip_space(&nested);
            if (!nested.ok || nested.position != nested.input.length) {
                parser->ok = false;
            }
            return value;
        }
        int index = variable_index(parser->runtime, name);
        if (index < 0) {
            parser->ok = false;
            return 0;
        }
        return parser->runtime->variables[index].value;
    }

    parser->ok = false;
    return 0;
}

static int64_t expression_parse_unary(expression_parser_t *parser)
{
    if (expression_match(parser, "!")) {
        return !expression_parse_unary(parser);
    }
    if (expression_match_keyword(parser, "NOT")) {
        return !expression_parse_unary(parser);
    }
    if (expression_match(parser, "-")) {
        return -expression_parse_unary(parser);
    }
    if (expression_match(parser, "+")) {
        return expression_parse_unary(parser);
    }
    if (expression_match(parser, "~")) {
        return ~expression_parse_unary(parser);
    }
    return expression_parse_primary(parser);
}

static int64_t expression_parse_power(expression_parser_t *parser)
{
    int64_t base = expression_parse_unary(parser);
    if (!parser->ok || !expression_match(parser, "^")) {
        return base;
    }
    int64_t exponent = expression_parse_power(parser);
    if (exponent < 0 || exponent > 63) {
        parser->ok = false;
        return 0;
    }
    int64_t result = 1;
    for (int64_t i = 0; i < exponent; ++i) {
        int64_t next;
        if (__builtin_mul_overflow(result, base, &next)) {
            parser->ok = false;
            return 0;
        }
        result = next;
    }
    return result;
}

static int64_t expression_parse_multiply(expression_parser_t *parser)
{
    int64_t value = expression_parse_power(parser);
    while (parser->ok) {
        if (expression_match(parser, "*")) {
            value *= expression_parse_power(parser);
        } else if (expression_match(parser, "/")) {
            int64_t divisor = expression_parse_power(parser);
            if (divisor == 0) {
                parser->ok = false;
            } else {
                value /= divisor;
            }
        } else if (expression_match(parser, "%")) {
            int64_t divisor = expression_parse_power(parser);
            if (divisor == 0) {
                parser->ok = false;
            } else {
                value %= divisor;
            }
        } else {
            break;
        }
    }
    return value;
}

static int64_t expression_parse_add(expression_parser_t *parser)
{
    int64_t value = expression_parse_multiply(parser);
    while (parser->ok) {
        if (expression_match(parser, "+")) {
            value += expression_parse_multiply(parser);
        } else if (expression_match(parser, "-")) {
            value -= expression_parse_multiply(parser);
        } else {
            break;
        }
    }
    return value;
}

static int64_t expression_parse_shift(expression_parser_t *parser)
{
    int64_t value = expression_parse_add(parser);
    while (parser->ok) {
        if (expression_match(parser, "<<")) {
            int64_t count = expression_parse_add(parser);
            if (count < 0 || count >= 64) {
                parser->ok = false;
            } else {
                value <<= count;
            }
        } else if (expression_match(parser, ">>")) {
            int64_t count = expression_parse_add(parser);
            if (count < 0 || count >= 64) {
                parser->ok = false;
            } else {
                value >>= count;
            }
        } else {
            break;
        }
    }
    return value;
}

static int64_t expression_parse_compare(expression_parser_t *parser)
{
    int64_t value = expression_parse_shift(parser);
    while (parser->ok) {
        if (expression_match(parser, "<=")) {
            value = value <= expression_parse_shift(parser);
        } else if (expression_match(parser, ">=")) {
            value = value >= expression_parse_shift(parser);
        } else if (expression_match(parser, "<")) {
            value = value < expression_parse_shift(parser);
        } else if (expression_match(parser, ">")) {
            value = value > expression_parse_shift(parser);
        } else {
            break;
        }
    }
    return value;
}

static int64_t expression_parse_equal(expression_parser_t *parser)
{
    int64_t value = expression_parse_compare(parser);
    while (parser->ok) {
        if (expression_match(parser, "==")) {
            value = value == expression_parse_compare(parser);
        } else if (expression_match(parser, "!=")) {
            value = value != expression_parse_compare(parser);
        } else {
            break;
        }
    }
    return value;
}

static int64_t expression_parse_bit_and(expression_parser_t *parser)
{
    int64_t value = expression_parse_equal(parser);
    while (parser->ok) {
        expression_skip_space(parser);
        if (parser->position + 1 < parser->input.length &&
            parser->input.data[parser->position] == '&' &&
            parser->input.data[parser->position + 1] == '&') {
            break;
        }
        if (expression_match(parser, "&")) {
            value &= expression_parse_equal(parser);
        } else {
            break;
        }
    }
    return value;
}

static int64_t expression_parse_bit_or(expression_parser_t *parser)
{
    int64_t value = expression_parse_bit_and(parser);
    while (parser->ok) {
        expression_skip_space(parser);
        if (parser->position + 1 < parser->input.length &&
            parser->input.data[parser->position] == '|' &&
            parser->input.data[parser->position + 1] == '|') {
            break;
        }
        if (expression_match(parser, "|")) {
            value |= expression_parse_bit_and(parser);
        } else {
            break;
        }
    }
    return value;
}

static int64_t expression_parse_and(expression_parser_t *parser)
{
    int64_t value = expression_parse_bit_or(parser);
    while (parser->ok) {
        if (expression_match(parser, "&&") || expression_match_keyword(parser, "AND")) {
            int64_t right = expression_parse_bit_or(parser);
            value = value && right;
        } else {
            break;
        }
    }
    return value;
}

static int64_t expression_parse_or(expression_parser_t *parser)
{
    int64_t value = expression_parse_and(parser);
    while (parser->ok) {
        if (expression_match(parser, "||") || expression_match_keyword(parser, "OR")) {
            int64_t right = expression_parse_and(parser);
            value = value || right;
        } else {
            break;
        }
    }
    return value;
}

static bool evaluate_expression(runtime_t *runtime, slice_t expression, size_t line, int64_t *value)
{
    expression_parser_t parser = {
        .runtime = runtime,
        .input = trim(expression),
        .source_line = line,
        .ok = true,
    };
    *value = expression_parse_or(&parser);
    expression_skip_space(&parser);
    if (!parser.ok || parser.position != parser.input.length) {
        if (runtime->result.status == DUCKY_OK) {
            set_error(runtime, DUCKY_PARSE_ERROR, line, "Invalid expression");
        }
        return false;
    }
    return true;
}

static bool key_in_array(const uint8_t keys[6], uint8_t key)
{
    for (size_t i = 0; i < 6; ++i) {
        if (keys[i] == key) {
            return true;
        }
    }
    return false;
}

static bool add_key(uint8_t keys[6], uint8_t key)
{
    if (key == 0 || key_in_array(keys, key)) {
        return true;
    }
    for (size_t i = 0; i < 6; ++i) {
        if (keys[i] == 0) {
            keys[i] = key;
            return true;
        }
    }
    return false;
}

static void remove_key(uint8_t keys[6], uint8_t key)
{
    for (size_t i = 0; i < 6; ++i) {
        if (keys[i] == key) {
            keys[i] = 0;
        }
    }
}

static bool send_keyboard(runtime_t *runtime, uint8_t modifiers, const uint8_t keys[6], size_t line)
{
    if (runtime->io->keyboard == NULL ||
        !runtime->io->keyboard(runtime->io->context, modifiers, keys)) {
        set_error(runtime, DUCKY_IO_ERROR, line, "Keyboard report failed");
        return false;
    }
    return true;
}

static bool tap_keys(
    runtime_t *runtime,
    uint8_t modifiers,
    const uint8_t keys_to_tap[6],
    size_t line)
{
    uint8_t pressed[6];
    memcpy(pressed, runtime->held_keys, sizeof(pressed));
    for (size_t i = 0; i < 6; ++i) {
        if (!add_key(pressed, keys_to_tap[i])) {
            set_error(runtime, DUCKY_LIMIT_EXCEEDED, line, "Keyboard rollover exceeds six keys");
            return false;
        }
    }
    if (!send_keyboard(runtime, runtime->held_modifiers | modifiers, pressed, line)) {
        return false;
    }
    if (!delay_ms(runtime, runtime->config.key_press_ms, line)) return false;
    return send_keyboard(runtime, runtime->held_modifiers, runtime->held_keys, line);
}

static bool type_text_internal(runtime_t *runtime, slice_t text, size_t line, unsigned depth)
{
    if (depth > 8) {
        set_error(runtime, DUCKY_LIMIT_EXCEEDED, line, "Constant expansion depth exceeded");
        return false;
    }
    char variable_text[32];
    if (text.length > 0 && (text.data[0] == '$' || text.data[0] == '#') &&
        variable_index(runtime, text) >= 0) {
        int index = variable_index(runtime, text);
        int length = snprintf(variable_text, sizeof(variable_text), "%" PRId64, runtime->variables[index].value);
        text = (slice_t){variable_text, length > 0 ? (size_t)length : 0};
    }

    for (size_t i = 0; i < text.length; ++i) {
        if (text.data[i] == '#') {
            size_t end = i + 1;
            while (end < text.length &&
                   (isalnum((unsigned char)text.data[end]) || text.data[end] == '_')) {
                ++end;
            }
            slice_t name = {text.data + i, end - i};
            int constant = constant_index(runtime, name);
            if (constant >= 0) {
                if (!type_text_internal(runtime, runtime->constants[constant].replacement, line, depth + 1)) {
                    return false;
                }
                i = end - 1;
                continue;
            }
        }
        uint8_t key = 0;
        uint8_t modifiers = 0;
        if (!ducky_ascii_to_key(text.data[i], &key, &modifiers)) {
            set_error(runtime, DUCKY_UNSUPPORTED, line, "STRING contains a character outside the US ASCII keymap");
            return false;
        }
        uint8_t keys[6] = {key};
        if (!tap_keys(runtime, modifiers, keys, line)) {
            return false;
        }
        if (runtime->jitter_enabled && runtime->jitter_max > 0) {
            if (!delay_ms(runtime, random_u32(runtime) % ((uint32_t)runtime->jitter_max + 1), line)) return false;
        }
    }
    return true;
}

static bool type_text(runtime_t *runtime, slice_t text, size_t line)
{
    return type_text_internal(runtime, text, line, 0);
}

static bool next_token(slice_t *input, slice_t *token)
{
    *input = trim(*input);
    if (input->length == 0) {
        *token = (slice_t){0};
        return false;
    }
    size_t length = 0;
    while (length < input->length && !isspace((unsigned char)input->data[length]) &&
           input->data[length] != ',') {
        ++length;
    }
    *token = (slice_t){input->data, length};
    size_t consumed = length;
    while (consumed < input->length &&
           (isspace((unsigned char)input->data[consumed]) || input->data[consumed] == ',')) {
        ++consumed;
    }
    input->data += consumed;
    input->length -= consumed;
    return true;
}

static ducky_key_token_t lookup_key_component(slice_t component, bool hyphenated)
{
    if (hyphenated && component.length == 1U &&
        isalpha((unsigned char)component.data[0])) {
        char letter = (char)tolower((unsigned char)component.data[0]);
        return ducky_lookup_key(&letter, 1U);
    }
    return ducky_lookup_key(component.data, component.length);
}

static bool key_token_is_hyphenated_sequence(slice_t token)
{
    bool saw_separator = false;
    size_t start = 0;
    for (size_t i = 0; i <= token.length; ++i) {
        if (i < token.length && token.data[i] != '-') continue;
        if (i == start) return false;
        slice_t component = {token.data + start, i - start};
        if (lookup_key_component(component, true).kind == DUCKY_KEY_TOKEN_INVALID) {
            return false;
        }
        if (i < token.length) saw_separator = true;
        start = i + 1U;
    }
    return saw_separator;
}

static slice_t next_key_component(slice_t token, bool hyphenated, size_t *offset)
{
    if (!hyphenated) {
        *offset = token.length;
        return token;
    }
    size_t start = *offset;
    size_t end = start;
    while (end < token.length && token.data[end] != '-') ++end;
    *offset = end < token.length ? end + 1U : token.length;
    return (slice_t){token.data + start, end - start};
}

static bool send_key_expression(runtime_t *runtime, slice_t expression, size_t line)
{
    uint8_t modifiers = 0;
    uint8_t keys[6] = {0};
    ducky_key_token_t special = {0};
    size_t special_count = 0;
    slice_t token;
    while (next_token(&expression, &token)) {
        bool hyphenated = key_token_is_hyphenated_sequence(token);
        size_t offset = 0;
        do {
            slice_t component = next_key_component(token, hyphenated, &offset);
            ducky_key_token_t key = lookup_key_component(component, hyphenated);
            if (key.kind == DUCKY_KEY_TOKEN_INVALID) {
                set_error_word(runtime, DUCKY_PARSE_ERROR, line, "Unknown key: ", token);
                return false;
            }
            if (key.kind == DUCKY_KEY_TOKEN_MODIFIER) {
                modifiers |= (uint8_t)key.value;
            } else if (key.kind == DUCKY_KEY_TOKEN_KEY) {
                modifiers |= key.implied_modifiers;
                if (!add_key(keys, (uint8_t)key.value)) {
                    set_error(runtime, DUCKY_LIMIT_EXCEEDED, line, "Keyboard rollover exceeds six keys");
                    return false;
                }
            } else {
                special = key;
                ++special_count;
            }
        } while (offset < token.length);
    }
    if (special_count > 0) {
        if (special_count != 1 || modifiers != 0 || keys[0] != 0) {
            set_error(runtime, DUCKY_PARSE_ERROR, line, "Consumer and system controls must be sent alone");
            return false;
        }
        if (special.kind == DUCKY_KEY_TOKEN_CONSUMER) {
            if (runtime->io->consumer == NULL ||
                !runtime->io->consumer(runtime->io->context, special.value)) {
                set_error(runtime, DUCKY_IO_ERROR, line, "Consumer-control report failed");
                return false;
            }
            if (!delay_ms(runtime, runtime->config.key_press_ms, line)) return false;
            if (!runtime->io->consumer(runtime->io->context, 0)) {
                set_error(runtime, DUCKY_IO_ERROR, line, "Consumer-control release failed");
                return false;
            }
            return true;
        }
        if (runtime->io->system == NULL ||
            !runtime->io->system(runtime->io->context, (uint8_t)special.value)) {
            set_error(runtime, DUCKY_IO_ERROR, line, "System-control report failed");
            return false;
        }
        if (!delay_ms(runtime, runtime->config.key_press_ms, line)) return false;
        if (!runtime->io->system(runtime->io->context, 0)) {
            set_error(runtime, DUCKY_IO_ERROR, line, "System-control release failed");
            return false;
        }
        return true;
    }
    if (modifiers == 0 && keys[0] == 0) {
        set_error(runtime, DUCKY_PARSE_ERROR, line, "Empty key command");
        return false;
    }
    return tap_keys(runtime, modifiers, keys, line);
}

static bool update_held_keys(runtime_t *runtime, slice_t expression, bool hold, size_t line)
{
    if (expression.length == 0 && !hold) {
        runtime->held_modifiers = 0;
        memset(runtime->held_keys, 0, sizeof(runtime->held_keys));
        runtime->mouse_buttons = 0;
        if (!send_keyboard(runtime, 0, runtime->held_keys, line)) {
            return false;
        }
        return runtime->io->mouse == NULL ||
               runtime->io->mouse(runtime->io->context, 0, 0, 0, 0, 0);
    }
    slice_t token;
    while (next_token(&expression, &token)) {
        bool hyphenated = key_token_is_hyphenated_sequence(token);
        size_t offset = 0;
        do {
            slice_t component = next_key_component(token, hyphenated, &offset);
            ducky_key_token_t key = lookup_key_component(component, hyphenated);
            if (key.kind == DUCKY_KEY_TOKEN_MODIFIER) {
                if (hold) {
                    runtime->held_modifiers |= (uint8_t)key.value;
                } else {
                    runtime->held_modifiers &= (uint8_t)~key.value;
                }
            } else if (key.kind == DUCKY_KEY_TOKEN_KEY) {
                if (hold) {
                    if (!add_key(runtime->held_keys, (uint8_t)key.value)) {
                        set_error(runtime, DUCKY_LIMIT_EXCEEDED, line,
                                  "Keyboard rollover exceeds six keys");
                        return false;
                    }
                    runtime->held_modifiers |= key.implied_modifiers;
                } else {
                    remove_key(runtime->held_keys, (uint8_t)key.value);
                    runtime->held_modifiers &= (uint8_t)~key.implied_modifiers;
                }
            } else {
                set_error(runtime, DUCKY_UNSUPPORTED, line,
                          "HOLD supports keyboard keys and modifiers only");
                return false;
            }
        } while (offset < token.length);
    }
    return send_keyboard(runtime, runtime->held_modifiers, runtime->held_keys, line);
}

static bool parse_arguments(
    runtime_t *runtime,
    slice_t arguments,
    size_t line,
    int64_t *values,
    size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        slice_t token;
        if (!next_token(&arguments, &token) || !evaluate_expression(runtime, token, line, &values[i])) {
            if (runtime->result.status == DUCKY_OK) {
                set_error(runtime, DUCKY_PARSE_ERROR, line, "Missing or invalid command argument");
            }
            return false;
        }
    }
    if (trim(arguments).length != 0) {
        set_error(runtime, DUCKY_PARSE_ERROR, line, "Too many command arguments");
        return false;
    }
    return true;
}

static int8_t clamp_i8(int64_t value)
{
    return value < -127 ? -127 : value > 127 ? 127 : (int8_t)value;
}

static int16_t clamp_absolute(int64_t value)
{
    return value < 0 ? 0 : value > 32767 ? 32767 : (int16_t)value;
}

static bool send_mouse(runtime_t *runtime, int8_t x, int8_t y, int8_t wheel, int8_t pan, size_t line)
{
    if (runtime->io->mouse == NULL ||
        !runtime->io->mouse(runtime->io->context, runtime->mouse_buttons, x, y, wheel, pan)) {
        set_error(runtime, DUCKY_IO_ERROR, line, "Mouse report failed");
        return false;
    }
    return true;
}

static bool mouse_button_command(
    runtime_t *runtime,
    slice_t arguments,
    bool hold,
    bool release,
    size_t line)
{
    slice_t button_name;
    if (!next_token(&arguments, &button_name) || trim(arguments).length != 0) {
        set_error(runtime, DUCKY_PARSE_ERROR, line, "Mouse command requires one button name");
        return false;
    }
    uint8_t button;
    if (!ducky_lookup_mouse_button(button_name.data, button_name.length, &button)) {
        set_error_word(runtime, DUCKY_PARSE_ERROR, line, "Unknown mouse button: ", button_name);
        return false;
    }
    if (hold) {
        runtime->mouse_buttons |= button;
        return send_mouse(runtime, 0, 0, 0, 0, line);
    }
    if (release) {
        runtime->mouse_buttons &= (uint8_t)~button;
        return send_mouse(runtime, 0, 0, 0, 0, line);
    }
    uint8_t previous = runtime->mouse_buttons;
    runtime->mouse_buttons |= button;
    if (!send_mouse(runtime, 0, 0, 0, 0, line)) {
        return false;
    }
    if (!delay_ms(runtime, runtime->config.key_press_ms, line)) return false;
    runtime->mouse_buttons = previous;
    return send_mouse(runtime, 0, 0, 0, 0, line);
}

static bool wait_for_lock(runtime_t *runtime, uint8_t mask, bool desired, size_t line)
{
    if (runtime->io->keyboard_leds == NULL) {
        set_error(runtime, DUCKY_UNSUPPORTED, line, "Host keyboard LED feedback is unavailable");
        return false;
    }
    uint32_t elapsed = 0;
    while (((runtime->io->keyboard_leds(runtime->io->context) & mask) != 0) != desired) {
        if (runtime->config.lock_wait_timeout_ms != 0 &&
            elapsed >= runtime->config.lock_wait_timeout_ms) {
            set_error(runtime, DUCKY_IO_ERROR, line, "Timed out waiting for host lock state");
            return false;
        }
        if (!delay_ms(runtime, 5, line)) return false;
        elapsed += 5;
    }
    return true;
}

static bool wait_for_lock_change(runtime_t *runtime, uint8_t mask, size_t line)
{
    if (runtime->io->keyboard_leds == NULL) {
        set_error(runtime, DUCKY_UNSUPPORTED, line, "Host keyboard LED feedback is unavailable");
        return false;
    }
    bool initial = (runtime->io->keyboard_leds(runtime->io->context) & mask) != 0;
    uint32_t elapsed = 0;
    while (((runtime->io->keyboard_leds(runtime->io->context) & mask) != 0) == initial) {
        if (runtime->config.lock_wait_timeout_ms != 0 &&
            elapsed >= runtime->config.lock_wait_timeout_ms) {
            set_error(runtime, DUCKY_IO_ERROR, line, "Timed out waiting for host lock state change");
            return false;
        }
        if (!delay_ms(runtime, 5, line)) return false;
        elapsed += 5;
    }
    return true;
}

static bool execute_button_block(runtime_t *runtime)
{
    if (runtime->button_first_line == SIZE_MAX) {
        return true;
    }
    int64_t ignored = 0;
    run_outcome_t outcome = run_range(
        runtime,
        runtime->button_first_line + 1,
        runtime->button_end_line,
        false,
        &ignored);
    if (outcome == RUN_STOPPED && runtime->result.status == DUCKY_OK) {
        set_error(runtime, DUCKY_STOPPED, runtime->button_first_line,
                  "Payload stopped from BUTTON_DEF");
    }
    return outcome == RUN_FINISHED;
}

static bool poll_async_button(runtime_t *runtime, size_t line)
{
    if (!runtime->button_enabled || runtime->button_wait_active ||
        runtime->button_handler_active || runtime->io->button_pressed == NULL) {
        return true;
    }
    if (!runtime->io->button_pressed(runtime->io->context, runtime->button_debounce_ms)) {
        return true;
    }
    runtime->button_push_received = true;
    if (runtime->button_first_line == SIZE_MAX) {
        set_error(runtime, DUCKY_STOPPED, line, "Payload stopped by button");
        return false;
    }
    runtime->button_handler_active = true;
    bool ok = execute_button_block(runtime);
    runtime->button_handler_active = false;
    return ok;
}

static bool wait_for_storage_state(runtime_t *runtime, bool inactive, size_t line)
{
    if (runtime->io->storage_activity_age_ms == NULL) {
        set_error(runtime, DUCKY_UNSUPPORTED, line, "Storage activity feedback is unavailable");
        return false;
    }
    for (;;) {
        uint32_t age = runtime->io->storage_activity_age_ms(runtime->io->context);
        bool reached = inactive ? age >= runtime->storage_activity_timeout_ms
                                : age <= runtime->storage_activity_timeout_ms;
        if (reached) return true;
        if (!delay_ms(runtime, 10U, line)) return false;
    }
}

static bool slice_prefix_case(slice_t value, const char *prefix, slice_t *suffix)
{
    size_t length = strlen(prefix);
    if (value.length < length) return false;
    for (size_t i = 0; i < length; ++i) {
        if (toupper((unsigned char)value.data[i]) !=
            toupper((unsigned char)prefix[i])) return false;
    }
    if (suffix != NULL) {
        *suffix = (slice_t){value.data + length, value.length - length};
    }
    return true;
}

static bool parse_attack_hex(slice_t token, const char *prefix, uint16_t *value)
{
    slice_t suffix;
    if (!slice_prefix_case(token, prefix, &suffix) || suffix.length != 4U) return false;
    uint16_t parsed = 0U;
    for (size_t i = 0; i < suffix.length; ++i) {
        unsigned char c = (unsigned char)suffix.data[i];
        int digit = isdigit(c) ? c - '0' :
            (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
            (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (digit < 0) return false;
        parsed = (uint16_t)((parsed << 4) | (uint16_t)digit);
    }
    *value = parsed;
    return true;
}

static bool copy_attack_text(slice_t token, const char *prefix, char *out,
                             size_t capacity, bool digits_only)
{
    slice_t suffix;
    if (!slice_prefix_case(token, prefix, &suffix) || suffix.length == 0U ||
        suffix.length >= capacity) return false;
    for (size_t i = 0; i < suffix.length; ++i) {
        unsigned char c = (unsigned char)suffix.data[i];
        if (digits_only ? !isdigit(c) : !isalnum(c)) return false;
    }
    memcpy(out, suffix.data, suffix.length);
    out[suffix.length] = '\0';
    return true;
}

static void random_attack_text(runtime_t *runtime, char *out, size_t length,
                               bool digits_only)
{
    static const char alnum[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static const char digits[] = "0123456789";
    const char *set = digits_only ? digits : alnum;
    size_t count = digits_only ? sizeof(digits) - 1U : sizeof(alnum) - 1U;
    for (size_t i = 0; i < length; ++i) {
        out[i] = set[random_u32(runtime) % count];
    }
    out[length] = '\0';
}

static bool apply_attackmode_profile(runtime_t *runtime,
                                     const ducky_attackmode_t *profile,
                                     size_t line)
{
    bool ok = false;
    if (runtime->io->attackmode_profile != NULL) {
        ok = runtime->io->attackmode_profile(runtime->io->context, profile);
    } else if (!profile->custom_identity && runtime->io->attackmode != NULL) {
        ok = runtime->io->attackmode(runtime->io->context, profile->mode);
    }
    if (!ok) {
        set_error(runtime, DUCKY_IO_ERROR, line, "ATTACKMODE transition failed");
        return false;
    }
    runtime->current_attackmode = profile->mode;
    runtime->attackmode_profile = *profile;
    return true;
}

static bool execute_action(runtime_t *runtime, size_t line_number, bool *recognized)
{
    slice_t line = get_line(runtime, line_number);
    slice_t arguments;
    slice_t command = first_word(line, &arguments);
    *recognized = true;

    if (equal_case(command, "EXFIL")) {
        slice_t name = trim(arguments);
        int64_t value = 0;
        bool found = false;
        if (name.length >= 3U && name.data[0] == '$' && name.data[1] == '_') {
            for (size_t i = 2U; i < name.length; ++i) {
                if (!(isalnum((unsigned char)name.data[i]) || name.data[i] == '_')) {
                    set_error(runtime, DUCKY_PARSE_ERROR, line_number,
                              "EXFIL requires exactly one variable");
                    return false;
                }
            }
            value = expression_internal_variable(runtime, name, &found);
        } else if (valid_name(name, '$')) {
            int index = variable_index(runtime, name);
            if (index >= 0) {
                value = runtime->variables[index].value;
                found = true;
            }
        }
        if (!found) {
            set_error(runtime, DUCKY_PARSE_ERROR, line_number,
                      "EXFIL requires one defined readable variable");
            return false;
        }
        if (runtime->io->variable_exfil == NULL) {
            set_error(runtime, DUCKY_UNSUPPORTED, line_number,
                      "Variable EXFIL is unavailable");
            return false;
        }
        if (!runtime->io->variable_exfil(runtime->io->context, (uint16_t)value)) {
            set_error(runtime, DUCKY_IO_ERROR, line_number, "EXFIL write failed");
            return false;
        }
        return true;
    }
    if (equal_case(command, "ATTACKMODE")) {
        ducky_attackmode_t profile = {0};
        profile.vid = runtime->io->current_vid != NULL
            ? runtime->io->current_vid(runtime->io->context) : 0U;
        profile.pid = runtime->io->current_pid != NULL
            ? runtime->io->current_pid(runtime->io->context) : 0U;
        bool hid = false, storage = false, off = false;
        bool vid_set = false, pid_set = false;
        bool man_set = false, prod_set = false, serial_set = false;
        slice_t token;
        while (next_token(&arguments, &token)) {
            if (equal_case(token, "HID")) {
                hid = true;
            } else if (equal_case(token, "STORAGE")) {
                storage = true;
            } else if (equal_case(token, "OFF")) {
                off = true;
            } else if (equal_case(token, "VID_RANDOM")) {
                profile.vid = (uint16_t)random_u32(runtime);
                vid_set = true;
            } else if (equal_case(token, "PID_RANDOM")) {
                profile.pid = (uint16_t)random_u32(runtime);
                pid_set = true;
            } else if (equal_case(token, "MAN_RANDOM")) {
                random_attack_text(runtime, profile.manufacturer, 12U, false);
                man_set = true;
            } else if (equal_case(token, "PROD_RANDOM")) {
                random_attack_text(runtime, profile.product, 12U, false);
                prod_set = true;
            } else if (equal_case(token, "SERIAL_RANDOM")) {
                random_attack_text(runtime, profile.serial, 12U, true);
                serial_set = true;
            } else if (parse_attack_hex(token, "VID_", &profile.vid)) {
                vid_set = true;
            } else if (parse_attack_hex(token, "PID_", &profile.pid)) {
                pid_set = true;
            } else if (copy_attack_text(token, "MAN_", profile.manufacturer,
                                        sizeof(profile.manufacturer), false)) {
                man_set = true;
            } else if (copy_attack_text(token, "PROD_", profile.product,
                                        sizeof(profile.product), false)) {
                prod_set = true;
            } else if (copy_attack_text(token, "SERIAL_", profile.serial,
                                        sizeof(profile.serial), true)) {
                serial_set = true;
            } else {
                set_error_word(runtime, DUCKY_PARSE_ERROR, line_number,
                               "Invalid ATTACKMODE option: ", token);
                return false;
            }
        }
        if (off && (hid || storage)) {
            set_error(runtime, DUCKY_PARSE_ERROR, line_number,
                      "ATTACKMODE OFF cannot be combined");
            return false;
        }
        profile.mode = off ? 0U :
            (uint8_t)((hid ? 1U : 0U) | (storage ? 2U : 0U));
        if (!off && profile.mode == 0U) {
            set_error(runtime, DUCKY_PARSE_ERROR, line_number,
                      "ATTACKMODE requires HID, STORAGE or OFF");
            return false;
        }
        if (vid_set != pid_set) {
            set_error(runtime, DUCKY_PARSE_ERROR, line_number,
                      "ATTACKMODE VID and PID must be specified together");
            return false;
        }
        if (man_set != prod_set || man_set != serial_set) {
            set_error(runtime, DUCKY_PARSE_ERROR, line_number,
                      "ATTACKMODE MAN, PROD and SERIAL must be specified together");
            return false;
        }
        profile.custom_identity = vid_set || man_set;
        if (off && profile.custom_identity) {
            set_error(runtime, DUCKY_PARSE_ERROR, line_number,
                      "ATTACKMODE OFF cannot use descriptor options");
            return false;
        }
        return apply_attackmode_profile(runtime, &profile, line_number);
    }
    if (equal_case(command, "SAVE_ATTACKMODE")) {
        runtime->saved_attackmode = runtime->current_attackmode;
        runtime->saved_attackmode_profile = runtime->attackmode_profile;
        runtime->attackmode_saved = true;
        return true;
    }
    if (equal_case(command, "RESTORE_ATTACKMODE")) {
        if (!runtime->attackmode_saved) {
            set_error(runtime, DUCKY_IO_ERROR, line_number,
                      "No saved ATTACKMODE or restore failed");
            return false;
        }
        return apply_attackmode_profile(
            runtime, &runtime->saved_attackmode_profile, line_number);
    }
    if (equal_case(command, "DELAY")) {
        int64_t value;
        if (!evaluate_expression(runtime, arguments, line_number, &value) || value < 0 || value > UINT32_MAX) {
            if (runtime->result.status == DUCKY_OK) {
                set_error(runtime, DUCKY_PARSE_ERROR, line_number, "DELAY must be between 0 and UINT32_MAX");
            }
            return false;
        }
        return delay_ms(runtime, (uint32_t)value, line_number);
    }
    if (equal_case(command, "DEFAULT_DELAY") || equal_case(command, "DEFAULTDELAY")) {
        int64_t value;
        if (!evaluate_expression(runtime, arguments, line_number, &value) || value < 0 || value > UINT32_MAX) {
            if (runtime->result.status == DUCKY_OK) {
                set_error(runtime, DUCKY_PARSE_ERROR, line_number, "DEFAULT_DELAY is out of range");
            }
            return false;
        }
        runtime->default_delay_ms = (uint32_t)value;
        return true;
    }
    if (equal_case(command, "STRING") || equal_case(command, "STRINGLN")) {
        if (!type_text(runtime, arguments, line_number)) {
            return false;
        }
        if (equal_case(command, "STRINGLN")) {
            uint8_t enter[6] = {0x28};
            return tap_keys(runtime, 0, enter, line_number);
        }
        return true;
    }
    if (equal_case(command, "HOLD")) {
        return update_held_keys(runtime, arguments, true, line_number);
    }
    if (equal_case(command, "RELEASE")) {
        return update_held_keys(runtime, arguments, false, line_number);
    }
    if (equal_case(command, "INJECT_MOD")) {
        return arguments.length == 0 || send_key_expression(runtime, arguments, line_number);
    }
    if (equal_case(command, "INJECT_VAR")) {
        int64_t value = 0;
        if (!evaluate_expression(runtime, arguments, line_number, &value) ||
            value <= 0 || value > UINT8_MAX) {
            if (runtime->result.status == DUCKY_OK) {
                set_error(runtime, DUCKY_PARSE_ERROR, line_number,
                          "INJECT_VAR requires a HID keycode from 1 to 255");
            }
            return false;
        }
        uint8_t keys[6] = {(uint8_t)value};
        return tap_keys(runtime, 0U, keys, line_number);
    }
    if (equal_case(command, "RESET")) {
        return update_held_keys(runtime, (slice_t){0}, false, line_number);
    }
    if (equal_case(command, "MOUSE_MOVE")) {
        int64_t values[2];
        return parse_arguments(runtime, arguments, line_number, values, 2) &&
               send_mouse(runtime, clamp_i8(values[0]), clamp_i8(values[1]), 0, 0, line_number);
    }
    if (equal_case(command, "MOUSE_WHEEL")) {
        int64_t value;
        return parse_arguments(runtime, arguments, line_number, &value, 1) &&
               send_mouse(runtime, 0, 0, clamp_i8(value), 0, line_number);
    }
    if (equal_case(command, "MOUSE_PAN")) {
        int64_t value;
        return parse_arguments(runtime, arguments, line_number, &value, 1) &&
               send_mouse(runtime, 0, 0, 0, clamp_i8(value), line_number);
    }
    if (equal_case(command, "MOUSE_CLICK")) {
        return mouse_button_command(runtime, arguments, false, false, line_number);
    }
    if (equal_case(command, "MOUSE_HOLD")) {
        return mouse_button_command(runtime, arguments, true, false, line_number);
    }
    if (equal_case(command, "MOUSE_RELEASE")) {
        return mouse_button_command(runtime, arguments, false, true, line_number);
    }
    if (equal_case(command, "MOUSE_ABSOLUTE")) {
        int64_t values[2];
        if (!parse_arguments(runtime, arguments, line_number, values, 2)) {
            return false;
        }
        if (runtime->io->absolute_mouse == NULL ||
            !runtime->io->absolute_mouse(
                runtime->io->context,
                runtime->mouse_buttons,
                clamp_absolute(values[0]),
                clamp_absolute(values[1]),
                0,
                0)) {
            set_error(runtime, DUCKY_IO_ERROR, line_number, "Absolute-mouse report failed");
            return false;
        }
        return true;
    }
    if (equal_case(command, "WAIT_FOR_BUTTON_PRESS")) {
        if (!runtime->button_enabled ||
            (runtime->io->button_pressed == NULL && runtime->io->wait_for_button == NULL)) {
            set_error(runtime, DUCKY_UNSUPPORTED, line_number, "Payload button is disabled or unavailable");
            return false;
        }
        runtime->button_wait_active = true;
        bool pressed = false;
        if (runtime->io->button_pressed != NULL) {
            uint32_t elapsed = 0U;
            for (;;) {
                if (runtime->io->button_pressed(
                        runtime->io->context, runtime->button_debounce_ms)) {
                    pressed = true;
                    break;
                }
                if (runtime->config.button_timeout_ms != 0U &&
                    elapsed >= runtime->config.button_timeout_ms) break;
                if (!delay_ms(runtime, 10U, line_number)) {
                    runtime->button_wait_active = false;
                    return false;
                }
                elapsed += 10U;
            }
        } else {
            pressed = runtime->io->wait_for_button(
                runtime->io->context, runtime->config.button_timeout_ms);
        }
        runtime->button_wait_active = false;
        runtime->button_push_received = pressed;
        return !pressed || execute_button_block(runtime);
    }
    if (equal_case(command, "ENABLE_BUTTON")) {
        runtime->button_enabled = true;
        return true;
    }
    if (equal_case(command, "DISABLE_BUTTON")) {
        runtime->button_enabled = false;
        return true;
    }
    if (equal_case(command, "LED_ON") || equal_case(command, "LED_R") ||
        equal_case(command, "LED_RED") || equal_case(command, "LED_G") ||
        equal_case(command, "LED_GREEN") || equal_case(command, "LED_OFF")) {
        if (runtime->io->status_led != NULL) {
            uint8_t state = equal_case(command, "LED_OFF") ? 0U :
                ((equal_case(command, "LED_R") || equal_case(command, "LED_RED")) ? 1U : 2U);
            runtime->io->status_led(runtime->io->context, state);
        }
        return true;
    }
    if (equal_case(command, "WAIT_FOR_STORAGE_ACTIVITY")) {
        return arguments.length == 0U && wait_for_storage_state(runtime, false, line_number);
    }
    if (equal_case(command, "WAIT_FOR_STORAGE_INACTIVITY")) {
        return arguments.length == 0U && wait_for_storage_state(runtime, true, line_number);
    }
    if (equal_case(command, "WAIT_FOR_CAPS_ON")) {
        return wait_for_lock(runtime, DUCKY_LED_CAPS_LOCK, true, line_number);
    }
    if (equal_case(command, "WAIT_FOR_CAPS_OFF")) {
        return wait_for_lock(runtime, DUCKY_LED_CAPS_LOCK, false, line_number);
    }
    if (equal_case(command, "WAIT_FOR_CAPS_CHANGE")) {
        return wait_for_lock_change(runtime, DUCKY_LED_CAPS_LOCK, line_number);
    }
    if (equal_case(command, "WAIT_FOR_NUM_ON")) {
        return wait_for_lock(runtime, DUCKY_LED_NUM_LOCK, true, line_number);
    }
    if (equal_case(command, "WAIT_FOR_NUM_OFF")) {
        return wait_for_lock(runtime, DUCKY_LED_NUM_LOCK, false, line_number);
    }
    if (equal_case(command, "WAIT_FOR_NUM_CHANGE")) {
        return wait_for_lock_change(runtime, DUCKY_LED_NUM_LOCK, line_number);
    }
    if (equal_case(command, "WAIT_FOR_SCROLL_ON")) {
        return wait_for_lock(runtime, DUCKY_LED_SCROLL_LOCK, true, line_number);
    }
    if (equal_case(command, "WAIT_FOR_SCROLL_OFF")) {
        return wait_for_lock(runtime, DUCKY_LED_SCROLL_LOCK, false, line_number);
    }
    if (equal_case(command, "WAIT_FOR_SCROLL_CHANGE")) {
        return wait_for_lock_change(runtime, DUCKY_LED_SCROLL_LOCK, line_number);
    }
    if (equal_case(command, "SAVE_HOST_KEYBOARD_LOCK_STATE")) {
        runtime->saved_lock_state = runtime->io->keyboard_leds != NULL
            ? runtime->io->keyboard_leds(runtime->io->context)
            : 0;
        runtime->lock_state_saved = true;
        return true;
    }
    if (equal_case(command, "RESTORE_HOST_KEYBOARD_LOCK_STATE")) {
        if (!runtime->lock_state_saved || runtime->io->keyboard_leds == NULL) {
            set_error(runtime, DUCKY_UNSUPPORTED, line_number, "No saved keyboard lock state");
            return false;
        }
        const uint8_t masks[] = {DUCKY_LED_CAPS_LOCK, DUCKY_LED_NUM_LOCK, DUCKY_LED_SCROLL_LOCK};
        const uint8_t keys[] = {0x39, 0x53, 0x47};
        for (size_t i = 0; i < 3; ++i) {
            uint8_t current = runtime->io->keyboard_leds(runtime->io->context);
            if ((current & masks[i]) != (runtime->saved_lock_state & masks[i])) {
                uint8_t keycodes[6] = {keys[i]};
                if (!tap_keys(runtime, 0, keycodes, line_number)) {
                    return false;
                }
                if (!wait_for_lock(runtime, masks[i], (runtime->saved_lock_state & masks[i]) != 0, line_number)) {
                    return false;
                }
            }
        }
        return true;
    }
    if (equal_case(command, "RANDOM_LOWERCASE_LETTER") ||
        equal_case(command, "RANDOM_UPPERCASE_LETTER") ||
        equal_case(command, "RANDOM_LETTER") || equal_case(command, "RANDOM_NUMBER") ||
        equal_case(command, "RANDOM_SPECIAL") || equal_case(command, "RANDOM_CHAR")) {
        static const char lower[] = "abcdefghijklmnopqrstuvwxyz";
        static const char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        static const char letters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        static const char numbers[] = "0123456789";
        static const char special[] = "!@#$%^&*()";
        static const char all[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
        const char *set = numbers; size_t n = sizeof(numbers) - 1U;
        if (equal_case(command, "RANDOM_LOWERCASE_LETTER")) { set=lower; n=sizeof(lower)-1U; }
        else if (equal_case(command, "RANDOM_UPPERCASE_LETTER")) { set=upper; n=sizeof(upper)-1U; }
        else if (equal_case(command, "RANDOM_LETTER")) { set=letters; n=sizeof(letters)-1U; }
        else if (equal_case(command, "RANDOM_SPECIAL")) { set=special; n=sizeof(special)-1U; }
        else if (equal_case(command, "RANDOM_CHAR")) { set=all; n=sizeof(all)-1U; }
        char character = set[random_u32(runtime) % n];
        return type_text(runtime, (slice_t){&character, 1}, line_number);
    }

    *recognized = false;
    return send_key_expression(runtime, line, line_number);
}

static bool parse_assignment(
    runtime_t *runtime,
    slice_t line,
    size_t source_line,
    bool define,
    bool read_only)
{
    line = trim(line);
    size_t name_length = 0;
    while (name_length < line.length &&
           (isalnum((unsigned char)line.data[name_length]) || line.data[name_length] == '_' ||
            line.data[name_length] == '$' || line.data[name_length] == '#')) {
        ++name_length;
    }
    slice_t name = {line.data, name_length};
    char prefix = read_only ? '#' : '$';
    bool valid_internal = !read_only && name.length >= 3 &&
        name.data[0] == '$' && name.data[1] == '_';
    for (size_t i = 2; valid_internal && i < name.length; ++i) {
        if (!(isalnum((unsigned char)name.data[i]) || name.data[i] == '_')) {
            valid_internal = false;
        }
    }
    if (!valid_name(name, prefix) && !valid_internal) {
        set_error(runtime, DUCKY_PARSE_ERROR, source_line, "Invalid variable or constant name");
        return false;
    }
    slice_t rest = trim((slice_t){line.data + name_length, line.length - name_length});
    if (rest.length == 0 || rest.data[0] != '=') {
        set_error(runtime, DUCKY_PARSE_ERROR, source_line, "Assignment requires '='");
        return false;
    }
    rest = trim((slice_t){rest.data + 1, rest.length - 1});
    int64_t value;
    if (!evaluate_expression(runtime, rest, source_line, &value)) {
        return false;
    }
    if (name.length >= 2 && name.data[0] == '$' && name.data[1] == '_') {
        if (define) {
            set_error(runtime, DUCKY_PARSE_ERROR, source_line, "Internal variables are assigned without VAR");
            return false;
        }
        return set_internal_variable(runtime, name, value, source_line);
    }
    return set_variable(runtime, name, value, define, read_only, source_line);
}

typedef struct {
    bool parent_active;
    bool condition;
    bool saw_else;
} defined_frame_t;

static bool defined_condition(runtime_t *runtime, slice_t arguments, bool invert,
                              size_t line, bool *value)
{
    slice_t name = trim(arguments);
    if (!valid_constant_name(name) || name.data[0] != '#') {
        set_error(runtime, DUCKY_PARSE_ERROR, line,
                  "IF_DEFINED directive requires one #CONSTANT");
        return false;
    }
    int index = constant_index(runtime, name);
    bool is_true = false;
    if (index >= 0) {
        int64_t evaluated = 0;
        if (!evaluate_expression(runtime, runtime->constants[index].replacement, line, &evaluated)) {
            return false;
        }
        is_true = evaluated != 0;
    }
    *value = invert ? !is_true : is_true;
    return true;
}

static bool preprocess_defined_blocks(runtime_t *runtime)
{
    if (runtime->line_count == 0) return true;
    runtime->line_enabled = calloc(runtime->line_count, sizeof(runtime->line_enabled[0]));
    if (runtime->line_enabled == NULL) {
        set_error(runtime, DUCKY_OUT_OF_MEMORY, 0, "Could not allocate compile-time line mask");
        return false;
    }
    defined_frame_t stack[DUCKY_MAX_CALL_DEPTH];
    size_t depth = 0;
    bool active = true;
    bool rem_block = false;
    const char *string_terminator = NULL;
    for (size_t line = 0; line < runtime->line_count; ++line) {
        slice_t arguments;
        slice_t command = first_word(get_line(runtime, line), &arguments);
        if (rem_block) {
            runtime->line_enabled[line] = active;
            if (equal_case(command, "END_REM")) rem_block = false;
            continue;
        }
        if (string_terminator != NULL) {
            runtime->line_enabled[line] = active;
            if (equal_case(command, string_terminator)) string_terminator = NULL;
            continue;
        }
        if (active && equal_case(command, "REM_BLOCK")) {
            runtime->line_enabled[line] = true;
            rem_block = true;
            continue;
        }
        if (active && arguments.length == 0 &&
            (equal_case(command, "STRING") || equal_case(command, "STRINGLN") ||
             equal_case(command, "STRING_POWERSHELL") ||
             equal_case(command, "STRINGLN_POWERSHELL") ||
             equal_case(command, "STRINGLN_BASH") ||
             equal_case(command, "STRINGLN_BLOCK"))) {
            runtime->line_enabled[line] = true;
            string_terminator = (equal_case(command, "STRING") ||
                equal_case(command, "STRING_POWERSHELL")) ? "END_STRING" : "END_STRINGLN";
            continue;
        }
        if (equal_case(command, "IF_DEFINED_TRUE") ||
            equal_case(command, "IF_NOT_DEFINED_TRUE")) {
            runtime->line_enabled[line] = false;
            if (depth == DUCKY_MAX_CALL_DEPTH) {
                set_error(runtime, DUCKY_LIMIT_EXCEEDED, line,
                          "IF_DEFINED nesting depth exceeded");
                return false;
            }
            bool condition = false;
            if (active && !defined_condition(runtime, arguments,
                    equal_case(command, "IF_NOT_DEFINED_TRUE"), line, &condition)) {
                return false;
            }
            stack[depth++] = (defined_frame_t){active, condition, false};
            active = active && condition;
            continue;
        }
        if (equal_case(command, "ELSE_DEFINED")) {
            runtime->line_enabled[line] = false;
            if (arguments.length != 0 || depth == 0 || stack[depth - 1].saw_else) {
                set_error(runtime, DUCKY_PARSE_ERROR, line,
                          "ELSE_DEFINED without one matching IF_DEFINED directive");
                return false;
            }
            stack[depth - 1].saw_else = true;
            active = stack[depth - 1].parent_active && !stack[depth - 1].condition;
            continue;
        }
        if (equal_case(command, "END_IF_DEFINED")) {
            runtime->line_enabled[line] = false;
            if (arguments.length != 0 || depth == 0) {
                set_error(runtime, DUCKY_PARSE_ERROR, line,
                          "END_IF_DEFINED without matching IF_DEFINED directive");
                return false;
            }
            active = stack[--depth].parent_active;
            continue;
        }
        if (equal_case(command, "DEFINE")) {
            runtime->line_enabled[line] = false;
            if (active && !define_constant(runtime, arguments, line)) return false;
            continue;
        }
        runtime->line_enabled[line] = active;
    }
    if (depth != 0) {
        set_error(runtime, DUCKY_PARSE_ERROR, runtime->line_count - 1,
                  "IF_DEFINED directive without END_IF_DEFINED");
        return false;
    }
    return true;
}

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} source_builder_t;

static bool source_builder_reserve(runtime_t *runtime, source_builder_t *builder,
                                   size_t additional, size_t line)
{
    if (additional > SIZE_MAX - builder->length - 1U) {
        set_error(runtime, DUCKY_LIMIT_EXCEEDED, line, "Preprocessed source is too large");
        return false;
    }
    size_t needed = builder->length + additional + 1U;
    if (needed <= builder->capacity) return true;
    size_t capacity = builder->capacity != 0 ? builder->capacity : 256U;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2U) {
            capacity = needed;
            break;
        }
        capacity *= 2U;
    }
    char *grown = (char *)realloc(builder->data, capacity);
    if (grown == NULL) {
        set_error(runtime, DUCKY_OUT_OF_MEMORY, line, "Could not allocate preprocessed source");
        return false;
    }
    builder->data = grown;
    builder->capacity = capacity;
    return true;
}

static bool source_builder_append(runtime_t *runtime, source_builder_t *builder,
                                  const char *data, size_t length, size_t line)
{
    if (!source_builder_reserve(runtime, builder, length, line)) return false;
    if (length != 0) memcpy(builder->data + builder->length, data, length);
    builder->length += length;
    builder->data[builder->length] = '\0';
    return true;
}

static bool append_expanded_source(runtime_t *runtime, source_builder_t *builder,
                                   slice_t source, size_t line, unsigned depth)
{
    if (depth > DUCKY_MAX_CALL_DEPTH) {
        set_error(runtime, DUCKY_LIMIT_EXCEEDED, line, "DEFINE expansion depth exceeded");
        return false;
    }
    size_t copied = 0;
    for (size_t i = 0; i < source.length; ++i) {
        int constant = -1;
        size_t matched = 0U;
        for (size_t candidate = 0; candidate < runtime->constant_count; ++candidate) {
            size_t length = strlen(runtime->constants[candidate].name);
            if (length <= matched || length > source.length - i ||
                memcmp(source.data + i, runtime->constants[candidate].name, length) != 0) {
                continue;
            }
            bool before = i > 0U &&
                (isalnum((unsigned char)source.data[i - 1U]) ||
                 source.data[i - 1U] == '_' || source.data[i - 1U] == '-');
            bool after = i + length < source.length &&
                (isalnum((unsigned char)source.data[i + length]) ||
                 source.data[i + length] == '_' || source.data[i + length] == '-');
            if (before || after) continue;
            constant = (int)candidate;
            matched = length;
        }
        if (constant < 0) continue;
        if (!source_builder_append(runtime, builder, source.data + copied, i - copied, line) ||
            !append_expanded_source(runtime, builder,
                runtime->constants[constant].replacement, line, depth + 1U)) {
            return false;
        }
        copied = i + matched;
        i = copied - 1U;
    }
    return source_builder_append(runtime, builder,
        source.data + copied, source.length - copied, line);
}

static bool build_line_index(runtime_t *runtime);

static bool compile_defined_source(runtime_t *runtime)
{
    source_builder_t builder = {0};
    for (size_t line = 0; line < runtime->line_count; ++line) {
        if (runtime->line_enabled == NULL || runtime->line_enabled[line]) {
            if (!append_expanded_source(runtime, &builder, get_line_raw(runtime, line), line, 0)) {
                free(builder.data);
                return false;
            }
        }
        if (line + 1U < runtime->line_count &&
            !source_builder_append(runtime, &builder, "\n", 1, line)) {
            free(builder.data);
            return false;
        }
    }
    if (builder.data == NULL) {
        builder.data = (char *)calloc(1, 1);
        if (builder.data == NULL) {
            set_error(runtime, DUCKY_OUT_OF_MEMORY, 0, "Could not allocate empty preprocessed source");
            return false;
        }
    }
    free(runtime->line_offsets);
    runtime->line_offsets = NULL;
    free(runtime->line_enabled);
    runtime->line_enabled = NULL;
    runtime->compiled_script = builder.data;
    runtime->script = builder.data;
    runtime->script_length = builder.length;
    return build_line_index(runtime);
}

static bool is_command_at(runtime_t *runtime, size_t line_number, const char *command)
{
    if (runtime->line_enabled != NULL && !runtime->line_enabled[line_number]) return false;
    slice_t arguments;
    return equal_case(first_word(get_line(runtime, line_number), &arguments), command);
}

static const char *literal_block_terminator(slice_t command, slice_t arguments)
{
    if (equal_case(command, "REM_BLOCK")) return "END_REM";
    if (arguments.length != 0U) return NULL;
    if (equal_case(command, "STRING") || equal_case(command, "STRING_POWERSHELL")) {
        return "END_STRING";
    }
    if (equal_case(command, "STRINGLN") || equal_case(command, "STRINGLN_POWERSHELL") ||
        equal_case(command, "STRINGLN_BASH") || equal_case(command, "STRINGLN_BLOCK")) {
        return "END_STRINGLN";
    }
    return NULL;
}

static size_t skip_literal_block(runtime_t *runtime, size_t first_line, size_t end_line)
{
    slice_t arguments;
    slice_t command = first_word(get_line(runtime, first_line), &arguments);
    const char *terminator = literal_block_terminator(command, arguments);
    if (terminator == NULL) return first_line;
    for (size_t line = first_line + 1U; line < end_line; ++line) {
        if (is_command_at(runtime, line, terminator)) return line;
    }
    return SIZE_MAX;
}

static size_t find_matching_forward(
    runtime_t *runtime,
    size_t opener_line,
    size_t end_line,
    const char *opener,
    const char *closer)
{
    unsigned depth = 0;
    for (size_t line = opener_line + 1; line < end_line; ++line) {
        size_t literal_end = skip_literal_block(runtime, line, end_line);
        if (literal_end == SIZE_MAX) return SIZE_MAX;
        if (literal_end != line) {
            line = literal_end;
            continue;
        }
        if (is_command_at(runtime, line, opener)) {
            ++depth;
        } else if (is_command_at(runtime, line, closer)) {
            if (depth == 0) {
                return line;
            }
            --depth;
        }
    }
    return SIZE_MAX;
}

static size_t find_matching_backward(
    runtime_t *runtime,
    size_t closer_line,
    size_t first_line,
    const char *opener,
    const char *closer)
{
    size_t stack[DUCKY_MAX_CALL_DEPTH];
    size_t depth = 0U;
    for (size_t line = first_line; line < closer_line; ++line) {
        size_t literal_end = skip_literal_block(runtime, line, closer_line);
        if (literal_end == SIZE_MAX) return SIZE_MAX;
        if (literal_end != line) {
            line = literal_end;
            continue;
        }
        if (is_command_at(runtime, line, opener)) {
            if (depth == DUCKY_MAX_CALL_DEPTH) return SIZE_MAX;
            stack[depth++] = line;
        } else if (is_command_at(runtime, line, closer)) {
            if (depth == 0U) return SIZE_MAX;
            --depth;
        }
    }
    return depth == 0U ? SIZE_MAX : stack[depth - 1U];
}

static slice_t conditional_expression(slice_t arguments)
{
    arguments = trim(arguments);
    if (arguments.length >= 4 &&
        equal_case((slice_t){arguments.data + arguments.length - 4, 4}, "THEN")) {
        arguments.length -= 4;
        arguments = trim(arguments);
    }
    return arguments;
}

static size_t select_false_if_branch(runtime_t *runtime, size_t if_line, size_t end_line)
{
    unsigned depth = 0;
    for (size_t line = if_line + 1; line < end_line; ++line) {
        size_t literal_end = skip_literal_block(runtime, line, end_line);
        if (literal_end == SIZE_MAX) return SIZE_MAX;
        if (literal_end != line) {
            line = literal_end;
            continue;
        }
        slice_t arguments;
        slice_t command = first_word(get_line(runtime, line), &arguments);
        if (equal_case(command, "IF")) {
            ++depth;
        } else if (equal_case(command, "END_IF")) {
            if (depth == 0) {
                return line + 1;
            }
            --depth;
        } else if (depth == 0 && equal_case(command, "ELSE")) {
            slice_t second_arguments;
            slice_t second = first_word(arguments, &second_arguments);
            if (equal_case(second, "IF")) {
                int64_t condition;
                if (!evaluate_expression(
                        runtime,
                        conditional_expression(second_arguments),
                        line,
                        &condition)) {
                    return SIZE_MAX;
                }
                if (condition) {
                    return line + 1;
                }
            } else if (arguments.length == 0) {
                return line + 1;
            }
        }
    }
    set_error(runtime, DUCKY_PARSE_ERROR, if_line, "IF without matching END_IF");
    return SIZE_MAX;
}

static bool parse_function_declaration(slice_t arguments, slice_t *name)
{
    arguments = trim(arguments);
    if (arguments.length < 3 || arguments.data[arguments.length - 2] != '(' ||
        arguments.data[arguments.length - 1] != ')') {
        return false;
    }
    arguments.length -= 2;
    arguments = trim(arguments);
    if (arguments.length == 0 || arguments.length > DUCKY_MAX_NAME ||
        !(isalpha((unsigned char)arguments.data[0]) || arguments.data[0] == '_')) {
        return false;
    }
    for (size_t i = 1; i < arguments.length; ++i) {
        if (!(isalnum((unsigned char)arguments.data[i]) || arguments.data[i] == '_')) {
            return false;
        }
    }
    *name = arguments;
    return true;
}

static bool scan_blocks(runtime_t *runtime)
{
    runtime->button_first_line = SIZE_MAX;
    runtime->button_end_line = SIZE_MAX;
    bool rem_block = false;
    const char *string_terminator = NULL;
    for (size_t line = 0; line < runtime->line_count; ++line) {
        if (runtime->line_enabled != NULL && !runtime->line_enabled[line]) continue;
        slice_t arguments;
        slice_t scan_command = first_word(get_line(runtime, line), &arguments);
        if (rem_block) {
            if (equal_case(scan_command, "END_REM")) rem_block = false;
            continue;
        }
        if (string_terminator != NULL) {
            if (equal_case(scan_command, string_terminator)) string_terminator = NULL;
            continue;
        }
        if (equal_case(scan_command, "REM_BLOCK")) {
            rem_block = true;
            continue;
        }
        if (arguments.length == 0U &&
            (equal_case(scan_command, "STRING") || equal_case(scan_command, "STRINGLN") ||
             equal_case(scan_command, "STRING_POWERSHELL") ||
             equal_case(scan_command, "STRINGLN_POWERSHELL") ||
             equal_case(scan_command, "STRINGLN_BASH") ||
             equal_case(scan_command, "STRINGLN_BLOCK"))) {
            string_terminator = (equal_case(scan_command, "STRING") ||
                equal_case(scan_command, "STRING_POWERSHELL")) ?
                    "END_STRING" : "END_STRINGLN";
            continue;
        }
        slice_t command = first_word(get_line(runtime, line), &arguments);
        if (equal_case(command, "FUNCTION")) {
            slice_t name;
            if (!parse_function_declaration(arguments, &name)) {
                set_error(runtime, DUCKY_PARSE_ERROR, line, "Invalid FUNCTION declaration");
                return false;
            }
            size_t end = find_matching_forward(
                runtime, line, runtime->line_count, "FUNCTION", "END_FUNCTION");
            if (end == SIZE_MAX) {
                set_error(runtime, DUCKY_PARSE_ERROR, line, "FUNCTION without END_FUNCTION");
                return false;
            }
            if (runtime->function_count == DUCKY_MAX_FUNCTIONS) {
                set_error(runtime, DUCKY_LIMIT_EXCEEDED, line, "Too many functions");
                return false;
            }
            if (find_function(runtime, name) != NULL) {
                set_error_word(runtime, DUCKY_PARSE_ERROR, line, "Duplicate function: ", name);
                return false;
            }
            function_t *function = &runtime->functions[runtime->function_count++];
            memcpy(function->name, name.data, name.length);
            function->name[name.length] = '\0';
            function->first_line = line;
            function->end_line = end;
            line = end;
        } else if (equal_case(command, "BUTTON_DEF")) {
            if (runtime->button_first_line != SIZE_MAX) {
                set_error(runtime, DUCKY_PARSE_ERROR, line, "Only one BUTTON_DEF block is allowed");
                return false;
            }
            size_t end = find_matching_forward(
                runtime, line, runtime->line_count, "BUTTON_DEF", "END_BUTTON");
            if (end == SIZE_MAX) {
                set_error(runtime, DUCKY_PARSE_ERROR, line, "BUTTON_DEF without END_BUTTON");
                return false;
            }
            runtime->button_first_line = line;
            runtime->button_end_line = end;
            line = end;
        }
    }
    return true;
}

static size_t skip_else_branch(runtime_t *runtime, size_t line_number, size_t end_line)
{
    unsigned depth = 0;
    for (size_t line = line_number + 1; line < end_line; ++line) {
        size_t literal_end = skip_literal_block(runtime, line, end_line);
        if (literal_end == SIZE_MAX) return SIZE_MAX;
        if (literal_end != line) {
            line = literal_end;
            continue;
        }
        if (is_command_at(runtime, line, "IF")) {
            ++depth;
        } else if (is_command_at(runtime, line, "END_IF")) {
            if (depth == 0) {
                return line + 1;
            }
            --depth;
        }
    }
    return SIZE_MAX;
}

static size_t find_simple_terminator(
    runtime_t *runtime,
    size_t first_line,
    size_t end_line,
    const char *terminator)
{
    for (size_t line = first_line + 1; line < end_line; ++line) {
        if (is_command_at(runtime, line, terminator)) {
            return line;
        }
    }
    return SIZE_MAX;
}

static bool is_line_comment(slice_t command)
{
    if (equal_case(command, "REM") ||
        (command.length >= 1U && command.data[0] == '#' &&
         (command.length == 1U || command.data[1] == '#'))) return true;
    return command.length > 3U &&
        toupper((unsigned char)command.data[0]) == 'R' &&
        toupper((unsigned char)command.data[1]) == 'E' &&
        toupper((unsigned char)command.data[2]) == 'M' &&
        !isalnum((unsigned char)command.data[3]) && command.data[3] != '_';
}

static run_outcome_t run_range(
    runtime_t *runtime,
    size_t first_line,
    size_t end_line,
    bool is_function,
    int64_t *return_value)
{
    size_t previous_action = SIZE_MAX;
    size_t line_number = first_line;
    while (line_number < end_line) {
        if (++runtime->execution_steps > runtime->config.max_execution_steps) {
            set_error(runtime, DUCKY_LIMIT_EXCEEDED, line_number, "Maximum execution step count exceeded");
            return RUN_FAILED;
        }

        if (runtime->line_enabled != NULL && !runtime->line_enabled[line_number]) {
            ++line_number;
            continue;
        }
        slice_t line = get_line(runtime, line_number);
        slice_t arguments;
        slice_t command = first_word(line, &arguments);
        if (!equal_case(command, "WAIT_FOR_BUTTON_PRESS") &&
            !poll_async_button(runtime, line_number)) {
            return RUN_FAILED;
        }
        if (command.length == 0 || is_line_comment(command)) {
            ++line_number;
            continue;
        }
        if (equal_case(command, "EXTENSION") || equal_case(command, "END_EXTENSION")) {
            ++line_number;
            continue;
        }
        if (equal_case(command, "REM_BLOCK")) {
            size_t end = find_matching_forward(runtime, line_number, end_line, "REM_BLOCK", "END_REM");
            if (end == SIZE_MAX) {
                set_error(runtime, DUCKY_PARSE_ERROR, line_number, "REM_BLOCK without END_REM");
                return RUN_FAILED;
            }
            line_number = end + 1;
            continue;
        }
        if (equal_case(command, "FUNCTION")) {
            size_t end = find_matching_forward(runtime, line_number, end_line, "FUNCTION", "END_FUNCTION");
            if (end == SIZE_MAX) {
                set_error(runtime, DUCKY_PARSE_ERROR, line_number, "FUNCTION without END_FUNCTION");
                return RUN_FAILED;
            }
            line_number = end + 1;
            continue;
        }
        if (equal_case(command, "BUTTON_DEF")) {
            size_t end = find_matching_forward(runtime, line_number, end_line, "BUTTON_DEF", "END_BUTTON");
            if (end == SIZE_MAX) {
                set_error(runtime, DUCKY_PARSE_ERROR, line_number, "BUTTON_DEF without END_BUTTON");
                return RUN_FAILED;
            }
            line_number = end + 1;
            continue;
        }
        if ((equal_case(command, "STRING") || equal_case(command, "STRINGLN") ||
             equal_case(command, "STRING_POWERSHELL") ||
             equal_case(command, "STRINGLN_POWERSHELL") ||
             equal_case(command, "STRINGLN_BASH") ||
             equal_case(command, "STRINGLN_BLOCK")) && arguments.length == 0) {
            const bool newline = !equal_case(command, "STRING") &&
                !equal_case(command, "STRING_POWERSHELL");
            const char *terminator = newline ? "END_STRINGLN" : "END_STRING";
            size_t end = find_simple_terminator(runtime, line_number, end_line, terminator);
            if (end == SIZE_MAX) {
                set_error(runtime, DUCKY_PARSE_ERROR, line_number, "STRING block has no matching terminator");
                return RUN_FAILED;
            }
            for (size_t content_line = line_number + 1; content_line < end; ++content_line) {
                slice_t content = get_line_raw(runtime, content_line);
                if (newline) {
                    /* Hak5 STRINGLN blocks strip exactly the first indentation
                     * tab and preserve every remaining byte on the line. */
                    if (content.length > 0 && content.data[0] == '\t') {
                        ++content.data;
                        --content.length;
                    }
                } else {
                    /* STRING blocks discard indentation and line breaks. */
                    content = trim(content);
                }
                if (!type_text(runtime, content, content_line)) {
                    return RUN_FAILED;
                }
                if (newline) {
                    uint8_t enter[6] = {0x28};
                    if (!tap_keys(runtime, 0, enter, content_line)) {
                        return RUN_FAILED;
                    }
                }
            }
            if (!delay_ms(runtime, runtime->default_delay_ms, line_number)) return RUN_FAILED;
            previous_action = SIZE_MAX;
            line_number = end + 1;
            continue;
        }
        if (equal_case(command, "VAR") || equal_case(command, "LET")) {
            if (!parse_assignment(runtime, arguments, line_number, true, false)) {
                return RUN_FAILED;
            }
            ++line_number;
            continue;
        }
        if (equal_case(command, "DEFINE")) {
            if (!define_constant(runtime, arguments, line_number)) {
                return RUN_FAILED;
            }
            ++line_number;
            continue;
        }
        if (line.data[0] == '$') {
            if (!parse_assignment(runtime, line, line_number, false, false)) {
                return RUN_FAILED;
            }
            ++line_number;
            continue;
        }
        if (equal_case(command, "IF")) {
            int64_t condition;
            if (!evaluate_expression(
                    runtime,
                    conditional_expression(arguments),
                    line_number,
                    &condition)) {
                return RUN_FAILED;
            }
            if (condition) {
                ++line_number;
            } else {
                line_number = select_false_if_branch(runtime, line_number, end_line);
                if (line_number == SIZE_MAX) {
                    return RUN_FAILED;
                }
            }
            continue;
        }
        if (equal_case(command, "ELSE")) {
            size_t end = skip_else_branch(runtime, line_number, end_line);
            if (end == SIZE_MAX) {
                set_error(runtime, DUCKY_PARSE_ERROR, line_number, "ELSE without END_IF");
                return RUN_FAILED;
            }
            line_number = end;
            continue;
        }
        if (equal_case(command, "END_IF")) {
            ++line_number;
            continue;
        }
        if (equal_case(command, "WHILE")) {
            int64_t condition;
            if (!evaluate_expression(runtime, arguments, line_number, &condition)) {
                return RUN_FAILED;
            }
            if (condition) {
                ++line_number;
            } else {
                size_t end = find_matching_forward(runtime, line_number, end_line, "WHILE", "END_WHILE");
                if (end == SIZE_MAX) {
                    set_error(runtime, DUCKY_PARSE_ERROR, line_number, "WHILE without END_WHILE");
                    return RUN_FAILED;
                }
                line_number = end + 1;
            }
            continue;
        }
        if (equal_case(command, "END_WHILE")) {
            size_t start = find_matching_backward(runtime, line_number, first_line, "WHILE", "END_WHILE");
            if (start == SIZE_MAX) {
                set_error(runtime, DUCKY_PARSE_ERROR, line_number, "END_WHILE without WHILE");
                return RUN_FAILED;
            }
            line_number = start;
            continue;
        }
        if (equal_case(command, "RETURN")) {
            if (!is_function) {
                set_error(runtime, DUCKY_PARSE_ERROR, line_number, "RETURN used outside a function");
                return RUN_FAILED;
            }
            *return_value = 0;
            if (arguments.length > 0 &&
                !evaluate_expression(runtime, arguments, line_number, return_value)) {
                return RUN_FAILED;
            }
            return RUN_RETURNED;
        }
        if (equal_case(command, "STOP_PAYLOAD")) {
            return RUN_STOPPED;
        }
        if (equal_case(command, "RESTART_PAYLOAD")) {
            if (is_function || first_line != 0) {
                set_error(runtime, DUCKY_UNSUPPORTED, line_number, "RESTART_PAYLOAD cannot be used in a nested block");
                return RUN_FAILED;
            }
            line_number = 0;
            previous_action = SIZE_MAX;
            continue;
        }
        if (equal_case(command, "REPEAT")) {
            slice_t inline_action;
            slice_t count_expression = first_word(arguments, &inline_action);
            bool inline_key_repeat = inline_action.length != 0U;
            int64_t repeat_count;
            slice_t expression = inline_key_repeat ? count_expression : arguments;
            if ((!inline_key_repeat && previous_action == SIZE_MAX) ||
                !evaluate_expression(runtime, expression, line_number, &repeat_count) ||
                repeat_count < 0 || repeat_count > UINT32_MAX) {
                if (runtime->result.status == DUCKY_OK) {
                    set_error(runtime, DUCKY_PARSE_ERROR, line_number,
                              "Invalid REPEAT count or no previous action");
                }
                return RUN_FAILED;
            }
            for (int64_t i = 0; i < repeat_count; ++i) {
                if (inline_key_repeat) {
                    if (!send_key_expression(runtime, inline_action, line_number)) return RUN_FAILED;
                } else {
                    bool recognized = false;
                    if (!execute_action(runtime, previous_action, &recognized)) return RUN_FAILED;
                }
                if (!delay_ms(runtime, runtime->default_delay_ms, line_number)) return RUN_FAILED;
            }
            if (inline_key_repeat) previous_action = SIZE_MAX;
            ++line_number;
            continue;
        }

        if (arguments.length == 0 && command.length >= 3 &&
            command.data[command.length - 2] == '(' && command.data[command.length - 1] == ')') {
            slice_t name = {command.data, command.length - 2};
            function_t *function = find_function(runtime, name);
            int64_t ignored;
            if (function == NULL) {
                set_error_word(runtime, DUCKY_PARSE_ERROR, line_number, "Unknown function: ", name);
                return RUN_FAILED;
            }
            if (!run_function(runtime, function, &ignored)) {
                return RUN_FAILED;
            }
            if (!delay_ms(runtime, runtime->default_delay_ms, line_number)) return RUN_FAILED;
            previous_action = SIZE_MAX;
            ++line_number;
            continue;
        }

        bool recognized = false;
        if (!execute_action(runtime, line_number, &recognized)) {
            return RUN_FAILED;
        }
        if (!delay_ms(runtime, runtime->default_delay_ms, line_number)) return RUN_FAILED;
        previous_action = line_number;
        ++line_number;
    }
    return RUN_FINISHED;
}

static bool build_line_index(runtime_t *runtime)
{
    size_t count = runtime->script_length == 0 ? 0 : 1;
    for (size_t i = 0; i < runtime->script_length; ++i) {
        if (runtime->script[i] == '\n' && i + 1 < runtime->script_length) {
            ++count;
        }
    }
    if (count > runtime->config.max_lines) {
        set_error(runtime, DUCKY_LIMIT_EXCEEDED, 0, "Script has too many lines");
        return false;
    }
    runtime->line_offsets = malloc((count + 1) * sizeof(runtime->line_offsets[0]));
    if (runtime->line_offsets == NULL) {
        set_error(runtime, DUCKY_OUT_OF_MEMORY, 0, "Could not allocate line index");
        return false;
    }
    runtime->line_count = count;
    if (count == 0) {
        runtime->line_offsets[0] = 0;
        return true;
    }
    size_t line = 0;
    runtime->line_offsets[line++] = 0;
    for (size_t i = 0; i < runtime->script_length && line < count; ++i) {
        if (runtime->script[i] == '\n' && i + 1 < runtime->script_length) {
            runtime->line_offsets[line++] = i + 1;
        }
    }
    runtime->line_offsets[count] = runtime->script_length;
    return true;
}

static bool capability_word_equal(const char *data, size_t length, const char *word)
{
    size_t expected = strlen(word);
    if (length != expected) return false;
    for (size_t i = 0; i < length; ++i) {
        if (toupper((unsigned char)data[i]) != toupper((unsigned char)word[i])) return false;
    }
    return true;
}

static bool capability_comment_word(const char *data, size_t length)
{
    if (capability_word_equal(data, length, "REM") ||
        (length >= 1U && data[0] == '#' &&
         (length == 1U || data[1] == '#'))) return true;
    return length > 3U && toupper((unsigned char)data[0]) == 'R' &&
        toupper((unsigned char)data[1]) == 'E' &&
        toupper((unsigned char)data[2]) == 'M' &&
        !isalnum((unsigned char)data[3]) && data[3] != '_';
}

uint32_t ducky_inspect_capabilities(const char *script, size_t script_length)
{
    if (script == NULL) return 0U;
    uint32_t capabilities = 0U;
    bool rem_block = false;
    const char *string_terminator = NULL;
    size_t position = 0U;
    while (position < script_length) {
        size_t end = position;
        while (end < script_length && script[end] != '\n') ++end;
        size_t start = position;
        while (start < end && isspace((unsigned char)script[start])) ++start;
        size_t command_end = start;
        while (command_end < end && !isspace((unsigned char)script[command_end])) ++command_end;
        const char *command = script + start;
        size_t command_length = command_end - start;
        if (rem_block) {
            if (capability_word_equal(command, command_length, "END_REM")) rem_block = false;
            position = end < script_length ? end + 1U : end;
            continue;
        }
        if (string_terminator != NULL) {
            if (capability_word_equal(command, command_length, string_terminator)) string_terminator = NULL;
            position = end < script_length ? end + 1U : end;
            continue;
        }
        if (capability_comment_word(command, command_length) || command_length == 0U) {
            position = end < script_length ? end + 1U : end;
            continue;
        }
        if (capability_word_equal(command, command_length, "REM_BLOCK")) {
            rem_block = true;
            position = end < script_length ? end + 1U : end;
            continue;
        }
        size_t rest = command_end;
        while (rest < end && isspace((unsigned char)script[rest])) ++rest;
        if (rest == end && (capability_word_equal(command, command_length, "STRING") ||
            capability_word_equal(command, command_length, "STRINGLN") ||
            capability_word_equal(command, command_length, "STRING_POWERSHELL") ||
            capability_word_equal(command, command_length, "STRINGLN_POWERSHELL") ||
            capability_word_equal(command, command_length, "STRINGLN_BASH") ||
            capability_word_equal(command, command_length, "STRINGLN_BLOCK"))) {
            string_terminator = (capability_word_equal(command, command_length, "STRING") ||
                capability_word_equal(command, command_length, "STRING_POWERSHELL"))
                    ? "END_STRING" : "END_STRINGLN";
            position = end < script_length ? end + 1U : end;
            continue;
        }
        for (size_t i = start; i < end;) {
            while (i < end && !(isalnum((unsigned char)script[i]) ||
                   script[i] == '_' || script[i] == '$')) ++i;
            size_t token = i;
            while (i < end && (isalnum((unsigned char)script[i]) ||
                   script[i] == '_' || script[i] == '$')) ++i;
            size_t length = i - token;
            if (capability_word_equal(script + token, length, "EXFIL"))
                capabilities |= DUCKY_CAP_VARIABLE_EXFIL;
            else if (capability_word_equal(script + token, length, "$_EXFIL_MODE_ENABLED"))
                capabilities |= DUCKY_CAP_KEYSTROKE_REFLECTION;
            else if (capability_word_equal(script + token, length, "HIDE_PAYLOAD") ||
                     capability_word_equal(script + token, length, "RESTORE_PAYLOAD"))
                capabilities |= DUCKY_CAP_PAYLOAD_HIDING;
        }
        position = end < script_length ? end + 1U : end;
    }
    return capabilities;
}

ducky_result_t ducky_run(
    const char *script,
    size_t script_length,
    const ducky_io_t *io,
    const ducky_config_t *config)
{
    ducky_result_t invalid = {
        .status = DUCKY_INVALID_ARGUMENT,
        .line = 0,
        .message = "Invalid DuckyScript runtime argument",
    };
    if ((script == NULL && script_length != 0) || io == NULL || io->keyboard == NULL ||
        io->delay_ms == NULL) {
        return invalid;
    }

    runtime_t *runtime = calloc(1, sizeof(*runtime));
    if (runtime == NULL) {
        invalid.status = DUCKY_OUT_OF_MEMORY;
        snprintf(invalid.message, sizeof(invalid.message), "Could not allocate DuckyScript runtime");
        return invalid;
    }
    *runtime = (runtime_t){
        .script = script != NULL ? script : "",
        .script_length = script_length,
        .io = io,
        .config = config != NULL ? *config : DUCKY_CONFIG_DEFAULT(),
        .result = {.status = DUCKY_OK},
        .button_enabled = true,
        .current_attackmode = 1U,
        .attackmode_profile = {.mode = 1U},
        .os = 0U,
        .fallback_random = 0x6D2B79F5U,
        .random_seed = 0x79F5U,
        .storage_activity_timeout_ms = 1000U,
        .storage_leds_enabled = true,
        .continuous_storage_led = true,
        .injecting_leds_enabled = true,
        .exfil_leds_enabled = true,
        .random_max = 9,
        .jitter_max = 20,
        .button_debounce_ms = 1000,
        .system_leds_enabled = true,
    };
    if (io->random_u32 != NULL) {
        runtime->fallback_random = io->random_u32(io->context);
        runtime->random_seed = (uint16_t)runtime->fallback_random;
    }
    publish_runtime_options(runtime);
    if (io->host_os_guess != NULL) {
        runtime->os = io->host_os_guess(io->context);
    }
    if (runtime->config.max_lines == 0 || runtime->config.max_execution_steps == 0) {
        free(runtime);
        return invalid;
    }
    if (!build_line_index(runtime) || !preprocess_defined_blocks(runtime) ||
        !compile_defined_source(runtime) || !scan_blocks(runtime)) {
        ducky_result_t result = runtime->result;
        free(runtime->compiled_script);
        free(runtime->line_enabled);
        free(runtime->line_offsets);
        free(runtime);
        return result;
    }

    int64_t ignored = 0;
    run_outcome_t outcome = run_range(runtime, 0, runtime->line_count, false, &ignored);
    if (outcome == RUN_STOPPED && runtime->result.status == DUCKY_OK) {
        runtime->result.status = DUCKY_STOPPED;
        snprintf(runtime->result.message, sizeof(runtime->result.message), "Payload stopped by STOP_PAYLOAD");
    } else if (outcome == RUN_FAILED && runtime->result.status == DUCKY_OK) {
        runtime->result.status = DUCKY_PARSE_ERROR;
        snprintf(runtime->result.message, sizeof(runtime->result.message), "Payload execution failed");
    }

    /* A final neutral report prevents a failed script from leaving host input stuck. */
    memset(runtime->held_keys, 0, sizeof(runtime->held_keys));
    runtime->held_modifiers = 0;
    runtime->mouse_buttons = 0;
    io->keyboard(io->context, 0, runtime->held_keys);
    if (io->mouse != NULL) {
        io->mouse(io->context, 0, 0, 0, 0, 0);
    }
    ducky_result_t result = runtime->result;
    free(runtime->compiled_script);
    free(runtime->line_enabled);
    free(runtime->line_offsets);
    free(runtime);
    return result;
}

const char *ducky_status_name(ducky_status_t status)
{
    switch (status) {
    case DUCKY_OK: return "ok";
    case DUCKY_INVALID_ARGUMENT: return "invalid argument";
    case DUCKY_OUT_OF_MEMORY: return "out of memory";
    case DUCKY_PARSE_ERROR: return "parse error";
    case DUCKY_UNSUPPORTED: return "unsupported";
    case DUCKY_IO_ERROR: return "I/O error";
    case DUCKY_LIMIT_EXCEEDED: return "limit exceeded";
    case DUCKY_STOPPED: return "stopped";
    default: return "unknown";
    }
}
