#!/usr/bin/env python3
"""PicoFido DuckyScript 3 compatibility patch for the pinned s3-ducky runtime.

Adds the device/runtime bridge needed by PicoFido USB Tool:
- logical ATTACKMODE OFF/HID/STORAGE/HID+STORAGE
- SAVE_ATTACKMODE / RESTORE_ATTACKMODE
- current attackmode/VID/PID and host fingerprint internal variables
- exact configuration-descriptor request counter, reset and OS snapshot
- saved lock-state variables
- RANDOM_SPECIAL / RANDOM_CHAR and 0..9 default random integer
- EXTENSION wrappers as source-level no-ops
- compile-time IF_DEFINED_TRUE / IF_NOT_DEFINED_TRUE blocks
- full recursive DEFINE preprocessing across active source lines
- exact STRING / STRINGLN block whitespace semantics
- PayloadStudio block aliases used by Hak5 payload sources
- IF(...)/WHILE(...) compact syntax accepted without whitespace
- strict compatibility for hyphen-separated key chords found in Hak5 payloads
- legacy bare/hyphenated DEFINE names used by official Hak5 examples
- WAIT_FOR_STORAGE_ACTIVITY / WAIT_FOR_STORAGE_INACTIVITY

Variable EXFIL and Keystroke Reflection are exposed only through explicit I/O
callbacks; firmware policy decides whether those capabilities exist. Payload
hiding remains deliberately unsupported and must not become a silent no-op.
"""
from __future__ import annotations


def _one(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def _counted(text: str, old: str, new: str, count: int, label: str) -> str:
    actual = text.count(old)
    if actual != count:
        raise RuntimeError(f"{label}: expected {count} anchors, found {actual}")
    return text.replace(old, new)


def patch_ducky_h(text: str) -> str:
    anchor = '''typedef struct {\n    ducky_status_t status;\n    size_t line;\n    char message[128];\n} ducky_result_t;\n'''
    repl = anchor + '''\n\nenum {\n    DUCKY_LED_OPT_SYSTEM = 1U << 0,\n    DUCKY_LED_OPT_STORAGE = 1U << 1,\n    DUCKY_LED_OPT_CONTINUOUS_STORAGE = 1U << 2,\n    DUCKY_LED_OPT_INJECTING = 1U << 3,\n    DUCKY_LED_OPT_EXFIL = 1U << 4,\n    DUCKY_LED_OPT_SHOW_CAPS = 1U << 5,\n    DUCKY_LED_OPT_SHOW_NUM = 1U << 6,\n    DUCKY_LED_OPT_SHOW_SCROLL = 1U << 7,\n};\n'''
    text = _one(text, anchor, repl, 'runtime LED option flags')
    anchor = '''enum {\n    DUCKY_LED_OPT_SYSTEM = 1U << 0,\n    DUCKY_LED_OPT_STORAGE = 1U << 1,\n    DUCKY_LED_OPT_CONTINUOUS_STORAGE = 1U << 2,\n    DUCKY_LED_OPT_INJECTING = 1U << 3,\n    DUCKY_LED_OPT_EXFIL = 1U << 4,\n    DUCKY_LED_OPT_SHOW_CAPS = 1U << 5,\n    DUCKY_LED_OPT_SHOW_NUM = 1U << 6,\n    DUCKY_LED_OPT_SHOW_SCROLL = 1U << 7,\n};\n'''
    repl = anchor + '''\n+enum {\n+    DUCKY_CAP_VARIABLE_EXFIL = 1U << 0,\n+    DUCKY_CAP_KEYSTROKE_REFLECTION = 1U << 1,\n+    DUCKY_CAP_PAYLOAD_HIDING = 1U << 2,\n+};\n'''.replace("\n+", "\n")
    text = _one(text, anchor, repl, 'stage 8 capability flags')
    anchor = '''typedef struct {\n    void *context;\n'''
    repl = '''typedef struct {\n    uint8_t mode;\n    uint16_t vid;\n    uint16_t pid;\n    char manufacturer[33];\n    char product[33];\n    char serial[13];\n    bool custom_identity;\n} ducky_attackmode_t;\n\ntypedef struct {\n    void *context;\n'''
    text = _one(text, anchor, repl, 'ATTACKMODE descriptor profile')
    old = '    void (*status_led)(void *context, bool on);\n'
    new = '''    /* Logical Ducky LED state. LED_ON is the green/default state. */
    void (*status_led)(void *context, uint8_t state);
'''
    text = _one(text, old, new, 'colour-aware status LED callback')
    anchor = '    uint32_t (*random_u32)(void *context);\n'
    repl = anchor + '''    void (*runtime_options)(void *context, uint8_t led_options,\n                            uint16_t storage_activity_timeout_ms);\n    uint32_t (*storage_activity_age_ms)(void *context);\n    bool (*button_pressed)(void *context, uint16_t debounce_ms);\n    bool (*attackmode)(void *context, uint8_t mode);\n    uint8_t (*current_attackmode)(void *context);\n    uint16_t (*current_vid)(void *context);\n    uint16_t (*current_pid)(void *context);\n    bool (*host_lock_reply_received)(void *context);\n    uint16_t (*host_configuration_request_count)(void *context);\n    bool (*reset_host_configuration_request_count)(void *context);\n    uint16_t (*host_os_guess)(void *context);\n    bool (*variable_exfil)(void *context, uint16_t value);\n    bool (*set_exfil_mode)(void *context, bool enabled);\n    bool (*exfil_mode_enabled)(void *context);\n'''
    text = _one(text, anchor, repl, 'ducky_io architecture callbacks')
    anchor = '    bool (*attackmode)(void *context, uint8_t mode);\n'
    repl = anchor + '    bool (*attackmode_profile)(void *context, const ducky_attackmode_t *profile);\n'
    text = _one(text, anchor, repl, 'dynamic ATTACKMODE callback')
    anchor = '''ducky_result_t ducky_run(\n'''
    repl = '''uint32_t ducky_inspect_capabilities(const char *script, size_t script_length);\n\n''' + anchor
    return _one(text, anchor, repl, 'capability inspector API')


def patch_ducky_c(text: str) -> str:
    text = _one(text, '#define DUCKY_MAX_NAME 31\n', '#define DUCKY_MAX_NAME 63\n',
                'Hak5 identifier length')
    old = '''static bool define_constant(runtime_t *runtime, slice_t definition, size_t line)
{
    definition = trim(definition);
    size_t name_length = 0;
    while (name_length < definition.length &&
           (isalnum((unsigned char)definition.data[name_length]) ||
            definition.data[name_length] == '_' || definition.data[name_length] == '#')) {
        ++name_length;
    }
    slice_t name = {definition.data, name_length};
    slice_t replacement = trim((slice_t){
        definition.data + name_length,
        definition.length - name_length,
    });
    if (!valid_name(name, '#') || replacement.length == 0) {
        set_error(runtime, DUCKY_PARSE_ERROR, line, "DEFINE requires '#NAME replacement'");
        return false;
    }
'''
    new = '''static bool valid_constant_name(slice_t name)
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
'''
    text = _one(text, old, new, 'legacy DEFINE identifiers')
    old = '''    int index = variable_index(runtime, name);
    if (index >= 0) {
        if (define) {
            set_error_word(runtime, DUCKY_PARSE_ERROR, line, "Variable already defined: ", name);
            return false;
        }
        if (runtime->variables[index].read_only) {
'''
    new = '''    int index = variable_index(runtime, name);
    if (index >= 0) {
        /* Hak5 treats a repeated VAR declaration as re-initialization. This is
         * also required for VAR declarations inside repeatedly called functions. */
        if (runtime->variables[index].read_only) {
'''
    text = _one(text, old, new, 'VAR re-initialization')
    old = '''    if (!define) {
        set_error_word(runtime, DUCKY_PARSE_ERROR, line, "Undefined variable: ", name);
        return false;
    }
'''
    new = '''    /* Assignment is also accepted as first initialization. Official Hak5
     * examples and payload extensions use both VAR $NAME and $NAME forms. */
'''
    text = _one(text, old, new, 'implicit variable initialization')
    anchor = '''static bool set_variable(
    runtime_t *runtime,
    slice_t name,
    int64_t value,
    bool define,
    bool read_only,
    size_t line)
{
'''
    repl = anchor + '''    (void)define;
'''
    text = _one(text, anchor, repl, 'retained VAR declaration flag')
    # Compact IF(...)/WHILE(...) syntax appears in official/community payload sources.
    anchor = '''    slice_t word = {line.data, length};\n    slice_t rest = {line.data + length, line.length - length};\n'''
    repl = '''    /* DuckyScript sources commonly omit whitespace before control expressions. */\n    if (length > 3 && toupper((unsigned char)line.data[0]) == 'I' &&\n        toupper((unsigned char)line.data[1]) == 'F' && line.data[2] == '(') {\n        length = 2;\n    } else if (length > 6 &&\n               toupper((unsigned char)line.data[0]) == 'W' &&\n               toupper((unsigned char)line.data[1]) == 'H' &&\n               toupper((unsigned char)line.data[2]) == 'I' &&\n               toupper((unsigned char)line.data[3]) == 'L' &&\n               toupper((unsigned char)line.data[4]) == 'E' && line.data[5] == '(') {\n        length = 5;\n    }\n    slice_t word = {line.data, length};\n    slice_t rest = {line.data + length, line.length - length};\n'''
    text = _one(text, anchor, repl, 'compact IF/WHILE syntax')

    # The DuckyScript reference uses spaces between arbitrary key/modifier
    # combinations. The official payload library also contains legacy/community
    # spellings such as CTRL-ALT, ALT-F4 and CTRL-SHIFT-ENTER. Split a token on
    # hyphens only when every component is itself a valid key name. This keeps a
    # literal '-' key working and keeps malformed/unknown compounds fail-closed.
    anchor = '''static bool send_key_expression(runtime_t *runtime, slice_t expression, size_t line)\n'''
    repl = '''static ducky_key_token_t lookup_key_component(slice_t component, bool hyphenated)\n{
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
'''
    text = _one(text, anchor, repl, 'hyphenated key sequence helpers')

    old = '''    slice_t token;
    while (next_token(&expression, &token)) {
        ducky_key_token_t key = ducky_lookup_key(token.data, token.length);
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
    }
'''
    new = '''    slice_t token;
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
'''
    text = _one(text, old, new, 'hyphenated key tap expressions')

    old = '''    slice_t token;
    while (next_token(&expression, &token)) {
        ducky_key_token_t key = ducky_lookup_key(token.data, token.length);
        if (key.kind == DUCKY_KEY_TOKEN_MODIFIER) {
            if (hold) {
                runtime->held_modifiers |= (uint8_t)key.value;
            } else {
                runtime->held_modifiers &= (uint8_t)~key.value;
            }
        } else if (key.kind == DUCKY_KEY_TOKEN_KEY) {
            if (hold) {
                if (!add_key(runtime->held_keys, (uint8_t)key.value)) {
                    set_error(runtime, DUCKY_LIMIT_EXCEEDED, line, "Keyboard rollover exceeds six keys");
                    return false;
                }
                runtime->held_modifiers |= key.implied_modifiers;
            } else {
                remove_key(runtime->held_keys, (uint8_t)key.value);
                runtime->held_modifiers &= (uint8_t)~key.implied_modifiers;
            }
        } else {
            set_error(runtime, DUCKY_UNSUPPORTED, line, "HOLD supports keyboard keys and modifiers only");
            return false;
        }
    }
'''
    new = '''    slice_t token;
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
'''
    text = _one(text, old, new, 'hyphenated HOLD/RELEASE expressions')

    old = '''        if (runtime->io->status_led != NULL) {
            runtime->io->status_led(runtime->io->context, !equal_case(command, "LED_OFF"));
        }
'''
    new = '''        if (runtime->io->status_led != NULL) {
            uint8_t state = equal_case(command, "LED_OFF") ? 0U :
                (equal_case(command, "LED_R") ? 1U : 2U);
            runtime->io->status_led(runtime->io->context, state);
        }
'''
    text = _one(text, old, new, 'colour-aware LED commands')
    text = _one(
        text,
        '''    if (equal_case(command, "LED_ON") || equal_case(command, "LED_R") ||
        equal_case(command, "LED_G") || equal_case(command, "LED_OFF")) {
''',
        '''    if (equal_case(command, "LED_ON") || equal_case(command, "LED_R") ||
        equal_case(command, "LED_RED") || equal_case(command, "LED_G") ||
        equal_case(command, "LED_GREEN") || equal_case(command, "LED_OFF")) {
''',
        'legacy LED colour aliases',
    )
    text = _one(
        text,
        '(equal_case(command, "LED_R") ? 1U : 2U);',
        '((equal_case(command, "LED_R") || equal_case(command, "LED_RED")) ? 1U : 2U);',
        'legacy red LED state',
    )

    anchor = '''    bool button_enabled;\n    bool button_push_received;\n'''
    repl = anchor + '''    bool button_handler_active;\n    bool button_wait_active;\n    uint8_t current_attackmode;\n    uint8_t saved_attackmode;\n    bool attackmode_saved;\n    ducky_attackmode_t attackmode_profile;\n    ducky_attackmode_t saved_attackmode_profile;\n    uint16_t os;\n'''
    text = _one(text, anchor, repl, 'runtime attackmode state')

    anchor = '''    uint16_t random_min;\n    uint16_t random_max;\n'''
    repl = anchor + '''    uint16_t random_seed;\n    uint16_t storage_activity_timeout_ms;\n    bool storage_leds_enabled;\n    bool continuous_storage_led;\n    bool injecting_leds_enabled;\n    bool exfil_leds_enabled;\n    bool led_show_caps;\n    bool led_show_num;\n    bool led_show_scroll;\n'''
    text = _one(text, anchor, repl, 'safe random storage and LED runtime state')

    anchor = '''    size_t *line_offsets;\n    size_t line_count;\n'''
    repl = anchor + '''    bool *line_enabled;\n    char *compiled_script;\n'''
    text = _one(text, anchor, repl, 'compile-time line mask')

    old = '''static uint32_t random_u32(runtime_t *runtime)\n{\n    if (runtime->io->random_u32 != NULL) {\n        return runtime->io->random_u32(runtime->io->context);\n    }\n    /* xorshift32 gives deterministic host tests and a no-dependency fallback. */\n    uint32_t value = runtime->fallback_random;\n    value ^= value << 13;\n    value ^= value >> 17;\n    value ^= value << 5;\n    runtime->fallback_random = value;\n    return value;\n}\n'''
    new = '''static uint32_t random_u32(runtime_t *runtime)\n{\n    /* Hardware entropy seeds one per-payload generator. Keeping generation in\n     * the runtime makes $_RANDOM_SEED deterministic and writable. */\n    runtime->fallback_random = runtime->fallback_random * 1664525U + 1013904223U;\n    return runtime->fallback_random;\n}\n'''
    text = _one(text, old, new, 'seedable per-payload PRNG')

    old = '''static slice_t get_line(const runtime_t *runtime, size_t line_number)\n{\n    if (line_number >= runtime->line_count) {\n        return (slice_t){0};\n    }\n    size_t start = runtime->line_offsets[line_number];\n    size_t end = runtime->line_offsets[line_number + 1];\n    if (end > start && runtime->script[end - 1] == '\\n') {\n        --end;\n    }\n    if (end > start && runtime->script[end - 1] == '\\r') {\n        --end;\n    }\n    return trim((slice_t){runtime->script + start, end - start});\n}\n'''
    new = '''static slice_t get_line_raw(const runtime_t *runtime, size_t line_number)\n{\n    if (line_number >= runtime->line_count) {\n        return (slice_t){0};\n    }\n    size_t start = runtime->line_offsets[line_number];\n    size_t end = runtime->line_offsets[line_number + 1];\n    if (end > start && runtime->script[end - 1] == '\\n') {\n        --end;\n    }\n    if (end > start && runtime->script[end - 1] == '\\r') {\n        --end;\n    }\n    return (slice_t){runtime->script + start, end - start};\n}\n\nstatic slice_t get_line(const runtime_t *runtime, size_t line_number)\n{\n    slice_t line = trim(get_line_raw(runtime, line_number));\n    if (line_number == 0U && line.length >= 3U &&\n        (unsigned char)line.data[0] == 0xEFU &&\n        (unsigned char)line.data[1] == 0xBBU &&\n        (unsigned char)line.data[2] == 0xBFU) {\n        line.data += 3;\n        line.length -= 3U;\n        line = trim(line);\n    }\n    return line;\n}\n'''
    text = _one(text, old, new, 'raw source line access')

    old = '''static void delay_ms(runtime_t *runtime, uint32_t milliseconds)\n{\n    if (runtime->io->delay_ms != NULL && milliseconds > 0) {\n        runtime->io->delay_ms(runtime->io->context, milliseconds);\n    }\n}\n'''
    new = '''static bool execute_button_block(runtime_t *runtime);\nstatic bool poll_async_button(runtime_t *runtime, size_t line);\n\nstatic bool delay_ms(runtime_t *runtime, uint32_t milliseconds, size_t line)\n{\n    while (milliseconds > 0U) {\n        uint32_t chunk = milliseconds > 10U ? 10U : milliseconds;\n        if (runtime->io->delay_ms != NULL) {\n            runtime->io->delay_ms(runtime->io->context, chunk);\n        }\n        milliseconds -= chunk;\n        if (!poll_async_button(runtime, line)) return false;\n    }\n    return true;\n}\n'''
    text = _one(text, old, new, 'asynchronous button-aware delays')

    text = _counted(
        text,
        '    delay_ms(runtime, runtime->config.key_press_ms);\n',
        '    if (!delay_ms(runtime, runtime->config.key_press_ms, line)) return false;\n',
        4,
        'key press delays',
    )
    text = _one(
        text,
        '            delay_ms(runtime, random_u32(runtime) % ((uint32_t)runtime->jitter_max + 1));\n',
        '            if (!delay_ms(runtime, random_u32(runtime) % ((uint32_t)runtime->jitter_max + 1), line)) return false;\n',
        'jitter delay',
    )
    text = _counted(
        text,
        '        delay_ms(runtime, 5);\n',
        '        if (!delay_ms(runtime, 5, line)) return false;\n',
        2,
        'lock wait delays',
    )
    text = _one(
        text,
        '        delay_ms(runtime, (uint32_t)value);\n        return true;\n',
        '        return delay_ms(runtime, (uint32_t)value, line_number);\n',
        'DELAY command',
    )

    old = '''static bool execute_button_block(runtime_t *runtime)\n{\n    if (runtime->button_first_line == SIZE_MAX) {\n        return true;\n    }\n    int64_t ignored = 0;\n    run_outcome_t outcome = run_range(\n        runtime,\n        runtime->button_first_line + 1,\n        runtime->button_end_line,\n        false,\n        &ignored);\n    return outcome == RUN_FINISHED;\n}\n'''
    new = '''static bool execute_button_block(runtime_t *runtime)\n{\n    if (runtime->button_first_line == SIZE_MAX) {\n        return true;\n    }\n    int64_t ignored = 0;\n    run_outcome_t outcome = run_range(\n        runtime,\n        runtime->button_first_line + 1,\n        runtime->button_end_line,\n        false,\n        &ignored);\n    if (outcome == RUN_STOPPED && runtime->result.status == DUCKY_OK) {\n        set_error(runtime, DUCKY_STOPPED, runtime->button_first_line,\n                  "Payload stopped from BUTTON_DEF");\n    }\n    return outcome == RUN_FINISHED;\n}\n\nstatic bool poll_async_button(runtime_t *runtime, size_t line)\n{\n    if (!runtime->button_enabled || runtime->button_wait_active ||\n        runtime->button_handler_active || runtime->io->button_pressed == NULL) {\n        return true;\n    }\n    if (!runtime->io->button_pressed(runtime->io->context, runtime->button_debounce_ms)) {\n        return true;\n    }\n    runtime->button_push_received = true;\n    if (runtime->button_first_line == SIZE_MAX) {\n        set_error(runtime, DUCKY_STOPPED, line, "Payload stopped by button");\n        return false;\n    }\n    runtime->button_handler_active = true;\n    bool ok = execute_button_block(runtime);\n    runtime->button_handler_active = false;\n    return ok;\n}\n'''
    text = _one(text, old, new, 'asynchronous BUTTON_DEF dispatch')

    anchor = '''static bool execute_action(runtime_t *runtime, size_t line_number, bool *recognized)
'''
    repl = '''static bool wait_for_storage_state(runtime_t *runtime, bool inactive, size_t line)
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

''' + anchor
    text = _one(text, anchor, repl, 'storage activity wait helper')

    old = '''    if (equal_case(command, "WAIT_FOR_BUTTON_PRESS")) {\n        if (!runtime->button_enabled || runtime->io->wait_for_button == NULL) {\n            set_error(runtime, DUCKY_UNSUPPORTED, line_number, "Payload button is disabled or unavailable");\n            return false;\n        }\n        runtime->button_push_received = runtime->io->wait_for_button(\n            runtime->io->context,\n            runtime->config.button_timeout_ms);\n        return !runtime->button_push_received || execute_button_block(runtime);\n    }\n'''
    new = '''    if (equal_case(command, "WAIT_FOR_BUTTON_PRESS")) {\n        if (!runtime->button_enabled ||\n            (runtime->io->button_pressed == NULL && runtime->io->wait_for_button == NULL)) {\n            set_error(runtime, DUCKY_UNSUPPORTED, line_number, "Payload button is disabled or unavailable");\n            return false;\n        }\n        runtime->button_wait_active = true;\n        bool pressed = false;\n        if (runtime->io->button_pressed != NULL) {\n            uint32_t elapsed = 0U;\n            while (!runtime->io->button_pressed(\n                    runtime->io->context, runtime->button_debounce_ms)) {\n                if (runtime->config.button_timeout_ms != 0U &&\n                    elapsed >= runtime->config.button_timeout_ms) break;\n                if (!delay_ms(runtime, 10U, line_number)) {\n                    runtime->button_wait_active = false;\n                    return false;\n                }\n                elapsed += 10U;\n            }\n            pressed = runtime->config.button_timeout_ms == 0U ||\n                      elapsed < runtime->config.button_timeout_ms;\n        } else {\n            pressed = runtime->io->wait_for_button(\n                runtime->io->context, runtime->config.button_timeout_ms);\n        }\n        runtime->button_wait_active = false;\n        runtime->button_push_received = pressed;\n        return !pressed || execute_button_block(runtime);\n    }\n'''
    text = _one(text, old, new, 'debounced WAIT_FOR_BUTTON_PRESS')
    old = '''            while (!runtime->io->button_pressed(\n                    runtime->io->context, runtime->button_debounce_ms)) {\n                if (runtime->config.button_timeout_ms != 0U &&\n                    elapsed >= runtime->config.button_timeout_ms) break;\n                if (!delay_ms(runtime, 10U, line_number)) {\n                    runtime->button_wait_active = false;\n                    return false;\n                }\n                elapsed += 10U;\n            }\n            pressed = runtime->config.button_timeout_ms == 0U ||\n                      elapsed < runtime->config.button_timeout_ms;\n'''
    new = '''            for (;;) {\n                if (runtime->io->button_pressed(\n                        runtime->io->context, runtime->button_debounce_ms)) {\n                    pressed = true;\n                    break;\n                }\n                if (runtime->config.button_timeout_ms != 0U &&\n                    elapsed >= runtime->config.button_timeout_ms) break;\n                if (!delay_ms(runtime, 10U, line_number)) {\n                    runtime->button_wait_active = false;\n                    return false;\n                }\n                elapsed += 10U;\n            }\n'''
    text = _one(text, old, new, 'button wait timeout boundary')

    anchor = '''    if (equal_case(command, "WAIT_FOR_CAPS_ON")) {
'''
    repl = '''    if (equal_case(command, "WAIT_FOR_STORAGE_ACTIVITY")) {
        return arguments.length == 0U && wait_for_storage_state(runtime, false, line_number);
    }
    if (equal_case(command, "WAIT_FOR_STORAGE_INACTIVITY")) {
        return arguments.length == 0U && wait_for_storage_state(runtime, true, line_number);
    }
''' + anchor
    text = _one(text, anchor, repl, 'storage activity wait commands')

    anchor = '''    if (equal_case(command, "RESET")) {
'''
    repl = '''    if (equal_case(command, "INJECT_VAR")) {
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
''' + anchor
    text = _one(text, anchor, repl, 'INJECT_VAR raw HID keycode')

    # Internal variables from the Hak5 quick reference that map cleanly to available hardware state.
    old = '''    if (equal_case(name, "$_CAPSLOCK_ON")) {\n        return (leds & DUCKY_LED_CAPS_LOCK) != 0;\n    }\n'''
    new = '''    if (equal_case(name, "$_CAPSLOCK_ON")) {\n        return (leds & DUCKY_LED_CAPS_LOCK) != 0;\n    }\n    if (equal_case(name, "$_SAVED_CAPSLOCK_ON")) {\n        return runtime->lock_state_saved && (runtime->saved_lock_state & DUCKY_LED_CAPS_LOCK) != 0;\n    }\n    if (equal_case(name, "$_SAVED_NUMLOCK_ON")) {\n        return runtime->lock_state_saved && (runtime->saved_lock_state & DUCKY_LED_NUM_LOCK) != 0;\n    }\n    if (equal_case(name, "$_SAVED_SCROLLLOCK_ON")) {\n        return runtime->lock_state_saved && (runtime->saved_lock_state & DUCKY_LED_SCROLL_LOCK) != 0;\n    }\n    if (equal_case(name, "$_RECEIVED_HOST_LOCK_LED_REPLY")) {\n        return runtime->io->host_lock_reply_received != NULL &&\n               runtime->io->host_lock_reply_received(runtime->io->context);\n    }\n    if (equal_case(name, "$_HOST_CONFIGURATION_REQUEST_COUNT")) {\n        return runtime->io->host_configuration_request_count != NULL\n            ? runtime->io->host_configuration_request_count(runtime->io->context) : 0;\n    }\n'''
    text = _one(text, old, new, 'lock/fingerprint internal variables')

    anchor = '''static bool set_internal_variable(runtime_t *runtime, slice_t name, int64_t value, size_t line)\n{\n'''
    repl = '''static uint8_t runtime_led_options(const runtime_t *runtime)\n{\n    return (runtime->system_leds_enabled ? DUCKY_LED_OPT_SYSTEM : 0U) |\n           (runtime->storage_leds_enabled ? DUCKY_LED_OPT_STORAGE : 0U) |\n           (runtime->continuous_storage_led ? DUCKY_LED_OPT_CONTINUOUS_STORAGE : 0U) |\n           (runtime->injecting_leds_enabled ? DUCKY_LED_OPT_INJECTING : 0U) |\n           (runtime->exfil_leds_enabled ? DUCKY_LED_OPT_EXFIL : 0U) |\n           (runtime->led_show_caps ? DUCKY_LED_OPT_SHOW_CAPS : 0U) |\n           (runtime->led_show_num ? DUCKY_LED_OPT_SHOW_NUM : 0U) |\n           (runtime->led_show_scroll ? DUCKY_LED_OPT_SHOW_SCROLL : 0U);\n}\n\nstatic void publish_runtime_options(runtime_t *runtime)\n{\n    if (runtime->io->runtime_options != NULL) {\n        runtime->io->runtime_options(runtime->io->context,\n            runtime_led_options(runtime), runtime->storage_activity_timeout_ms);\n    }\n}\n\nstatic bool set_internal_variable(runtime_t *runtime, slice_t name, int64_t value, size_t line)\n{\n'''
    text = _one(text, anchor, repl, 'runtime option publisher')

    # Host-detection extensions assign $_OS directly. Preserve arbitrary
    # extension-defined values such as #NOT_WINDOWS as 16-bit runtime state.
    old = '''    } else if (equal_case(name, "$_SYSTEM_LEDS_ENABLED")) {\n        runtime->system_leds_enabled = value != 0;\n    } else {\n'''
    new = '''    } else if (equal_case(name, "$_EXFIL_MODE_ENABLED")) {\n        if (runtime->io->set_exfil_mode == NULL) {\n            set_error(runtime, DUCKY_UNSUPPORTED, line, "Keystroke Reflection is unavailable");\n            return false;\n        }\n        if (!runtime->io->set_exfil_mode(runtime->io->context, value != 0)) {\n            set_error(runtime, DUCKY_IO_ERROR, line, "Keystroke Reflection transition failed");\n            return false;\n        }\n    } else if (equal_case(name, "$_SYSTEM_LEDS_ENABLED")) {\n        runtime->system_leds_enabled = value != 0;\n        publish_runtime_options(runtime);\n    } else if (equal_case(name, "$_STORAGE_LEDS_ENABLED")) {\n        runtime->storage_leds_enabled = value != 0;\n        publish_runtime_options(runtime);\n    } else if (equal_case(name, "$_LED_CONTINUOUS_SHOW_STORAGE_ACTIVITY")) {\n        runtime->continuous_storage_led = value != 0;\n        publish_runtime_options(runtime);\n    } else if (equal_case(name, "$_INJECTING_LEDS_ENABLED")) {\n        runtime->injecting_leds_enabled = value != 0;\n        publish_runtime_options(runtime);\n    } else if (equal_case(name, "$_EXFIL_LEDS_ENABLED")) {\n        runtime->exfil_leds_enabled = value != 0;\n        publish_runtime_options(runtime);\n    } else if (equal_case(name, "$_LED_SHOW_CAPS")) {\n        runtime->led_show_caps = value != 0;\n        publish_runtime_options(runtime);\n    } else if (equal_case(name, "$_LED_SHOW_NUM")) {\n        runtime->led_show_num = value != 0;\n        publish_runtime_options(runtime);\n    } else if (equal_case(name, "$_LED_SHOW_SCROLL")) {\n        runtime->led_show_scroll = value != 0;\n        publish_runtime_options(runtime);\n    } else if (equal_case(name, "$_STORAGE_ACTIVITY_TIMEOUT")) {\n        runtime->storage_activity_timeout_ms = (uint16_t)value;\n        publish_runtime_options(runtime);\n    } else if (equal_case(name, "$_RANDOM_SEED")) {\n        runtime->random_seed = (uint16_t)value;\n        runtime->fallback_random = ((uint32_t)(uint16_t)value << 16) | (uint16_t)value;\n    } else if (equal_case(name, "$_HOST_CONFIGURATION_REQUEST_COUNT")) {\n        if (value != 0 || runtime->io->reset_host_configuration_request_count == NULL ||\n            !runtime->io->reset_host_configuration_request_count(runtime->io->context)) {\n            set_error(runtime, DUCKY_UNSUPPORTED, line,\n                      "$_HOST_CONFIGURATION_REQUEST_COUNT may only be reset to zero");\n            return false;\n        }\n    } else if (equal_case(name, "$_OS")) {\n        runtime->os = (uint16_t)value;\n    } else {\n'''
    text = _one(text, old, new, 'writable $_OS internal variable')
    old = '''    if (equal_case(name, "$_CURRENT_VID")) {\n        return 0x303A;\n    }\n    if (equal_case(name, "$_CURRENT_PID")) {\n        return 0x4010;\n    }\n'''
    new = '''    if (equal_case(name, "$_OS")) {\n        return runtime->os;\n    }\n    if (equal_case(name, "$_CURRENT_VID")) {\n        return runtime->io->current_vid != NULL ? runtime->io->current_vid(runtime->io->context) : 0;\n    }\n    if (equal_case(name, "$_CURRENT_PID")) {\n        return runtime->io->current_pid != NULL ? runtime->io->current_pid(runtime->io->context) : 0;\n    }\n    if (equal_case(name, "$_CURRENT_ATTACKMODE")) {\n        return runtime->io->current_attackmode != NULL\n            ? runtime->io->current_attackmode(runtime->io->context) : runtime->current_attackmode;\n    }\n'''
    text = _one(text, old, new, 'current USB identity variables')
    anchor = '''static int64_t expression_internal_variable(runtime_t *runtime, slice_t name, bool *found)\n{\n'''
    repl = '''static uint16_t swap_usb_id(uint16_t value)\n{\n    return (uint16_t)((value >> 8) | (value << 8));\n}\n\nstatic int64_t expression_internal_variable(runtime_t *runtime, slice_t name, bool *found)\n{\n'''
    text = _one(text, anchor, repl, 'documented current USB ID byte order')
    text = _one(
        text,
        'return runtime->io->current_vid != NULL ? runtime->io->current_vid(runtime->io->context) : 0;',
        'return runtime->io->current_vid != NULL ? swap_usb_id(runtime->io->current_vid(runtime->io->context)) : 0;',
        '$_CURRENT_VID endian swap',
    )
    text = _one(
        text,
        'return runtime->io->current_pid != NULL ? runtime->io->current_pid(runtime->io->context) : 0;',
        'return runtime->io->current_pid != NULL ? swap_usb_id(runtime->io->current_pid(runtime->io->context)) : 0;',
        '$_CURRENT_PID endian swap',
    )

    anchor = '''    if (equal_case(name, "$_SYSTEM_LEDS_ENABLED")) {\n        return runtime->system_leds_enabled;\n    }\n'''
    repl = anchor + '''    if (equal_case(name, "$_STORAGE_LEDS_ENABLED")) return runtime->storage_leds_enabled;\n    if (equal_case(name, "$_LED_CONTINUOUS_SHOW_STORAGE_ACTIVITY")) return runtime->continuous_storage_led;\n    if (equal_case(name, "$_INJECTING_LEDS_ENABLED")) return runtime->injecting_leds_enabled;\n    if (equal_case(name, "$_EXFIL_LEDS_ENABLED")) return runtime->exfil_leds_enabled;\n    if (equal_case(name, "$_LED_SHOW_CAPS")) return runtime->led_show_caps;\n    if (equal_case(name, "$_LED_SHOW_NUM")) return runtime->led_show_num;\n    if (equal_case(name, "$_LED_SHOW_SCROLL")) return runtime->led_show_scroll;\n    if (equal_case(name, "$_STORAGE_ACTIVITY_TIMEOUT")) return runtime->storage_activity_timeout_ms;\n    if (equal_case(name, "$_RANDOM_SEED")) return runtime->random_seed;\n    if (equal_case(name, "$_RANDOM_LOWER_LETTER_KEYCODE") ||\n        equal_case(name, "$_RANDOM_UPPER_LETTER_KEYCODE") ||\n        equal_case(name, "$_RANDOM_LETTER_KEYCODE")) {\n        return 0x04 + (random_u32(runtime) % 26U);\n    }\n    if (equal_case(name, "$_RANDOM_NUMBER_KEYCODE") ||\n        equal_case(name, "$_RANDOM_SPECIAL_KEYCODE")) {\n        uint32_t digit = random_u32(runtime) % 10U;\n        return digit == 0U ? 0x27 : 0x1d + digit;\n    }\n    if (equal_case(name, "$_RANDOM_CHAR_KEYCODE")) {\n        uint32_t choice = random_u32(runtime) % 46U;\n        if (choice < 26U) return 0x04 + choice;\n        choice %= 10U;\n        return choice == 0U ? 0x27 : 0x1d + choice;\n    }\n'''
    text = _one(text, anchor, repl, 'safe LED storage and random reads')
    anchor = '''    if (equal_case(name, "$_SYSTEM_LEDS_ENABLED")) {\n        return runtime->system_leds_enabled;\n    }\n'''
    repl = '''    if (equal_case(name, "$_EXFIL_MODE_ENABLED")) {\n        return runtime->io->exfil_mode_enabled != NULL &&\n               runtime->io->exfil_mode_enabled(runtime->io->context);\n    }\n''' + anchor
    text = _one(text, anchor, repl, 'readable Reflection mode variable')

    # OS symbolic values used by Hak5 extensions. Only equality matters inside payloads.
    anchor = '''        if (equal_case(name, "TRUE")) {\n            return 1;\n        }\n        if (equal_case(name, "FALSE")) {\n            return 0;\n        }\n'''
    repl = anchor + '''        if (equal_case(name, "WINDOWS")) return 1;\n        if (equal_case(name, "LINUX")) return 2;\n        if (equal_case(name, "MACOS")) return 3;\n        if (equal_case(name, "CHROMEOS")) return 4;\n        if (equal_case(name, "ANDROID")) return 5;\n        if (equal_case(name, "IOS")) return 6;\n'''
    text = _one(text, anchor, repl, 'OS symbolic constants')

    anchor = '''static bool execute_action(runtime_t *runtime, size_t line_number, bool *recognized)\n{\n'''
    repl = '''static bool slice_prefix_case(slice_t value, const char *prefix, slice_t *suffix)\n{\n    size_t length = strlen(prefix);\n    if (value.length < length) return false;\n    for (size_t i = 0; i < length; ++i) {\n        if (toupper((unsigned char)value.data[i]) !=\n            toupper((unsigned char)prefix[i])) return false;\n    }\n    if (suffix != NULL) {\n        *suffix = (slice_t){value.data + length, value.length - length};\n    }\n    return true;\n}\n\nstatic bool parse_attack_hex(slice_t token, const char *prefix, uint16_t *value)\n{\n    slice_t suffix;\n    if (!slice_prefix_case(token, prefix, &suffix) || suffix.length != 4U) return false;\n    uint16_t parsed = 0U;\n    for (size_t i = 0; i < suffix.length; ++i) {\n        unsigned char c = (unsigned char)suffix.data[i];\n        int digit = isdigit(c) ? c - '0' :\n            (c >= 'a' && c <= 'f') ? c - 'a' + 10 :\n            (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;\n        if (digit < 0) return false;\n        parsed = (uint16_t)((parsed << 4) | (uint16_t)digit);\n    }\n    *value = parsed;\n    return true;\n}\n\nstatic bool copy_attack_text(slice_t token, const char *prefix, char *out,\n                             size_t capacity, bool digits_only)\n{\n    slice_t suffix;\n    if (!slice_prefix_case(token, prefix, &suffix) || suffix.length == 0U ||\n        suffix.length >= capacity) return false;\n    for (size_t i = 0; i < suffix.length; ++i) {\n        unsigned char c = (unsigned char)suffix.data[i];\n        if (digits_only ? !isdigit(c) : !isalnum(c)) return false;\n    }\n    memcpy(out, suffix.data, suffix.length);\n    out[suffix.length] = '\\0';\n    return true;\n}\n\nstatic void random_attack_text(runtime_t *runtime, char *out, size_t length,\n                               bool digits_only)\n{\n    static const char alnum[] =\n        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";\n    static const char digits[] = "0123456789";\n    const char *set = digits_only ? digits : alnum;\n    size_t count = digits_only ? sizeof(digits) - 1U : sizeof(alnum) - 1U;\n    for (size_t i = 0; i < length; ++i) {\n        out[i] = set[random_u32(runtime) % count];\n    }\n    out[length] = '\\0';\n}\n\nstatic bool apply_attackmode_profile(runtime_t *runtime,\n                                     const ducky_attackmode_t *profile,\n                                     size_t line)\n{\n    bool ok = false;\n    if (runtime->io->attackmode_profile != NULL) {\n        ok = runtime->io->attackmode_profile(runtime->io->context, profile);\n    } else if (!profile->custom_identity && runtime->io->attackmode != NULL) {\n        ok = runtime->io->attackmode(runtime->io->context, profile->mode);\n    }\n    if (!ok) {\n        set_error(runtime, DUCKY_IO_ERROR, line, "ATTACKMODE transition failed");\n        return false;\n    }\n    runtime->current_attackmode = profile->mode;\n    runtime->attackmode_profile = *profile;\n    return true;\n}\n\nstatic bool execute_action(runtime_t *runtime, size_t line_number, bool *recognized)\n{\n'''
    text = _one(text, anchor, repl, 'dynamic ATTACKMODE parsing helpers')

    anchor = '''    if (equal_case(command, "ATTACKMODE")) {\n'''
    repl = '''    if (equal_case(command, "EXFIL")) {\n        slice_t name = trim(arguments);\n        int64_t value = 0;\n        bool found = false;\n        if (name.length >= 3U && name.data[0] == '$' && name.data[1] == '_') {\n            for (size_t i = 2U; i < name.length; ++i) {\n                if (!(isalnum((unsigned char)name.data[i]) || name.data[i] == '_')) {\n                    set_error(runtime, DUCKY_PARSE_ERROR, line_number,\n                              "EXFIL requires exactly one variable");\n                    return false;\n                }\n            }\n            value = expression_internal_variable(runtime, name, &found);\n        } else if (valid_name(name, '$')) {\n            int index = variable_index(runtime, name);\n            if (index >= 0) {\n                value = runtime->variables[index].value;\n                found = true;\n            }\n        }\n        if (!found) {\n            set_error(runtime, DUCKY_PARSE_ERROR, line_number,\n                      "EXFIL requires one defined readable variable");\n            return false;\n        }\n        if (runtime->io->variable_exfil == NULL) {\n            set_error(runtime, DUCKY_UNSUPPORTED, line_number,\n                      "Variable EXFIL is unavailable");\n            return false;\n        }\n        if (!runtime->io->variable_exfil(runtime->io->context, (uint16_t)value)) {\n            set_error(runtime, DUCKY_IO_ERROR, line_number, "EXFIL write failed");\n            return false;\n        }\n        return true;\n    }\n''' + anchor
    text = _one(text, anchor, repl, 'strict variable EXFIL command')

    # Replace HID-only ATTACKMODE implementation with logical composite-state bridge.
    old = '''    if (equal_case(command, "ATTACKMODE")) {\n        bool hid = false;\n        slice_t token;\n        while (next_token(&arguments, &token)) {\n            if (equal_case(token, "HID")) {\n                hid = true;\n            } else {\n                set_error_word(runtime, DUCKY_UNSUPPORTED, line_number, "Unsupported ATTACKMODE option: ", token);\n                return false;\n            }\n        }\n        if (!hid) {\n            set_error(runtime, DUCKY_UNSUPPORTED, line_number, "Only ATTACKMODE HID is supported during execution");\n            return false;\n        }\n        return true;\n    }\n'''
    new = '''    if (equal_case(command, "ATTACKMODE")) {\n        ducky_attackmode_t profile = {0};\n        bool hid = false, storage = false, off = false;\n        bool vid_set = false, pid_set = false;\n        bool man_set = false, prod_set = false, serial_set = false;\n        slice_t token;\n        while (next_token(&arguments, &token)) {\n            if (equal_case(token, "HID")) {\n                hid = true;\n            } else if (equal_case(token, "STORAGE")) {\n                storage = true;\n            } else if (equal_case(token, "OFF")) {\n                off = true;\n            } else if (equal_case(token, "VID_RANDOM")) {\n                profile.vid = (uint16_t)random_u32(runtime);\n                vid_set = true;\n            } else if (equal_case(token, "PID_RANDOM")) {\n                profile.pid = (uint16_t)random_u32(runtime);\n                pid_set = true;\n            } else if (equal_case(token, "MAN_RANDOM")) {\n                random_attack_text(runtime, profile.manufacturer, 12U, false);\n                man_set = true;\n            } else if (equal_case(token, "PROD_RANDOM")) {\n                random_attack_text(runtime, profile.product, 12U, false);\n                prod_set = true;\n            } else if (equal_case(token, "SERIAL_RANDOM")) {\n                random_attack_text(runtime, profile.serial, 12U, true);\n                serial_set = true;\n            } else if (parse_attack_hex(token, "VID_", &profile.vid)) {\n                vid_set = true;\n            } else if (parse_attack_hex(token, "PID_", &profile.pid)) {\n                pid_set = true;\n            } else if (copy_attack_text(token, "MAN_", profile.manufacturer,\n                                        sizeof(profile.manufacturer), false)) {\n                man_set = true;\n            } else if (copy_attack_text(token, "PROD_", profile.product,\n                                        sizeof(profile.product), false)) {\n                prod_set = true;\n            } else if (copy_attack_text(token, "SERIAL_", profile.serial,\n                                        sizeof(profile.serial), true)) {\n                serial_set = true;\n            } else {\n                set_error_word(runtime, DUCKY_PARSE_ERROR, line_number,\n                               "Invalid ATTACKMODE option: ", token);\n                return false;\n            }\n        }\n        if (off && (hid || storage)) {\n            set_error(runtime, DUCKY_PARSE_ERROR, line_number,\n                      "ATTACKMODE OFF cannot be combined");\n            return false;\n        }\n        profile.mode = off ? 0U :\n            (uint8_t)((hid ? 1U : 0U) | (storage ? 2U : 0U));\n        if (!off && profile.mode == 0U) {\n            set_error(runtime, DUCKY_PARSE_ERROR, line_number,\n                      "ATTACKMODE requires HID, STORAGE or OFF");\n            return false;\n        }\n        if (vid_set != pid_set) {\n            set_error(runtime, DUCKY_PARSE_ERROR, line_number,\n                      "ATTACKMODE VID and PID must be specified together");\n            return false;\n        }\n        if (man_set != prod_set || man_set != serial_set) {\n            set_error(runtime, DUCKY_PARSE_ERROR, line_number,\n                      "ATTACKMODE MAN, PROD and SERIAL must be specified together");\n            return false;\n        }\n        profile.custom_identity = vid_set || man_set;\n        if (off && profile.custom_identity) {\n            set_error(runtime, DUCKY_PARSE_ERROR, line_number,\n                      "ATTACKMODE OFF cannot use descriptor options");\n            return false;\n        }\n        return apply_attackmode_profile(runtime, &profile, line_number);\n    }\n    if (equal_case(command, "SAVE_ATTACKMODE")) {\n        runtime->saved_attackmode = runtime->current_attackmode;\n        runtime->saved_attackmode_profile = runtime->attackmode_profile;\n        runtime->attackmode_saved = true;\n        return true;\n    }\n    if (equal_case(command, "RESTORE_ATTACKMODE")) {\n        if (!runtime->attackmode_saved) {\n            set_error(runtime, DUCKY_IO_ERROR, line_number,\n                      "No saved ATTACKMODE or restore failed");\n            return false;\n        }\n        return apply_attackmode_profile(\n            runtime, &runtime->saved_attackmode_profile, line_number);\n    }\n'''
    text = _one(text, old, new, 'ATTACKMODE architecture')

    anchor = '''        ducky_attackmode_t profile = {0};\n        bool hid = false, storage = false, off = false;\n'''
    repl = '''        ducky_attackmode_t profile = {0};\n        profile.vid = runtime->io->current_vid != NULL\n            ? runtime->io->current_vid(runtime->io->context) : 0U;\n        profile.pid = runtime->io->current_pid != NULL\n            ? runtime->io->current_pid(runtime->io->context) : 0U;\n        bool hid = false, storage = false, off = false;\n'''
    text = _one(text, anchor, repl, 'ATTACKMODE inherited VID/PID defaults')

    # Random character commands + documented default integer range.
    old = '''    if (equal_case(command, "RANDOM_LOWERCASE_LETTER") ||\n        equal_case(command, "RANDOM_UPPERCASE_LETTER") ||\n        equal_case(command, "RANDOM_LETTER") ||\n        equal_case(command, "RANDOM_NUMBER")) {\n        char character;\n        uint32_t value = random_u32(runtime);\n        if (equal_case(command, "RANDOM_LOWERCASE_LETTER")) {\n            character = (char)('a' + value % 26);\n        } else if (equal_case(command, "RANDOM_UPPERCASE_LETTER")) {\n            character = (char)('A' + value % 26);\n        } else if (equal_case(command, "RANDOM_LETTER")) {\n            character = value & 1 ? (char)('a' + value % 26) : (char)('A' + value % 26);\n        } else {\n            character = (char)('0' + value % 10);\n        }\n        return type_text(runtime, (slice_t){&character, 1}, line_number);\n    }\n'''
    new = '''    if (equal_case(command, "RANDOM_LOWERCASE_LETTER") ||\n        equal_case(command, "RANDOM_UPPERCASE_LETTER") ||\n        equal_case(command, "RANDOM_LETTER") || equal_case(command, "RANDOM_NUMBER") ||\n        equal_case(command, "RANDOM_SPECIAL") || equal_case(command, "RANDOM_CHAR")) {\n        static const char lower[] = "abcdefghijklmnopqrstuvwxyz";\n        static const char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";\n        static const char letters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";\n        static const char numbers[] = "0123456789";\n        static const char special[] = "!@#$%^&*()";\n        static const char all[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";\n        const char *set = numbers; size_t n = sizeof(numbers) - 1U;\n        if (equal_case(command, "RANDOM_LOWERCASE_LETTER")) { set=lower; n=sizeof(lower)-1U; }\n        else if (equal_case(command, "RANDOM_UPPERCASE_LETTER")) { set=upper; n=sizeof(upper)-1U; }\n        else if (equal_case(command, "RANDOM_LETTER")) { set=letters; n=sizeof(letters)-1U; }\n        else if (equal_case(command, "RANDOM_SPECIAL")) { set=special; n=sizeof(special)-1U; }\n        else if (equal_case(command, "RANDOM_CHAR")) { set=all; n=sizeof(all)-1U; }\n        char character = set[random_u32(runtime) % n];\n        return type_text(runtime, (slice_t){&character, 1}, line_number);\n    }\n'''
    text = _one(text, old, new, 'DuckyScript random-character commands')
    text = _one(text, '.random_max = UINT16_MAX,', '.random_max = 9,', '$_RANDOM_INT default 0-9')

    # Source extensions are already expanded in PayloadStudio, but repo payloads may carry wrappers.
    anchor = '''        if (command.length == 0 || equal_case(command, "REM")) {\n            ++line_number;\n            continue;\n        }\n'''
    repl = anchor + '''        if (equal_case(command, "EXTENSION") || equal_case(command, "END_EXTENSION")) {\n            ++line_number;\n            continue;\n        }\n'''
    text = _one(text, anchor, repl, 'extension wrapper no-op')

    old = '''        if ((equal_case(command, "STRING") || equal_case(command, "STRINGLN")) &&\n            arguments.length == 0) {\n            const bool newline = equal_case(command, "STRINGLN");\n            const char *terminator = newline ? "END_STRINGLN" : "END_STRING";\n'''
    new = '''        if ((equal_case(command, "STRING") || equal_case(command, "STRINGLN") ||\n             equal_case(command, "STRING_POWERSHELL") ||\n             equal_case(command, "STRINGLN_POWERSHELL") ||\n             equal_case(command, "STRINGLN_BASH") ||\n             equal_case(command, "STRINGLN_BLOCK")) && arguments.length == 0) {\n            const bool newline = !equal_case(command, "STRING") &&\n                !equal_case(command, "STRING_POWERSHELL");\n            const char *terminator = newline ? "END_STRINGLN" : "END_STRING";\n'''
    text = _one(text, old, new, 'PayloadStudio STRING block aliases')

    old = '''            for (size_t content_line = line_number + 1; content_line < end; ++content_line) {\n                if (!type_text(runtime, get_line(runtime, content_line), content_line)) {\n                    return RUN_FAILED;\n                }\n                if (newline) {\n                    uint8_t enter[6] = {0x28};\n                    if (!tap_keys(runtime, 0, enter, content_line)) {\n                        return RUN_FAILED;\n                    }\n                }\n                delay_ms(runtime, runtime->default_delay_ms);\n            }\n            previous_action = SIZE_MAX;\n            line_number = end + 1;\n            continue;\n'''
    new = '''            for (size_t content_line = line_number + 1; content_line < end; ++content_line) {\n                slice_t content = get_line_raw(runtime, content_line);\n                if (newline) {\n                    /* Hak5 STRINGLN blocks strip exactly the first indentation\n                     * tab and preserve every remaining byte on the line. */\n                    if (content.length > 0 && content.data[0] == '\\t') {\n                        ++content.data;\n                        --content.length;\n                    }\n                } else {\n                    /* STRING blocks discard indentation and line breaks. */\n                    content = trim(content);\n                }\n                if (!type_text(runtime, content, content_line)) {\n                    return RUN_FAILED;\n                }\n                if (newline) {\n                    uint8_t enter[6] = {0x28};\n                    if (!tap_keys(runtime, 0, enter, content_line)) {\n                        return RUN_FAILED;\n                    }\n                }\n            }\n            if (!delay_ms(runtime, runtime->default_delay_ms, line_number)) return RUN_FAILED;\n            previous_action = SIZE_MAX;\n            line_number = end + 1;\n            continue;\n'''
    text = _one(text, old, new, 'exact STRING block whitespace')

    old = '''                delay_ms(runtime, runtime->default_delay_ms);\n            }\n            ++line_number;\n            continue;\n'''
    new = '''                if (!delay_ms(runtime, runtime->default_delay_ms, line_number)) return RUN_FAILED;\n            }\n            ++line_number;\n            continue;\n'''
    text = _one(text, old, new, 'REPEAT default delay')

    old = '''            delay_ms(runtime, runtime->default_delay_ms);\n            previous_action = SIZE_MAX;\n            ++line_number;\n            continue;\n'''
    new = '''            if (!delay_ms(runtime, runtime->default_delay_ms, line_number)) return RUN_FAILED;\n            previous_action = SIZE_MAX;\n            ++line_number;\n            continue;\n'''
    text = _one(text, old, new, 'function-call default delay')

    old = '''        delay_ms(runtime, runtime->default_delay_ms);\n        previous_action = line_number;\n'''
    new = '''        if (!delay_ms(runtime, runtime->default_delay_ms, line_number)) return RUN_FAILED;\n        previous_action = line_number;\n'''
    text = _one(text, old, new, 'action default delay')

    old = '''        if (equal_case(command, "REPEAT")) {
            int64_t repeat_count;
            if (previous_action == SIZE_MAX ||
                !evaluate_expression(runtime, arguments, line_number, &repeat_count) ||
                repeat_count < 0 || repeat_count > UINT32_MAX) {
                if (runtime->result.status == DUCKY_OK) {
                    set_error(runtime, DUCKY_PARSE_ERROR, line_number, "Invalid REPEAT count or no previous action");
                }
                return RUN_FAILED;
            }
            for (int64_t i = 0; i < repeat_count; ++i) {
                bool recognized = false;
                if (!execute_action(runtime, previous_action, &recognized)) {
                    return RUN_FAILED;
                }
                if (!delay_ms(runtime, runtime->default_delay_ms, line_number)) return RUN_FAILED;
            }
            ++line_number;
            continue;
        }
'''
    new = '''        if (equal_case(command, "REPEAT")) {
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
'''
    text = _one(text, old, new, 'legacy inline key REPEAT')

    anchor = '''static run_outcome_t run_range(
    runtime_t *runtime,
    size_t first_line,
    size_t end_line,
    bool is_function,
    int64_t *return_value)
{
'''
    repl = '''static bool is_line_comment(slice_t command)
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

''' + anchor
    text = _one(text, anchor, repl, 'legacy comment spellings')

    # Hak5's *_DEFINED directives are compile-time gates. Build a line mask
    # before function discovery so inactive declarations and malformed commands
    # are removed like preprocessed source, rather than only skipped at runtime.
    anchor = '''static bool is_command_at(runtime_t *runtime, size_t line_number, const char *command)\n{\n    slice_t arguments;\n    return equal_case(first_word(get_line(runtime, line_number), &arguments), command);\n}\n'''
    repl = '''typedef struct {\n    bool parent_active;\n    bool condition;\n    bool saw_else;\n} defined_frame_t;\n\nstatic bool defined_condition(runtime_t *runtime, slice_t arguments, bool invert,\n                              size_t line, bool *value)\n{\n    slice_t name = trim(arguments);\n    if (!valid_name(name, '#')) {\n        set_error(runtime, DUCKY_PARSE_ERROR, line,\n                  "IF_DEFINED directive requires one #CONSTANT");\n        return false;\n    }\n    int index = constant_index(runtime, name);\n    bool is_true = false;\n    if (index >= 0) {\n        int64_t evaluated = 0;\n        if (!evaluate_expression(runtime, runtime->constants[index].replacement, line, &evaluated)) {\n            return false;\n        }\n        is_true = evaluated != 0;\n    }\n    *value = invert ? !is_true : is_true;\n    return true;\n}\n\nstatic bool preprocess_defined_blocks(runtime_t *runtime)\n{\n    if (runtime->line_count == 0) return true;\n    runtime->line_enabled = calloc(runtime->line_count, sizeof(runtime->line_enabled[0]));\n    if (runtime->line_enabled == NULL) {\n        set_error(runtime, DUCKY_OUT_OF_MEMORY, 0, "Could not allocate compile-time line mask");\n        return false;\n    }\n    defined_frame_t stack[DUCKY_MAX_CALL_DEPTH];\n    size_t depth = 0;\n    bool active = true;\n    for (size_t line = 0; line < runtime->line_count; ++line) {\n        slice_t arguments;\n        slice_t command = first_word(get_line(runtime, line), &arguments);\n        if (equal_case(command, "IF_DEFINED_TRUE") ||\n            equal_case(command, "IF_NOT_DEFINED_TRUE")) {\n            runtime->line_enabled[line] = false;\n            if (depth == DUCKY_MAX_CALL_DEPTH) {\n                set_error(runtime, DUCKY_LIMIT_EXCEEDED, line,\n                          "IF_DEFINED nesting depth exceeded");\n                return false;\n            }\n            bool condition = false;\n            if (active && !defined_condition(runtime, arguments,\n                    equal_case(command, "IF_NOT_DEFINED_TRUE"), line, &condition)) {\n                return false;\n            }\n            stack[depth++] = (defined_frame_t){active, condition, false};\n            active = active && condition;\n            continue;\n        }\n        if (equal_case(command, "ELSE_DEFINED")) {\n            runtime->line_enabled[line] = false;\n            if (arguments.length != 0 || depth == 0 || stack[depth - 1].saw_else) {\n                set_error(runtime, DUCKY_PARSE_ERROR, line,\n                          "ELSE_DEFINED without one matching IF_DEFINED directive");\n                return false;\n            }\n            stack[depth - 1].saw_else = true;\n            active = stack[depth - 1].parent_active && !stack[depth - 1].condition;\n            continue;\n        }\n        if (equal_case(command, "END_IF_DEFINED")) {\n            runtime->line_enabled[line] = false;\n            if (arguments.length != 0 || depth == 0) {\n                set_error(runtime, DUCKY_PARSE_ERROR, line,\n                          "END_IF_DEFINED without matching IF_DEFINED directive");\n                return false;\n            }\n            active = stack[--depth].parent_active;\n            continue;\n        }\n        if (equal_case(command, "DEFINE")) {\n            runtime->line_enabled[line] = false;\n            if (active && !define_constant(runtime, arguments, line)) return false;\n            continue;\n        }\n        runtime->line_enabled[line] = active;\n    }\n    if (depth != 0) {\n        set_error(runtime, DUCKY_PARSE_ERROR, runtime->line_count - 1,\n                  "IF_DEFINED directive without END_IF_DEFINED");\n        return false;\n    }\n    return true;\n}\n\nstatic bool is_command_at(runtime_t *runtime, size_t line_number, const char *command)\n{\n    if (runtime->line_enabled != NULL && !runtime->line_enabled[line_number]) return false;\n    slice_t arguments;\n    return equal_case(first_word(get_line(runtime, line_number), &arguments), command);\n}\n'''
    text = _one(text, anchor, repl, 'compile-time IF_DEFINED preprocessor')
    text = _one(
        text,
        "    if (!valid_name(name, '#')) {\n",
        "    if (!valid_constant_name(name) || name.data[0] != '#') {\n",
        'hyphenated IF_DEFINED constant name',
    )

    old = '''    size_t depth = 0;\n    bool active = true;\n    for (size_t line = 0; line < runtime->line_count; ++line) {\n        slice_t arguments;\n        slice_t command = first_word(get_line(runtime, line), &arguments);\n'''
    new = '''    size_t depth = 0;\n    bool active = true;\n    bool rem_block = false;\n    const char *string_terminator = NULL;\n    for (size_t line = 0; line < runtime->line_count; ++line) {\n        slice_t arguments;\n        slice_t command = first_word(get_line(runtime, line), &arguments);\n        if (rem_block) {\n            runtime->line_enabled[line] = active;\n            if (equal_case(command, "END_REM")) rem_block = false;\n            continue;\n        }\n        if (string_terminator != NULL) {\n            runtime->line_enabled[line] = active;\n            if (equal_case(command, string_terminator)) string_terminator = NULL;\n            continue;\n        }\n        if (active && equal_case(command, "REM_BLOCK")) {\n            runtime->line_enabled[line] = true;\n            rem_block = true;\n            continue;\n        }\n        if (active && arguments.length == 0 &&\n            (equal_case(command, "STRING") || equal_case(command, "STRINGLN") ||\n             equal_case(command, "STRING_POWERSHELL") ||\n             equal_case(command, "STRINGLN_POWERSHELL") ||\n             equal_case(command, "STRINGLN_BASH") ||\n             equal_case(command, "STRINGLN_BLOCK"))) {\n            runtime->line_enabled[line] = true;\n            string_terminator = (equal_case(command, "STRING") ||\n                equal_case(command, "STRING_POWERSHELL")) ? "END_STRING" : "END_STRINGLN";\n            continue;\n        }\n'''
    text = _one(text, old, new, 'preprocessor literal-block awareness')

    # Hak5 DEFINE is a recursive textual compile-time substitution. Compile
    # every active source line before block discovery and execution. Inactive
    # and directive lines become blank so diagnostic line numbers stay stable.
    anchor = '''static bool is_command_at(runtime_t *runtime, size_t line_number, const char *command)\n{\n    if (runtime->line_enabled != NULL && !runtime->line_enabled[line_number]) return false;\n    slice_t arguments;\n    return equal_case(first_word(get_line(runtime, line_number), &arguments), command);\n}\n'''
    repl = '''typedef struct {\n    char *data;\n    size_t length;\n    size_t capacity;\n} source_builder_t;\n\nstatic bool source_builder_reserve(runtime_t *runtime, source_builder_t *builder,\n                                   size_t additional, size_t line)\n{\n    if (additional > SIZE_MAX - builder->length - 1U) {\n        set_error(runtime, DUCKY_LIMIT_EXCEEDED, line, "Preprocessed source is too large");\n        return false;\n    }\n    size_t needed = builder->length + additional + 1U;\n    if (needed <= builder->capacity) return true;\n    size_t capacity = builder->capacity != 0 ? builder->capacity : 256U;\n    while (capacity < needed) {\n        if (capacity > SIZE_MAX / 2U) {\n            capacity = needed;\n            break;\n        }\n        capacity *= 2U;\n    }\n    char *grown = (char *)realloc(builder->data, capacity);\n    if (grown == NULL) {\n        set_error(runtime, DUCKY_OUT_OF_MEMORY, line, "Could not allocate preprocessed source");\n        return false;\n    }\n    builder->data = grown;\n    builder->capacity = capacity;\n    return true;\n}\n\nstatic bool source_builder_append(runtime_t *runtime, source_builder_t *builder,\n                                  const char *data, size_t length, size_t line)\n{\n    if (!source_builder_reserve(runtime, builder, length, line)) return false;\n    if (length != 0) memcpy(builder->data + builder->length, data, length);\n    builder->length += length;\n    builder->data[builder->length] = '\\0';\n    return true;\n}\n\nstatic bool append_expanded_source(runtime_t *runtime, source_builder_t *builder,\n                                   slice_t source, size_t line, unsigned depth)\n{\n    if (depth > DUCKY_MAX_CALL_DEPTH) {\n        set_error(runtime, DUCKY_LIMIT_EXCEEDED, line, "DEFINE expansion depth exceeded");\n        return false;\n    }\n    size_t copied = 0;\n    for (size_t i = 0; i < source.length; ++i) {\n        if (source.data[i] != '#' || i + 1 >= source.length ||\n            !(isalpha((unsigned char)source.data[i + 1]) || source.data[i + 1] == '_')) {\n            continue;\n        }\n        size_t end = i + 2;\n        while (end < source.length &&\n               (isalnum((unsigned char)source.data[end]) || source.data[end] == '_')) {\n            ++end;\n        }\n        slice_t name = {source.data + i, end - i};\n        int constant = constant_index(runtime, name);\n        if (constant < 0) {\n            i = end - 1;\n            continue;\n        }\n        if (!source_builder_append(runtime, builder, source.data + copied, i - copied, line) ||\n            !append_expanded_source(runtime, builder,\n                runtime->constants[constant].replacement, line, depth + 1U)) {\n            return false;\n        }\n        copied = end;\n        i = end - 1;\n    }\n    return source_builder_append(runtime, builder,\n        source.data + copied, source.length - copied, line);\n}\n\nstatic bool build_line_index(runtime_t *runtime);\n\nstatic bool compile_defined_source(runtime_t *runtime)\n{\n    source_builder_t builder = {0};\n    for (size_t line = 0; line < runtime->line_count; ++line) {\n        if (runtime->line_enabled == NULL || runtime->line_enabled[line]) {\n            if (!append_expanded_source(runtime, &builder, get_line_raw(runtime, line), line, 0)) {\n                free(builder.data);\n                return false;\n            }\n        }\n        if (line + 1U < runtime->line_count &&\n            !source_builder_append(runtime, &builder, "\\n", 1, line)) {\n            free(builder.data);\n            return false;\n        }\n    }\n    if (builder.data == NULL) {\n        builder.data = (char *)calloc(1, 1);\n        if (builder.data == NULL) {\n            set_error(runtime, DUCKY_OUT_OF_MEMORY, 0, "Could not allocate empty preprocessed source");\n            return false;\n        }\n    }\n    free(runtime->line_offsets);\n    runtime->line_offsets = NULL;\n    free(runtime->line_enabled);\n    runtime->line_enabled = NULL;\n    runtime->compiled_script = builder.data;\n    runtime->script = builder.data;\n    runtime->script_length = builder.length;\n    return build_line_index(runtime);\n}\n\nstatic bool is_command_at(runtime_t *runtime, size_t line_number, const char *command)\n{\n    if (runtime->line_enabled != NULL && !runtime->line_enabled[line_number]) return false;\n    slice_t arguments;\n    return equal_case(first_word(get_line(runtime, line_number), &arguments), command);\n}\n'''
    text = _one(text, anchor, repl, 'full DEFINE source compiler')
    old = '''    size_t copied = 0;
    for (size_t i = 0; i < source.length; ++i) {
        if (source.data[i] != '#' || i + 1 >= source.length ||
            !(isalpha((unsigned char)source.data[i + 1]) || source.data[i + 1] == '_')) {
            continue;
        }
        size_t end = i + 2;
        while (end < source.length &&
               (isalnum((unsigned char)source.data[end]) || source.data[end] == '_')) {
            ++end;
        }
        slice_t name = {source.data + i, end - i};
        int constant = constant_index(runtime, name);
        if (constant < 0) {
            i = end - 1;
            continue;
        }
        if (!source_builder_append(runtime, builder, source.data + copied, i - copied, line) ||
            !append_expanded_source(runtime, builder,
                runtime->constants[constant].replacement, line, depth + 1U)) {
            return false;
        }
        copied = end;
        i = end - 1;
    }
'''
    new = '''    size_t copied = 0;
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
'''
    text = _one(text, old, new, 'bare and hyphenated DEFINE expansion')

    anchor = '''static size_t find_matching_forward(
'''
    repl = '''static const char *literal_block_terminator(slice_t command, slice_t arguments)
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

''' + anchor
    text = _one(text, anchor, repl, 'literal block structural helper')

    old = '''    unsigned depth = 0;
    for (size_t line = opener_line + 1; line < end_line; ++line) {
        if (is_command_at(runtime, line, opener)) {
            ++depth;
        } else if (is_command_at(runtime, line, closer)) {
'''
    new = '''    unsigned depth = 0;
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
'''
    text = _one(text, old, new, 'literal-aware forward block matching')

    old = '''    unsigned depth = 0;
    size_t line = closer_line;
    while (line > first_line) {
        --line;
        if (is_command_at(runtime, line, closer)) {
            ++depth;
        } else if (is_command_at(runtime, line, opener)) {
            if (depth == 0) {
                return line;
            }
            --depth;
        }
    }
    return SIZE_MAX;
'''
    new = '''    size_t stack[DUCKY_MAX_CALL_DEPTH];
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
'''
    text = _one(text, old, new, 'literal-aware backward block matching')

    old = '''    unsigned depth = 0;
    for (size_t line = if_line + 1; line < end_line; ++line) {
        slice_t arguments;
'''
    new = '''    unsigned depth = 0;
    for (size_t line = if_line + 1; line < end_line; ++line) {
        size_t literal_end = skip_literal_block(runtime, line, end_line);
        if (literal_end == SIZE_MAX) return SIZE_MAX;
        if (literal_end != line) {
            line = literal_end;
            continue;
        }
        slice_t arguments;
'''
    text = _one(text, old, new, 'literal-aware false IF branch selection')

    old = '''    unsigned depth = 0;
    for (size_t line = line_number + 1; line < end_line; ++line) {
        if (is_command_at(runtime, line, "IF")) {
'''
    new = '''    unsigned depth = 0;
    for (size_t line = line_number + 1; line < end_line; ++line) {
        size_t literal_end = skip_literal_block(runtime, line, end_line);
        if (literal_end == SIZE_MAX) return SIZE_MAX;
        if (literal_end != line) {
            line = literal_end;
            continue;
        }
        if (is_command_at(runtime, line, "IF")) {
'''
    text = _one(text, old, new, 'literal-aware ELSE branch skipping')

    # Internal names such as $_HOST_CONFIGURATION_REQUEST_COUNT are longer
    # than the user-variable storage limit. They are slices, never copied into
    # DUCKY_MAX_NAME buffers, so validate their characters without truncation.
    old = '''    char prefix = read_only ? '#' : '$';\n    if (!valid_name(name, prefix)) {\n        set_error(runtime, DUCKY_PARSE_ERROR, source_line, "Invalid variable or constant name");\n        return false;\n    }\n'''
    new = '''    char prefix = read_only ? '#' : '$';\n    bool valid_internal = !read_only && name.length >= 3 &&\n        name.data[0] == '$' && name.data[1] == '_';\n    for (size_t i = 2; valid_internal && i < name.length; ++i) {\n        if (!(isalnum((unsigned char)name.data[i]) || name.data[i] == '_')) {\n            valid_internal = false;\n        }\n    }\n    if (!valid_name(name, prefix) && !valid_internal) {\n        set_error(runtime, DUCKY_PARSE_ERROR, source_line, "Invalid variable or constant name");\n        return false;\n    }\n'''
    text = _one(text, old, new, 'long internal variable assignment')

    anchor = '''    runtime->button_first_line = SIZE_MAX;\n    runtime->button_end_line = SIZE_MAX;\n    for (size_t line = 0; line < runtime->line_count; ++line) {\n        slice_t arguments;\n'''
    repl = '''    runtime->button_first_line = SIZE_MAX;\n    runtime->button_end_line = SIZE_MAX;\n    bool rem_block = false;\n    const char *string_terminator = NULL;\n    for (size_t line = 0; line < runtime->line_count; ++line) {\n        if (runtime->line_enabled != NULL && !runtime->line_enabled[line]) continue;\n        slice_t arguments;\n        slice_t scan_command = first_word(get_line(runtime, line), &arguments);\n        if (rem_block) {\n            if (equal_case(scan_command, "END_REM")) rem_block = false;\n            continue;\n        }\n        if (string_terminator != NULL) {\n            if (equal_case(scan_command, string_terminator)) string_terminator = NULL;\n            continue;\n        }\n        if (equal_case(scan_command, "REM_BLOCK")) {\n            rem_block = true;\n            continue;\n        }\n        if (arguments.length == 0U &&\n            (equal_case(scan_command, "STRING") || equal_case(scan_command, "STRINGLN") ||\n             equal_case(scan_command, "STRING_POWERSHELL") ||\n             equal_case(scan_command, "STRINGLN_POWERSHELL") ||\n             equal_case(scan_command, "STRINGLN_BASH") ||\n             equal_case(scan_command, "STRINGLN_BLOCK"))) {\n            string_terminator = (equal_case(scan_command, "STRING") ||\n                equal_case(scan_command, "STRING_POWERSHELL")) ?\n                    "END_STRING" : "END_STRINGLN";\n            continue;\n        }\n'''
    text = _one(text, anchor, repl, 'literal-aware function scan filtering')

    anchor = '''        slice_t line = get_line(runtime, line_number);\n        slice_t arguments;\n'''
    repl = '''        if (runtime->line_enabled != NULL && !runtime->line_enabled[line_number]) {\n            ++line_number;\n            continue;\n        }\n        slice_t line = get_line(runtime, line_number);\n        slice_t arguments;\n'''
    text = _one(text, anchor, repl, 'inactive runtime line filtering')

    old = '''        slice_t command = first_word(line, &arguments);\n        if (command.length == 0 || equal_case(command, "REM")) {\n'''
    new = '''        slice_t command = first_word(line, &arguments);\n        if (!equal_case(command, "WAIT_FOR_BUTTON_PRESS") &&\n            !poll_async_button(runtime, line_number)) {\n            return RUN_FAILED;\n        }\n        if (command.length == 0 || is_line_comment(command)) {\n'''
    text = _one(text, old, new, 'button polling between instructions')

    # Initial logical state is HID; hardware callback may report composite availability separately.
    anchor = '''        .button_enabled = true,\n        .fallback_random = 0x6D2B79F5U,\n'''
    repl = '''        .button_enabled = true,\n        .current_attackmode = 1U,\n        .attackmode_profile = {.mode = 1U},\n        .os = 0U,\n        .fallback_random = 0x6D2B79F5U,\n        .random_seed = 0x79F5U,\n        .storage_activity_timeout_ms = 1000U,\n        .storage_leds_enabled = true,\n        .continuous_storage_led = true,\n        .injecting_leds_enabled = true,\n        .exfil_leds_enabled = true,\n'''
    text = _one(text, anchor, repl, 'safe runtime variable defaults')

    anchor = '''    if (runtime->config.max_lines == 0 || runtime->config.max_execution_steps == 0) {\n'''
    repl = '''    if (io->random_u32 != NULL) {\n        runtime->fallback_random = io->random_u32(io->context);\n        runtime->random_seed = (uint16_t)runtime->fallback_random;\n    }\n    publish_runtime_options(runtime);\n    if (io->host_os_guess != NULL) {\n        runtime->os = io->host_os_guess(io->context);\n    }\n    if (runtime->config.max_lines == 0 || runtime->config.max_execution_steps == 0) {\n'''
    text = _one(text, anchor, repl, 'initial random seed options and host OS snapshot')

    old = '''    if (!build_line_index(runtime) || !scan_blocks(runtime)) {\n        ducky_result_t result = runtime->result;\n        free(runtime->line_offsets);\n        free(runtime);\n        return result;\n    }\n'''
    new = '''    if (!build_line_index(runtime) || !preprocess_defined_blocks(runtime) ||\n        !compile_defined_source(runtime) || !scan_blocks(runtime)) {\n        ducky_result_t result = runtime->result;\n        free(runtime->compiled_script);\n        free(runtime->line_enabled);\n        free(runtime->line_offsets);\n        free(runtime);\n        return result;\n    }\n'''
    text = _one(text, old, new, 'compile-time preprocessor invocation')

    old = '''    ducky_result_t result = runtime->result;\n    free(runtime->line_offsets);\n'''
    new = '''    ducky_result_t result = runtime->result;\n    free(runtime->compiled_script);\n    free(runtime->line_enabled);\n    free(runtime->line_offsets);\n'''
    text = _one(text, old, new, 'compile-time line mask cleanup')

    anchor = '''ducky_result_t ducky_run(\n'''
    inspector = r'''static bool capability_word_equal(const char *data, size_t length, const char *word)
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

'''
    text = _one(text, anchor, inspector + anchor, 'shared Stage 8 capability inspector')
    return text


def patch_ducky_keymap_c(text: str) -> str:
    old = '''    {"RIGHTARROW", DUCKY_KEY_TOKEN_KEY, KEY_RIGHT},
    {"ARROWRIGHT", DUCKY_KEY_TOKEN_KEY, KEY_RIGHT},
    {"LEFT", DUCKY_KEY_TOKEN_KEY, KEY_LEFT},
    {"LEFTARROW", DUCKY_KEY_TOKEN_KEY, KEY_LEFT},
    {"ARROWLEFT", DUCKY_KEY_TOKEN_KEY, KEY_LEFT},
    {"DOWN", DUCKY_KEY_TOKEN_KEY, KEY_DOWN},
    {"DOWNARROW", DUCKY_KEY_TOKEN_KEY, KEY_DOWN},
    {"ARROWDOWN", DUCKY_KEY_TOKEN_KEY, KEY_DOWN},
    {"UP", DUCKY_KEY_TOKEN_KEY, KEY_UP},
    {"UPARROW", DUCKY_KEY_TOKEN_KEY, KEY_UP},
    {"ARROWUP", DUCKY_KEY_TOKEN_KEY, KEY_UP},
'''
    new = '''    {"RIGHTARROW", DUCKY_KEY_TOKEN_KEY, KEY_RIGHT},
    {"RIGHT_ARROW", DUCKY_KEY_TOKEN_KEY, KEY_RIGHT},
    {"ARROWRIGHT", DUCKY_KEY_TOKEN_KEY, KEY_RIGHT},
    {"LEFT", DUCKY_KEY_TOKEN_KEY, KEY_LEFT},
    {"LEFTARROW", DUCKY_KEY_TOKEN_KEY, KEY_LEFT},
    {"LEFT_ARROW", DUCKY_KEY_TOKEN_KEY, KEY_LEFT},
    {"ARROWLEFT", DUCKY_KEY_TOKEN_KEY, KEY_LEFT},
    {"DOWN", DUCKY_KEY_TOKEN_KEY, KEY_DOWN},
    {"DOWNARROW", DUCKY_KEY_TOKEN_KEY, KEY_DOWN},
    {"DOWN_ARROW", DUCKY_KEY_TOKEN_KEY, KEY_DOWN},
    {"ARROWDOWN", DUCKY_KEY_TOKEN_KEY, KEY_DOWN},
    {"UP", DUCKY_KEY_TOKEN_KEY, KEY_UP},
    {"UPARROW", DUCKY_KEY_TOKEN_KEY, KEY_UP},
    {"UP_ARROW", DUCKY_KEY_TOKEN_KEY, KEY_UP},
    {"ARROWUP", DUCKY_KEY_TOKEN_KEY, KEY_UP},
'''
    text = _one(text, old, new, 'underscore cursor aliases')

    old = '''    {"KP_SLASH", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_DIVIDE},
    {"KP_ASTERISK", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_MULTIPLY},
    {"KP_MINUS", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_SUBTRACT},
    {"KP_PLUS", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_ADD},
    {"KP_ENTER", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_ENTER},
    {"KP_DOT", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_DECIMAL},
'''
    new = '''    {"KP_SLASH", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_DIVIDE},
    {"KPAD_SLASH", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_DIVIDE},
    {"KP_ASTERISK", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_MULTIPLY},
    {"KPAD_ASTERISK", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_MULTIPLY},
    {"KP_MINUS", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_SUBTRACT},
    {"KPAD_MINUS", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_SUBTRACT},
    {"KP_PLUS", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_ADD},
    {"KPAD_PLUS", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_ADD},
    {"KP_ENTER", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_ENTER},
    {"KPAD_ENTER", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_ENTER},
    {"KP_DOT", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_DECIMAL},
    {"KPAD_DOT", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_DECIMAL},
'''
    text = _one(text, old, new, 'KPAD operator aliases')

    old = '''    if (length == 3 && toupper((unsigned char)name[0]) == 'K' &&
        toupper((unsigned char)name[1]) == 'P' && isdigit((unsigned char)name[2])) {
        unsigned number = (unsigned)(name[2] - '0');
'''
    new = '''    bool kp_digit = length == 3 && toupper((unsigned char)name[0]) == 'K' &&
        toupper((unsigned char)name[1]) == 'P' && isdigit((unsigned char)name[2]);
    bool kpad_digit = length == 6 && toupper((unsigned char)name[0]) == 'K' &&
        toupper((unsigned char)name[1]) == 'P' &&
        toupper((unsigned char)name[2]) == 'A' &&
        toupper((unsigned char)name[3]) == 'D' && name[4] == '_' &&
        isdigit((unsigned char)name[5]);
    if (kp_digit || kpad_digit) {
        unsigned number = (unsigned)(name[kp_digit ? 2 : 5] - '0');
'''
    return _one(text, old, new, 'KPAD digit aliases')


TRANSFORMS = {
    "ducky/components/ducky/ducky.c": patch_ducky_c,
    "ducky/components/ducky/ducky_keymap.c": patch_ducky_keymap_c,
    "ducky/components/ducky/include/ducky.h": patch_ducky_h,
}
