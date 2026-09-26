#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    DUCKY_KEY_TOKEN_INVALID,
    DUCKY_KEY_TOKEN_KEY,
    DUCKY_KEY_TOKEN_MODIFIER,
    DUCKY_KEY_TOKEN_CONSUMER,
    DUCKY_KEY_TOKEN_SYSTEM,
} ducky_key_token_kind_t;

typedef struct {
    ducky_key_token_kind_t kind;
    uint16_t value;
    uint8_t implied_modifiers;
} ducky_key_token_t;

bool ducky_ascii_to_key(char character, uint8_t *keycode, uint8_t *modifiers);
ducky_key_token_t ducky_lookup_key(const char *name, size_t length);
bool ducky_lookup_mouse_button(const char *name, size_t length, uint8_t *button);
