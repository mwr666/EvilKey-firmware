#include "../../../../pf_build_config.h"
#include "ducky_keymap.h"

#include <ctype.h>
#include <string.h>

#include "include/ducky_hid_codes.h"

enum {
    KEY_A = 0x04,
    KEY_1 = 0x1E,
    KEY_ENTER = 0x28,
    KEY_ESCAPE = 0x29,
    KEY_BACKSPACE = 0x2A,
    KEY_TAB = 0x2B,
    KEY_SPACE = 0x2C,
    KEY_MINUS = 0x2D,
    KEY_EQUAL = 0x2E,
    KEY_LEFT_BRACKET = 0x2F,
    KEY_RIGHT_BRACKET = 0x30,
    KEY_BACKSLASH = 0x31,
    KEY_SEMICOLON = 0x33,
    KEY_APOSTROPHE = 0x34,
    KEY_GRAVE = 0x35,
    KEY_COMMA = 0x36,
    KEY_PERIOD = 0x37,
    KEY_SLASH = 0x38,
    KEY_CAPS_LOCK = 0x39,
    KEY_F1 = 0x3A,
    KEY_PRINT_SCREEN = 0x46,
    KEY_SCROLL_LOCK = 0x47,
    KEY_PAUSE = 0x48,
    KEY_INSERT = 0x49,
    KEY_HOME = 0x4A,
    KEY_PAGE_UP = 0x4B,
    KEY_DELETE = 0x4C,
    KEY_END = 0x4D,
    KEY_PAGE_DOWN = 0x4E,
    KEY_RIGHT = 0x4F,
    KEY_LEFT = 0x50,
    KEY_DOWN = 0x51,
    KEY_UP = 0x52,
    KEY_NUM_LOCK = 0x53,
    KEY_KEYPAD_DIVIDE = 0x54,
    KEY_KEYPAD_MULTIPLY = 0x55,
    KEY_KEYPAD_SUBTRACT = 0x56,
    KEY_KEYPAD_ADD = 0x57,
    KEY_KEYPAD_ENTER = 0x58,
    KEY_KEYPAD_1 = 0x59,
    KEY_KEYPAD_0 = 0x62,
    KEY_KEYPAD_DECIMAL = 0x63,
    KEY_APPLICATION = 0x65,
    KEY_POWER = 0x66,
    KEY_F13 = 0x68,
};

typedef struct {
    const char *name;
    ducky_key_token_kind_t kind;
    uint16_t value;
} named_key_t;

static const named_key_t s_named_keys[] = {
    {"CTRL", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_CTRL},
    {"CONTROL", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_CTRL},
    {"LCTRL", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_CTRL},
    {"LEFTCTRL", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_CTRL},
    {"LEFT_CONTROL", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_CTRL},
    {"RCTRL", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_RIGHT_CTRL},
    {"RIGHTCTRL", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_RIGHT_CTRL},
    {"RIGHT_CONTROL", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_RIGHT_CTRL},
    {"SHIFT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_SHIFT},
    {"LSHIFT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_SHIFT},
    {"LEFTSHIFT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_SHIFT},
    {"LEFT_SHIFT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_SHIFT},
    {"RSHIFT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_RIGHT_SHIFT},
    {"RIGHTSHIFT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_RIGHT_SHIFT},
    {"RIGHT_SHIFT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_RIGHT_SHIFT},
    {"ALT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_ALT},
    {"OPTION", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_ALT},
    {"LALT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_ALT},
    {"LEFTALT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_ALT},
    {"LEFT_ALT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_ALT},
    {"RALT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_RIGHT_ALT},
    {"RIGHTALT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_RIGHT_ALT},
    {"RIGHT_ALT", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_RIGHT_ALT},
    {"ALTGR", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_RIGHT_ALT},
    {"GUI", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_GUI},
    {"WINDOWS", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_GUI},
    {"COMMAND", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_GUI},
    {"META", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_GUI},
    {"LGUI", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_LEFT_GUI},
    {"RGUI", DUCKY_KEY_TOKEN_MODIFIER, DUCKY_MOD_RIGHT_GUI},
    {"ENTER", DUCKY_KEY_TOKEN_KEY, KEY_ENTER},
    {"RETURN", DUCKY_KEY_TOKEN_KEY, KEY_ENTER},
    {"ESC", DUCKY_KEY_TOKEN_KEY, KEY_ESCAPE},
    {"ESCAPE", DUCKY_KEY_TOKEN_KEY, KEY_ESCAPE},
    {"BACKSPACE", DUCKY_KEY_TOKEN_KEY, KEY_BACKSPACE},
    {"BKSP", DUCKY_KEY_TOKEN_KEY, KEY_BACKSPACE},
    {"TAB", DUCKY_KEY_TOKEN_KEY, KEY_TAB},
    {"SPACE", DUCKY_KEY_TOKEN_KEY, KEY_SPACE},
    {"SPACEBAR", DUCKY_KEY_TOKEN_KEY, KEY_SPACE},
    {"CAPSLOCK", DUCKY_KEY_TOKEN_KEY, KEY_CAPS_LOCK},
    {"CAPS_LOCK", DUCKY_KEY_TOKEN_KEY, KEY_CAPS_LOCK},
    {"PRINTSCREEN", DUCKY_KEY_TOKEN_KEY, KEY_PRINT_SCREEN},
    {"PRINT_SCREEN", DUCKY_KEY_TOKEN_KEY, KEY_PRINT_SCREEN},
    {"SCROLLLOCK", DUCKY_KEY_TOKEN_KEY, KEY_SCROLL_LOCK},
    {"SCROLLOCK", DUCKY_KEY_TOKEN_KEY, KEY_SCROLL_LOCK},
    {"SCROLL_LOCK", DUCKY_KEY_TOKEN_KEY, KEY_SCROLL_LOCK},
    {"PAUSE", DUCKY_KEY_TOKEN_KEY, KEY_PAUSE},
    {"BREAK", DUCKY_KEY_TOKEN_KEY, KEY_PAUSE},
    {"INSERT", DUCKY_KEY_TOKEN_KEY, KEY_INSERT},
    {"HOME", DUCKY_KEY_TOKEN_KEY, KEY_HOME},
    {"PAGEUP", DUCKY_KEY_TOKEN_KEY, KEY_PAGE_UP},
    {"PAGE_UP", DUCKY_KEY_TOKEN_KEY, KEY_PAGE_UP},
    {"DELETE", DUCKY_KEY_TOKEN_KEY, KEY_DELETE},
    {"DEL", DUCKY_KEY_TOKEN_KEY, KEY_DELETE},
    {"END", DUCKY_KEY_TOKEN_KEY, KEY_END},
    {"PAGEDOWN", DUCKY_KEY_TOKEN_KEY, KEY_PAGE_DOWN},
    {"PAGE_DOWN", DUCKY_KEY_TOKEN_KEY, KEY_PAGE_DOWN},
    {"RIGHT", DUCKY_KEY_TOKEN_KEY, KEY_RIGHT},
    {"RIGHTARROW", DUCKY_KEY_TOKEN_KEY, KEY_RIGHT},
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
    {"NUMLOCK", DUCKY_KEY_TOKEN_KEY, KEY_NUM_LOCK},
    {"NUM_LOCK", DUCKY_KEY_TOKEN_KEY, KEY_NUM_LOCK},
    {"MENU", DUCKY_KEY_TOKEN_KEY, KEY_APPLICATION},
    {"APP", DUCKY_KEY_TOKEN_KEY, KEY_APPLICATION},
    {"APPLICATION", DUCKY_KEY_TOKEN_KEY, KEY_APPLICATION},
    {"POWER", DUCKY_KEY_TOKEN_KEY, KEY_POWER},
    {"KP_SLASH", DUCKY_KEY_TOKEN_KEY, KEY_KEYPAD_DIVIDE},
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
    {"MEDIA_PLAY_PAUSE", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_PLAY_PAUSE},
    {"MEDIA_NEXT", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_SCAN_NEXT},
    {"MEDIA_PREVIOUS", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_SCAN_PREVIOUS},
    {"MEDIA_PREV", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_SCAN_PREVIOUS},
    {"MEDIA_STOP", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_STOP},
    {"MEDIA_EJECT", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_EJECT},
    {"MEDIA_MUTE", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_MUTE},
    {"VOLUME_MUTE", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_MUTE},
    {"MEDIA_VOLUME_UP", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_VOLUME_UP},
    {"VOLUME_UP", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_VOLUME_UP},
    {"MEDIA_VOLUME_DOWN", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_VOLUME_DOWN},
    {"VOLUME_DOWN", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_VOLUME_DOWN},
    {"BRIGHTNESS_UP", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_BRIGHTNESS_UP},
    {"BRIGHTNESS_DOWN", DUCKY_KEY_TOKEN_CONSUMER, DUCKY_CONSUMER_BRIGHTNESS_DOWN},
    {"SYSTEM_POWER", DUCKY_KEY_TOKEN_SYSTEM, DUCKY_SYSTEM_POWER_DOWN},
    {"SYSTEM_SLEEP", DUCKY_KEY_TOKEN_SYSTEM, DUCKY_SYSTEM_SLEEP},
    {"SYSTEM_WAKE", DUCKY_KEY_TOKEN_SYSTEM, DUCKY_SYSTEM_WAKE},
};

static bool equal_name(const char *left, size_t left_length, const char *right)
{
    size_t right_length = strlen(right);
    if (left_length != right_length) {
        return false;
    }
    for (size_t i = 0; i < left_length; ++i) {
        if (toupper((unsigned char)left[i]) != (unsigned char)right[i]) {
            return false;
        }
    }
    return true;
}

bool ducky_ascii_to_key(char character, uint8_t *keycode, uint8_t *modifiers)
{
    if (keycode == NULL || modifiers == NULL) {
        return false;
    }
    *modifiers = 0;
    if (character >= 'a' && character <= 'z') {
        *keycode = (uint8_t)(KEY_A + character - 'a');
        return true;
    }
    if (character >= 'A' && character <= 'Z') {
        *keycode = (uint8_t)(KEY_A + character - 'A');
        *modifiers = DUCKY_MOD_LEFT_SHIFT;
        return true;
    }
    if (character >= '1' && character <= '9') {
        *keycode = (uint8_t)(KEY_1 + character - '1');
        return true;
    }
    if (character == '0') {
        *keycode = KEY_1 + 9;
        return true;
    }

    struct ascii_entry {
        char character;
        uint8_t key;
        bool shift;
    };
    static const struct ascii_entry entries[] = {
        {'\n', KEY_ENTER, false}, {'\r', KEY_ENTER, false}, {'\t', KEY_TAB, false},
        {' ', KEY_SPACE, false}, {'-', KEY_MINUS, false}, {'_', KEY_MINUS, true},
        {'=', KEY_EQUAL, false}, {'+', KEY_EQUAL, true}, {'[', KEY_LEFT_BRACKET, false},
        {'{', KEY_LEFT_BRACKET, true}, {']', KEY_RIGHT_BRACKET, false},
        {'}', KEY_RIGHT_BRACKET, true}, {'\\', KEY_BACKSLASH, false},
        {'|', KEY_BACKSLASH, true}, {';', KEY_SEMICOLON, false},
        {':', KEY_SEMICOLON, true}, {'\'', KEY_APOSTROPHE, false},
        {'"', KEY_APOSTROPHE, true}, {'`', KEY_GRAVE, false}, {'~', KEY_GRAVE, true},
        {',', KEY_COMMA, false}, {'<', KEY_COMMA, true}, {'.', KEY_PERIOD, false},
        {'>', KEY_PERIOD, true}, {'/', KEY_SLASH, false}, {'?', KEY_SLASH, true},
        {'!', KEY_1, true}, {'@', KEY_1 + 1, true}, {'#', KEY_1 + 2, true},
        {'$', KEY_1 + 3, true}, {'%', KEY_1 + 4, true}, {'^', KEY_1 + 5, true},
        {'&', KEY_1 + 6, true}, {'*', KEY_1 + 7, true}, {'(', KEY_1 + 8, true},
        {')', KEY_1 + 9, true},
    };
    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); ++i) {
        if (entries[i].character == character) {
            *keycode = entries[i].key;
            *modifiers = entries[i].shift ? DUCKY_MOD_LEFT_SHIFT : 0;
            return true;
        }
    }
    return false;
}

ducky_key_token_t ducky_lookup_key(const char *name, size_t length)
{
    ducky_key_token_t result = {0};
    if (name == NULL || length == 0) {
        return result;
    }
    if (length == 1) {
        uint8_t key;
        uint8_t modifiers;
        if (ducky_ascii_to_key(name[0], &key, &modifiers)) {
            result.kind = DUCKY_KEY_TOKEN_KEY;
            result.value = key;
            result.implied_modifiers = modifiers;
            return result;
        }
    }
    if (length >= 2 && length <= 3 && toupper((unsigned char)name[0]) == 'F') {
        unsigned number = 0;
        for (size_t i = 1; i < length; ++i) {
            if (!isdigit((unsigned char)name[i])) {
                number = 0;
                break;
            }
            number = number * 10 + (unsigned)(name[i] - '0');
        }
        if (number >= 1 && number <= 24) {
            result.kind = DUCKY_KEY_TOKEN_KEY;
            result.value = number <= 12 ? KEY_F1 + number - 1 : KEY_F13 + number - 13;
            return result;
        }
    }
    bool kp_digit = length == 3 && toupper((unsigned char)name[0]) == 'K' &&
        toupper((unsigned char)name[1]) == 'P' && isdigit((unsigned char)name[2]);
    bool kpad_digit = length == 6 && toupper((unsigned char)name[0]) == 'K' &&
        toupper((unsigned char)name[1]) == 'P' &&
        toupper((unsigned char)name[2]) == 'A' &&
        toupper((unsigned char)name[3]) == 'D' && name[4] == '_' &&
        isdigit((unsigned char)name[5]);
    if (kp_digit || kpad_digit) {
        unsigned number = (unsigned)(name[kp_digit ? 2 : 5] - '0');
        result.kind = DUCKY_KEY_TOKEN_KEY;
        result.value = number == 0 ? KEY_KEYPAD_0 : KEY_KEYPAD_1 + number - 1;
        return result;
    }
    for (size_t i = 0; i < sizeof(s_named_keys) / sizeof(s_named_keys[0]); ++i) {
        if (equal_name(name, length, s_named_keys[i].name)) {
            result.kind = s_named_keys[i].kind;
            result.value = s_named_keys[i].value;
            return result;
        }
    }
    return result;
}

bool ducky_lookup_mouse_button(const char *name, size_t length, uint8_t *button)
{
    if (button == NULL) {
        return false;
    }
    struct mouse_name {
        const char *name;
        uint8_t value;
    };
    static const struct mouse_name names[] = {
        {"LEFT", DUCKY_MOUSE_LEFT},
        {"RIGHT", DUCKY_MOUSE_RIGHT},
        {"MIDDLE", DUCKY_MOUSE_MIDDLE},
        {"BACK", DUCKY_MOUSE_BACK},
        {"BACKWARD", DUCKY_MOUSE_BACK},
        {"FORWARD", DUCKY_MOUSE_FORWARD},
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (equal_name(name, length, names[i].name)) {
            *button = names[i].value;
            return true;
        }
    }
    return false;
}
