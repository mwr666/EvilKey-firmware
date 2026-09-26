#pragma once
#include <stdbool.h>
typedef enum {BUTTON_EV_NONE,BUTTON_EV_PRESSED,BUTTON_EV_CANCELLED,BUTTON_EV_TIMEOUT} button_event_t;
extern bool cancel_button;
