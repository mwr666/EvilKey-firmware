/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
/* One landscape layout shared by rendering and touch hit testing (456 x 280). */
typedef struct { int x,y,w,h; } WsPadRect;
typedef enum { WS_PAD_A,WS_PAD_B,WS_PAD_X,WS_PAD_Y,WS_PAD_LB,WS_PAD_RB,
    WS_PAD_SELECT,WS_PAD_START,WS_PAD_LT,WS_PAD_RT,WS_PAD_IMU,WS_PAD_CENTER,
    WS_PAD_SETTINGS,WS_PAD_EXIT_AREA,WS_PAD_AREA_COUNT } WsPadArea;
static const WsPadRect ws_pad_layout[WS_PAD_AREA_COUNT]={
    {188,190,80,76},{268,110,80,76},{108,110,80,76},{188,30,80,76},
    {8,30,92,55},{356,93,92,55},{356,166,92,46},{8,166,92,46},
    {8,93,92,55},{356,30,92,55},{196,116,64,64},{8,220,92,46},
    {356,220,44,46},{404,220,44,46}
};
typedef enum {
    WS_PAD_UI_NONE=0, WS_PAD_UI_CENTER, WS_PAD_UI_IMU, WS_PAD_UI_SETTINGS,
    WS_PAD_UI_EXIT, WS_PAD_UI_MODE, WS_PAD_UI_ROTATE, WS_PAD_UI_CALIBRATE,
    WS_PAD_UI_PAIR, WS_PAD_UI_FORGET, WS_PAD_UI_MINUS, WS_PAD_UI_PLUS,
    WS_PAD_UI_BACK, WS_PAD_UI_YES, WS_PAD_UI_NO
} WsPadUiControl;
/* Absolute landscape coordinates shared by menu rendering and input. */
static const WsPadRect ws_pad_menu_layout[8]={
    {48,64,170,36},{238,64,170,36},{48,108,360,36},
    {48,152,170,36},{238,152,170,36},{48,196,76,36},
    {142,196,76,36},{238,196,170,36}
};
static const WsPadRect ws_pad_confirm_layout[2]={{90,168,126,54},{240,168,126,54}};
