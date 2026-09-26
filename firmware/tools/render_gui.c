/* SPDX-License-Identifier: AGPL-3.0-or-later
 * HOST ONLY: render the actual firmware UI to PPM. No device connection.
 */
#include "ws_ui.h"
#include "ws_pins.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv) {
    if(argc<3 || argc>5) {fprintf(stderr,"Usage: render_gui STATE OUTPUT.ppm [PIN_LENGTH] [PRESS]\n");return 2;}
    int state=atoi(argv[1]);
    if(state<0 || state>WS_UI_INPUT_ERROR)return 2;
    ws_ui_snapshot_t v={.state=(ws_ui_state_t)state,.epoch=1,.seconds_left=state==WS_UI_PIN?117:28,
        .touch_enabled=true,.touch_available=true,.boot_allowed=false,
        .pin_length=argc>=4?(unsigned)atoi(argv[3]):6,.uv_retries=8,.pin_permissions=3,
        .animation_phase=4,.pressed_action=argc>=5?(uint8_t)atoi(argv[4]):0};
    uint16_t strip[WS_LCD_WIDTH*WS_LCD_STRIP_ROWS];
    FILE *out=fopen(argv[2],"wb");if(!out){perror("fopen");return 1;}
    fprintf(out,"P6\n%d %d\n255\n",WS_LCD_WIDTH,WS_LCD_HEIGHT);
    for(int y=0;y<WS_LCD_HEIGHT;y+=WS_LCD_STRIP_ROWS) {
        int rows=WS_LCD_HEIGHT-y;if(rows>WS_LCD_STRIP_ROWS)rows=WS_LCD_STRIP_ROWS;
        ws_ui_render_strip(strip,y,rows,&v);
        for(int i=0;i<WS_LCD_WIDTH*rows;++i) {
            uint16_t p=strip[i];
            unsigned char rgb[3]={(unsigned char)(((p>>11)&31)*255/31),
              (unsigned char)(((p>>5)&63)*255/63),(unsigned char)((p&31)*255/31)};
            if(fwrite(rgb,1,3,out)!=3){fclose(out);return 1;}
        }
    }
    return fclose(out)==0?0:1;
}
