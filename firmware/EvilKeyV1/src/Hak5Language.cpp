/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "Hak5Language.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

static void set_error(char *out,size_t out_len,const char *msg)
{
    if(!out || out_len==0U)return;
    if(!msg)msg="";
    strncpy(out,msg,out_len-1U);out[out_len-1U]='\0';
}

static const char *skip_ws(const char *p,const char *end)
{
    while(p<end && isspace((unsigned char)*p))++p;
    return p;
}

static int hex_value(char c)
{
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return 10+c-'a';
    if(c>='A'&&c<='F')return 10+c-'A';
    return -1;
}

/* Decode enough JSON string syntax to handle the Hak5 flat language objects.
 * Non-ASCII \u escapes are preserved as a placeholder so they can never be
 * mistaken for one printable ASCII key. */
static bool parse_string(const char **cursor,const char *end,char *out,size_t out_len)
{
    const char *p=*cursor;
    if(p>=end || *p!='\"')return false;
    ++p;size_t used=0U;
    while(p<end) {
        unsigned char c=(unsigned char)*p++;
        if(c=='\"') {
            if(out && out_len)out[used<out_len?used:out_len-1U]='\0';
            *cursor=p;return true;
        }
        if(c=='\\') {
            if(p>=end)return false;
            char esc=*p++;
            switch(esc) {
            case '\"':c='\"';break;case '\\':c='\\';break;case '/':c='/';break;
            case 'b':c='\b';break;case 'f':c='\f';break;case 'n':c='\n';break;
            case 'r':c='\r';break;case 't':c='\t';break;
            case 'u': {
                if((size_t)(end-p)<4U)return false;
                unsigned v=0U;
                for(unsigned i=0;i<4U;++i){int h=hex_value(*p++);if(h<0)return false;v=(v<<4)|(unsigned)h;}
                c=v<=0x7fU?(unsigned char)v:0xffU;
                break;
            }
            default:return false;
            }
        }
        if(out && out_len && used+1U<out_len)out[used]=(char)c;
        ++used;
    }
    return false;
}

static bool parse_hex_byte(const char **cursor,const char *end,uint8_t *out)
{
    const char *p=skip_ws(*cursor,end);unsigned value=0U;unsigned digits=0U;
    if((size_t)(end-p)>=2U && p[0]=='0' && (p[1]=='x'||p[1]=='X'))p+=2;
    while(p<end) {
        int h=hex_value(*p);if(h<0)break;
        value=(value<<4)|(unsigned)h;++digits;++p;
        if(value>0xffU || digits>2U)return false;
    }
    if(digits==0U)return false;
    *out=(uint8_t)value;*cursor=p;return true;
}

static bool parse_triplet(const char *text,uint8_t *mod,uint8_t *key)
{
    if(!text||!mod||!key)return false;
    const char *p=text,*end=text+strlen(text);uint8_t m=0,res=0,k=0;
    if(!parse_hex_byte(&p,end,&m))return false;
    p=skip_ws(p,end);if(p>=end||*p++!=',')return false;
    if(!parse_hex_byte(&p,end,&res))return false;
    p=skip_ws(p,end);if(p>=end||*p++!=',')return false;
    if(!parse_hex_byte(&p,end,&k))return false;
    p=skip_ws(p,end);if(p!=end)return false;
    (void)res;*mod=m;*key=k;return true;
}

bool pf_hak5_parse_language_json(const char *json,size_t json_len,
                                 pf_hak5_key_t out_ascii[95],size_t *mapped_count,
                                 char *error,size_t error_len)
{
    if(mapped_count)*mapped_count=0U;
    set_error(error,error_len,"");
    if(!json||!out_ascii||json_len==0U){set_error(error,error_len,"Invalid language JSON");return false;}
    memset(out_ascii,0,sizeof(pf_hak5_key_t)*95U);
    const char *p=json,*end=json+json_len;p=skip_ws(p,end);
    if(p>=end||*p!='{'){set_error(error,error_len,"Language JSON must be an object");return false;}
    ++p;size_t mapped=0U;
    while(true) {
        p=skip_ws(p,end);if(p>=end){set_error(error,error_len,"Truncated language JSON");return false;}
        if(*p=='}'){++p;break;}
        char name[24]={0},value[40]={0};
        if(!parse_string(&p,end,name,sizeof(name))){set_error(error,error_len,"Invalid language JSON key");return false;}
        p=skip_ws(p,end);if(p>=end||*p++!=':'){set_error(error,error_len,"Missing ':' in language JSON");return false;}
        p=skip_ws(p,end);
        if(p>=end){set_error(error,error_len,"Truncated language JSON value");return false;}
        if(*p=='\"') {
            if(!parse_string(&p,end,value,sizeof(value))){set_error(error,error_len,"Invalid language JSON value");return false;}
            if(name[0] && name[1]=='\0' && (unsigned char)name[0]>=0x20U && (unsigned char)name[0]<=0x7eU) {
                uint8_t mod=0,key=0;
                if(parse_triplet(value,&mod,&key) && key!=0U) {
                    unsigned idx=(unsigned char)name[0]-0x20U;
                    if(!out_ascii[idx].valid)++mapped;
                    out_ascii[idx].modifiers=mod;out_ascii[idx].keycode=key;out_ascii[idx].valid=1U;
                }
            }
        } else {
            /* The official language files use strings for mappings.  Tolerate
             * any future scalar metadata by skipping until comma/object end. */
            bool in_string=false,escaped=false;
            while(p<end) {
                char c=*p;
                if(in_string){if(escaped)escaped=false;else if(c=='\\')escaped=true;else if(c=='\"')in_string=false;++p;continue;}
                if(c=='\"'){in_string=true;++p;continue;}
                if(c==','||c=='}')break;
                ++p;
            }
        }
        p=skip_ws(p,end);
        if(p<end && *p==','){++p;continue;}
        if(p<end && *p=='}'){++p;break;}
        if(p>=end){set_error(error,error_len,"Truncated language JSON");return false;}
        set_error(error,error_len,"Expected ',' in language JSON");return false;
    }
    if(mapped_count)*mapped_count=mapped;
    if(mapped<80U){set_error(error,error_len,"Language JSON has too few ASCII mappings");return false;}
    return true;
}
