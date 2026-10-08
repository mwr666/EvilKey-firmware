#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compare benchmark RGB565+alpha outputs; make a native-resolution QA board."""
import argparse,json
from pathlib import Path
from PIL import Image,ImageDraw

def image(path):
    data=path.read_bytes();side=round((len(data)//3)**.5);assert len(data)==side*side*3
    rgb=[];alpha=[]
    for i in range(0,len(data),3):
        c=(data[i]<<8)|data[i+1];a=data[i+2];alpha.append(a)
        rgb.append((((c>>11)&31)*255//31*a//255,((c>>5)&63)*255//63*a//255,(c&31)*255//31*a//255))
    out=Image.new('RGB',(side,side));out.putdata(rgb);return out,alpha

def main():
    p=argparse.ArgumentParser();p.add_argument('before',type=Path);p.add_argument('after',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    metrics=[]
    for before in sorted(a.before.glob('*.raw')):
        old,oa=image(before);new,na=image(a.after/before.name);assert old.size==new.size
        delta=sum(abs(x-y) for x,y in zip(oa,na))/(255*len(oa))
        metrics.append({'frame':before.name,'alpha_mean_difference':delta,'occupied_before':sum(x!=0 for x in oa),'occupied_after':sum(x!=0 for x in na)})
    a.output.mkdir(parents=True,exist_ok=True)
    (a.output/'frame-comparison.json').write_text(json.dumps(metrics,indent=2)+'\n')
    board=Image.new('RGB',(960,1120),'#090f13');d=ImageDraw.Draw(board)
    d.text((25,16),'JET GUI PERFORMANCE — ORIGINAL / OPTIMIZED',fill='#4de3c1')
    for col,phase in enumerate((0,64,128,192)):
        d.text((50+col*230,42),f'Phase {phase:03} — before / after',fill='white')
        for row,name in enumerate(('saver','settings','apps')):
            old,_=image(a.before/f'{name}-{phase:03}.raw');new,_=image(a.after/f'{name}-{phase:03}.raw')
            # Nearest-neighbour zoom explicitly exposes edge/detail changes.
            if old.width==120:old=old.resize((200,200),Image.Resampling.NEAREST);new=new.resize((200,200),Image.Resampling.NEAREST)
            old=old.resize((100,100),Image.Resampling.NEAREST);new=new.resize((100,100),Image.Resampling.NEAREST)
            x=25+col*230;y=78+row*340
            d.text((x,y-18),name,fill='#8fa4ae');board.paste(old,(x,y));board.paste(new,(x+108,y))
            # Full-size optimized output below each pair.
            native,_=image(a.after/f'{name}-{phase:03}.raw');board.paste(native,(x+(208-native.width)//2,y+115))
    board.save(a.output/'comparison.png')
    print(json.dumps({'compared_frames':len(metrics),'max_alpha_mean_difference':max(m['alpha_mean_difference'] for m in metrics),'board':str(a.output/'comparison.png')}))
if __name__=='__main__':main()
