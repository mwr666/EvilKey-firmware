#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compare frontal Jet icons with real original LVGL rasterization."""
from pathlib import Path
import re
from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont, ImageStat

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / 'firmware/build'
OUT = ROOT / 'docs/design/3d-gui'
NAMES = ['Settings', 'Loader', 'Touch', 'Confirm', 'Cancel', 'Clock', 'Lock', 'Moon', 'Warning', 'USB', 'Apps']


def main():
    from build_settings_icon_asset import render
    original_source=(ROOT/'firmware/templates/port/ws_settings_icon_asset.h').read_text(encoding='utf-8')
    array=re.search(r'ws_settings_gear_map\[\d+\]\s*=\s*\{(.*?)\}',original_source,re.S).group(1)
    assert render().tobytes()==bytes(map(int,re.findall(r'\d+',array))), 'Original Settings asset changed'
    OUT.mkdir(parents=True, exist_ok=True)
    pairs = [(Image.open(BUILD/'classic-gear.ppm').crop((80,76,200,196)),
              Image.open(BUILD/'jet-reference-gear.ppm'))]
    for i in range(1,10):
        pairs.append((Image.open(BUILD/f'classic-icon-{i}.ppm').crop((105,105,175,175)),
                      Image.open(BUILD/f'jet-reference-{i}.ppm').crop((5,5,75,75))))
    pairs.append((Image.open(BUILD/'classic-apps.ppm').crop((80,76,200,196)), Image.open(BUILD/'jet-reference-apps.ppm')))
    font = ImageFont.truetype('C:/Windows/Fonts/arial.ttf', 16)
    sheet = Image.new('RGB', (1160, 652), '#080e10')
    draw = ImageDraw.Draw(sheet)
    for index, (original, jet) in enumerate(pairs):
        # A two-pixel tolerance covers subpixel sampling, rounded line caps
        # and thin extrusion sides. Coverage is tested in both directions.
        old = original.getchannel('G').point(lambda p:255 if p>10 else 0)
        new = jet.getchannel('G').point(lambda p:255 if p>10 else 0)
        missed_old = ImageChops.subtract(old,new.filter(ImageFilter.MaxFilter(5)))
        missed_new = ImageChops.subtract(new,old.filter(ImageFilter.MaxFilter(5)))
        misses = (sum(missed_old.histogram()[1:])+sum(missed_new.histogram()[1:]))
        foreground = sum(old.histogram()[1:])+sum(new.histogram()[1:])
        error = sum(ImageStat.Stat(ImageChops.difference(original,jet)).mean)/3
        print(f'{NAMES[index]}: within-2px coverage {(1-misses/max(1,foreground))*100:.2f}%, RGB mean error {error:.2f}/255')
        assert misses/max(1,foreground)<=.01, f'Changed silhouette: {NAMES[index]}'
        assert error<=6, f'Changed tonal style: {NAMES[index]}'
        x,y = 16+(index%5)*230,18+(index//5)*212
        draw.text((x,y),NAMES[index],font=font,fill='#f7f9fa')
        for col,image in enumerate((original,jet)):
            panel = Image.new('RGB', (104,136), '#000000')
            # Native dimensions: hero icons are unchanged at 70px; Settings
            # alone uses a reduced display preview to fit this overview.
            if index in (0,10):image=image.resize((96,96),Image.Resampling.LANCZOS)
            panel.paste(image,((104-image.width)//2,(136-image.height)//2))
            sheet.paste(panel,(x+col*108,y+27))
            draw.text((x+col*108,y+170), 'Original' if col==0 else 'Jet',font=font,fill='#a7bec4')
    sheet.save(OUT/'icons-original-vs-jet.png')
    original,jet=pairs[0]
    gear=Image.new('RGB',(420,220),'#080e10');d=ImageDraw.Draw(gear)
    for x,image,caption in ((40,original,'Original LVGL'),(250,jet,'Jet · frontal pose')):
        gear.paste(image,(x,65));d.text((x-12,25),caption,font=font,fill='#f7f9fa')
    gear.save(OUT/'settings-original-vs-jet.png')
    original,jet=pairs[10]
    apps=Image.new('RGB',(420,220),'#080e10');d=ImageDraw.Draw(apps)
    for x,image,caption in ((40,original,'Original LVGL'),(250,jet,'Jet - frontal pose')):
        apps.paste(image,(x,65));d.text((x-12,25),caption,font=font,fill='#f7f9fa')
    apps.save(OUT/'apps-original-vs-jet.png')
    print('PASS: original Settings A8 asset unchanged; all eleven designs preserve geometry and tonal style')


if __name__=='__main__':
    main()
