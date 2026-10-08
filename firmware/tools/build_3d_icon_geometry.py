#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Derive Jet gear contours from the original Settings icon generator."""
from math import cos, sin, pi, hypot
from pathlib import Path
from build_settings_icon_asset import gear_outline, SIZE, SCALE

ROOT = Path(__file__).resolve().parents[1]


def main():
    curves = gear_outline()
    # Five samples per 2.8px quadratic corner; retain both curve endpoints.
    points = [(x / SCALE - SIZE / 2, y / SCALE - SIZE / 2)
              for i, (x, y) in enumerate(curves) if i % 13 in (0, 3, 6, 9, 12)]
    lines = ['/* SPDX-License-Identifier: AGPL-3.0-or-later',
             ' * Generated from build_settings_icon_asset.py by build_3d_icon_geometry.py. */',
             '#pragma once', 'struct WsGearPoint { float x, y, nx, ny; };',
             f'static constexpr WsGearPoint WS_GEAR_CONTOUR[{len(points)}] = {{']
    for i, (x, y) in enumerate(points):
        previous, following = points[i - 1], points[(i + 1) % len(points)]
        dx, dy = following[0] - previous[0], following[1] - previous[1]
        length = hypot(dx, dy)
        lines.append(f'    {{{x:.6f}f,{y:.6f}f,{dy/length:.6f}f,{-dx/length:.6f}f}},')
    lines.extend(['};', 'struct WsCirclePoint { float x, y; };',
                  'static constexpr WsCirclePoint WS_ICON_CIRCLE[64] = {'])
    for i in range(64):
        a = i * 2 * pi / 64
        lines.append(f'    {{{cos(a):.6f}f,{sin(a):.6f}f}},')
    lines.extend(['};', ''])
    out = ROOT / 'templates/port/ws_gui_3d_geometry.h'
    out.write_text('\n'.join(lines), encoding='utf-8')
    print(f'Generated original eight-tooth contour: {len(points)} vertices, {out}')


if __name__ == '__main__':
    main()
