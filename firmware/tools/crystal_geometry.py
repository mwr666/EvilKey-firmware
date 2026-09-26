"""Faceted crystal geometry shared by firmware assets and release preview."""
from __future__ import annotations

import math
from PIL import Image, ImageDraw

SCALE = 4
RADIUS = 18.5
HALF_HEIGHT = 34.0
LIGHT = (-0.55, -0.55, 0.75)


def rotate_y(point, theta):
    x, y, z = point
    co, si = math.cos(theta), math.sin(theta)
    return (x * co + z * si, y, -x * si + z * co)


def normal(a, b, c):
    u = tuple(b[i] - a[i] for i in range(3))
    v = tuple(c[i] - a[i] for i in range(3))
    n = (u[1] * v[2] - u[2] * v[1],
         u[2] * v[0] - u[0] * v[2],
         u[0] * v[1] - u[1] * v[0])
    length = math.sqrt(sum(q * q for q in n))
    return tuple(q / length for q in n)


def crystal_layer(theta):
    """Render the approved elongated octahedron with fixed lighting."""
    side = 88
    layer = Image.new("RGBA", (side * SCALE, side * SCALE), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    vertices = [rotate_y(v, theta) for v in (
        (0, -HALF_HEIGHT, 0), (0, HALF_HEIGHT, 0),
        (RADIUS, 0, 0), (0, 0, RADIUS),
        (-RADIUS, 0, 0), (0, 0, -RADIUS),
    )]
    faces = [(0, 2 + i, 2 + ((i + 1) % 4)) for i in range(4)]
    faces += [(1, 2 + ((i + 1) % 4), 2 + i) for i in range(4)]
    visible = []
    for indices in faces:
        a, b, c = (vertices[i] for i in indices)
        n = normal(a, b, c)
        if n[2] <= 0.001:
            continue
        light = max(0.0, sum(n[i] * LIGHT[i] for i in range(3)))
        # Stronger light-to-shadow separation survives RGB565 and remains a
        # neutral icy white crystal against the existing mint mark.
        tone = min(252, round(132 + 130 * light))
        color = (tone, min(255, tone + 5), min(255, tone + 10), 255)
        depth = (a[2] + b[2] + c[2]) / 3
        visible.append((depth, indices, color, light))

    def project(v):
        factor = 1.0 + v[2] / 170.0
        return ((side / 2 + v[0] * factor) * SCALE,
                (side / 2 + v[1] * factor) * SCALE)

    for _, indices, color, light in sorted(visible):
        pts = [project(vertices[i]) for i in indices]
        d.polygon(pts, fill=color)
        edge_tone = min(255, color[0] + 24)
        d.line(pts + pts[:1], fill=(edge_tone, min(255, edge_tone + 4),
                                   min(255, edge_tone + 8), 255), width=SCALE)

    top = project(vertices[0])
    bottom = project(vertices[1])
    front = max(vertices[2:], key=lambda v: v[2])
    mid = project(front)
    highlight = 150 + 90 * max(0.0, front[2] / RADIUS)
    d.line((top, mid, bottom), fill=(255, 255, 255, round(highlight)), width=SCALE)
    return layer.resize((side, side), Image.Resampling.LANCZOS)
