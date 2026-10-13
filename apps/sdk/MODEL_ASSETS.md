<!-- SPDX-License-Identifier: MIT -->
# Models from microSD — sdmesh1

All ABI5 applications can use arbitrary static indexed triangle meshes. The
firmware has no game ID checks, model name checks or game geometry. Models may
be exported from an authoring tool or generated programmatically. Bone animation
and textures are not part of this extension; applications animate instances
using their position/rotation/scale and choose up to eight RGB565 materials.

Convert an OBJ with `python mesh.py car.obj car.ekmesh`. Vertices are centered
and uniformly normalized to a longest extent of one unit. Material names become
roles in encounter order. Negative/slashed OBJ indices work. Triangulate concave
polygons in the authoring tool before export; the converter fans convex polygons.
Bounds: 1024vertices/1280triangles/65536bytes per model, 32resources and 1MiB total
embedded plus external data. The existing scene limits and20ms deadline stay.

Resource manifest example (no dimensions for models):

```json
{"assets":[{"id":23,"type":"mesh","file":"car.ekmesh","external":true}]}
```

`pack_ekapp.py --abi 5 ... --assets assets.json` adds the feature bit and copies
the model next to the package in `<app-id>.models/23.ekmesh`. Copy both the
`.ekapp` and its `.models` directory to `/evilkey/apps/`. The package binds each
external model's size and SHA256. Missing or modified files fail before app_init;
update the package reference when intentionally replacing a model. No per-frame
SD access; model data is immutable until the app stops. `external:false` embeds
the same format in the asset payload. Bitmap commands cannot use mesh assets.
`package_app_release.py` includes and verifies referenced external files.

Set scene.version=2 and object.model=`EVILKEY_3D_MESH_ASSET | 23`.
object.material selects role0; object.reserved2[0] contains seven nibbles for
roles1..7 (low-to-high). Every mapped index must be less than material_count.
The upper nibble, reserved2[1] and reserved remain zero. Example palette:

```c
object.material = 2; /* body */
object.reserved2[0] = 1u | (5u<<4) | (3u<<8) | (4u<<12)
                   | (4u<<16) | (4u<<20) | (4u<<24);
```

The fixed scene3172B/object32B layout stays. Builtins1..4 remain optional and
retain zero reserved words. Scene version1 retains all legacy validation.
Package revision5/header offset14 feature bit0=1 selects this extension; ABI4
must use0. Released0.7.5 rejects the feature before starting VM. Install the
matching sdmesh1 firmware build first; a filename/version claim is not sufficient.

Binary `.ekmesh`: little-endian 20B header: `EKMESH1\0` (8B), u16version1,
u16vertices, u16triangles, u16reserved0, u32total_bytes. Vertex entries6B are
signed i16XYZ/32768 in[-.5,.5]. Triangle entries8B are u16a/u16b/u16c,
u8material_role0..7, u8reserved0. Distinct in-range indices required, no trailing
bytes. Geometrically degenerate triangles are skipped safely. Models are data;
the loader does not execute them or grant an application general filesystem access.

## Transparent scene background (sdmesh1-r4)

With scene.version2,set scene.flags=EVILKEY_3D_TRANSPARENT_BACKGROUND.
Draw any2D underlay before Scene3D:depth0 retains it,depth>0 copies geometry,
including black RGB565. Opaque flags0 remains exact;version1requires flags0.
Unknown flags reject the whole command list before effects;command.flags stays0.
Declare required_features bit1=2 when publishing; combine with meshbit0 to3.
Oldr3 rejects2/3 before app_init. Package tool --required-features2 automatically
ORs meshbit0 if models are present. ABI4 requires0;wire/scene layout unchanged.
Timeout rollback uses last committed scene mode;first transparent timeout keeps
the underlay untouched. No textures,bones,game-specific branches or frame SD reads.
