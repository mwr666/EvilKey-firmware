/* SPDX-License-Identifier: MIT
 * Independent wire declarations: EvilKey Apps ABI v5 native scenes.
 * All integers little-endian. No native pointers or executable models. */
#ifndef EVILKEY_SCENE3D_H
#define EVILKEY_SCENE3D_H
#include <stdint.h>
#define EVILKEY_APP_SCENE3D 7u
#define EVILKEY_3D_MAGIC 0x35443345u /* E3D5 */
#define EVILKEY_3D_MAX_OBJECTS 96u
#define EVILKEY_3D_MAX_MATERIALS 8u
#define EVILKEY_3D_MAX_TRIANGLES 1280u
#define EVILKEY_3D_MAX_WIDTH 280u
#define EVILKEY_3D_MAX_HEIGHT 320u
#define EVILKEY_3D_BOX 1u
#define EVILKEY_3D_BALL 2u /* 32 faces, diameter one before scale */
#define EVILKEY_3D_PLANE 3u /* XZ plane, +Y up */
#define EVILKEY_3D_PYRAMID 4u
#define EVILKEY_3D_ORTHOGRAPHIC 0u
#define EVILKEY_3D_PERSPECTIVE 1u
#define EVILKEY_3D_UNLIT 1u
#define EVILKEY_3D_NONE 0u
#define EVILKEY_3D_OK 1u
#define EVILKEY_3D_TIMEOUT 2u
#define EVILKEY_3D_WORK_LIMIT 3u
#define EVILKEY_3D_NO_MEMORY 4u
/* Q8.8 world coordinates, right handed: X right, Y up, Z toward viewer.
 * camera.span is vertical extent in orthographic projection; fov is degrees.
 * The camera looks at target, world Y is up (near vertical views rejected). */
typedef struct {
    int16_t position[3], target[3];
    uint16_t fov, projection, span, reserved;
} EvilKey3DCamera; /* 20 bytes */
typedef struct { uint16_t rgb565, flags; uint32_t reserved; } EvilKey3DMaterial;
/* Full size Q8.8 (not half size). Euler angles in hundredths of a degree,
 * X then Y then Z. Zero reserved words required. Materials indexed from 0. */
typedef struct {
    uint16_t model, material;
    int16_t position[3], rotation[3];
    uint16_t scale[3], reserved;
    uint32_t reserved2[2];
} EvilKey3DObject; /* 32 bytes */
typedef struct {
    uint32_t magic;
    uint16_t version, object_count, material_count, background;
    uint32_t flags;
    EvilKey3DCamera camera;
    EvilKey3DMaterial materials[EVILKEY_3D_MAX_MATERIALS];
    EvilKey3DObject objects[EVILKEY_3D_MAX_OBJECTS];
} EvilKey3DScene; /* fixed 3172 bytes, unused slots must be zero */
/* SCENE3D: flags=0, viewport x/y/w/h (even size, max 280x320),
 * arg0=guest scene offset, arg1=sizeof(EvilKey3DScene). At most one per call.
 * Follow with 2D HUD commands and PRESENT. ABI5 input.reserved[0..2] report
 * previous render status, elapsed microseconds and submitted triangles.
 * ABI4 keeps these fields zero and rejects SCENE3D. */
#endif
