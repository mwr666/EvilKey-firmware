/* SPDX-License-Identifier: AGPL-3.0-or-later */
#pragma once
/* Firmware overrides come from FidoConfig.h via pf_build_config.h.
 * Defaults also make the exact renderer buildable on a host without Arduino. */
#ifndef FIDO_V1_GUI_ACCENT_RGB
#define FIDO_V1_GUI_ACCENT_RGB 0x4DE3C1UL
#endif
#ifndef FIDO_V1_GUI_ANIMATION
#define FIDO_V1_GUI_ANIMATION 1
#endif
#ifndef FIDO_V1_GUI_3D
#define FIDO_V1_GUI_3D 1
#endif
#if FIDO_V1_GUI_ACCENT_RGB < 0 || FIDO_V1_GUI_ACCENT_RGB > 0xFFFFFFUL
#error "FIDO_V1_GUI_ACCENT_RGB must be a 24-bit RGB value"
#endif
#if FIDO_V1_GUI_ANIMATION != 0 && FIDO_V1_GUI_ANIMATION != 1
#error "FIDO_V1_GUI_ANIMATION must be 0 or 1"
#endif
#if FIDO_V1_GUI_3D != 0 && FIDO_V1_GUI_3D != 1
#error "FIDO_V1_GUI_3D must be 0 or 1"
#endif
