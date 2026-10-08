# On-device FIDO2 PIN entry

EvilKey's 280 × 456 touch AMOLED can collect a configured **numeric FIDO PIN on the key
itself** for built-in user verification (UV). This is a functional authenticator input
path, not a visual keypad that forwards keystrokes to the computer.

## What the user sees

The modal **Enter PIN** page has a 3 × 4 keypad, Backspace, Verify and Cancel. It
displays masked PIN dots, digit count, remaining attempts and a timeout. Verify becomes
available after at least four digits. The FIDO request determines the short scope label,
such as **Sign in** or **Create credential**. The screen does not put plaintext digits
in its display snapshot.

## Which FIDO2 path is used

The firmware advertises both `uv` (built-in verification when ready) and `clientPin`. A
compatible client may request built-in UV. EvilKey then reads the PIN locally, checks it
against its existing FIDO PIN verifier and retry budget, and authorizes the requested
operation or a permission-bound PIN/UV token. On this path, the PIN is **entered on the
authenticator**, so there is no computer-side PIN typing and no plaintext PIN sent over
USB.

Standard ClientPIN remains supported for PIN setup and client compatibility. The
operating system or browser chooses the protocol flow; EvilKey cannot promise that every
sign-in will show its touch keypad. The local keypad accepts numeric PINs. An
alphanumeric host-configured PIN does not fit this local entry path.

A separate Settings action also uses the same keypad to authorize a **READ ONLY →
READ/WRITE** transition for the Manager Drive. That local configuration check does not
create a reusable FIDO UV token.

## Security boundary and validation

A wrong local PIN attempt consumes the retry budget. The firmware clears temporary
plaintext and verifier buffers after checking. On-device entry narrows exposure to a
connected computer's keyboard/PIN prompt for compatible built-in UV requests; it is not
a guarantee against compromised device firmware, physical access or every host-side
attack. EvilKey makes no FIDO certification claim.

The source paths are `firmware/templates/port/ws_lvgl.c`, `ws_pinpad.c`, `ws_board.c`
and `firmware/templates/local_uv_engine.inc`. FIDO return and existing credentials are
included in release acceptance. A dedicated built-in UV keypad test is separate from
that check; use a disposable credential without exposing the PIN.

The [FIDO CTAP
specification](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)
distinguishes built-in UV from ClientPIN.
