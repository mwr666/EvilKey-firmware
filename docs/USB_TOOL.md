# USB Tool

USB Tool is a programmable HID role with a keyboard, mouse and optional
microSD storage. Its default USB identity is `FEFF:FCFB`. During USB enumeration
it is mutually exclusive with FIDO and Manager Drive.

## Run a script

1. Review the payload and save work on the connected computer.
2. Select USB Tool and a script on the device.
3. Press **RUN** locally. Scripts never run at boot, enumeration or card mounting.

Use it on systems you own or are authorized to test. Scripts can type commands
into the host, drive keyboard/mouse interactions, transfer files and collect
data accessible to that host session. Keystroke Reflection provides a return
channel when mass storage is unavailable. Host permissions and defenses still
apply; support for scripting does not guarantee a bypass.

## Examples and layouts

The Windows `hello_world.duck` example minimizes windows, opens Notepad,
creates a document and types a harmless three-line message.
[The real USB Tool Short](https://youtube.com/shorts/k0a0o6s1Ayg) shows this HID
test, not file transfer or data collection. Examples are a
[separate component](https://github.com/mwr666/EvilKey-examples/blob/main/microSD_EVILKEY_EXAMPLES/README.md).

The built-in layout selector offers `US`, `PL Programmer`, `DE`, `FR` and `ES`.
It maps implemented printable characters; it is not general UTF-8 typing.
The language-code setting uses the pinned Hak5 language adapter separately.

## Results

Captured values and feedback go to `loot.bin`. The adjacent `loot.idx` identifies
segment kinds/offsets and a SHA-256 digest. Manager's **USB Tool data** tab
reads these files offline and exports CSV; see [Manager](https://github.com/mwr666/EvilKey-Manager/blob/main/manager/README.md).

## Returning from storage to HID

A read-only session may switch after its payload finishes and storage is idle.
After host writes, firmware waits for cache synchronization or host eject
before detaching, to avoid truncating card data.
