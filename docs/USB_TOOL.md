# USB Tool

USB Tool is an explicitly selected USB role with a keyboard, mouse, and optional microSD storage. Its USB identity is `FEFF:FCFB` by default. It is mutually exclusive with FIDO and Manager Drive during USB enumeration.

It is a programmable HID scripting mode, not an automatic action on connection. Scripts can drive keyboard and mouse interactions, move files or collect data accessible to the connected host session, and save results on microSD. Keystroke Reflection provides a return channel when a mass-storage drive is unavailable. Host permissions and defenses still apply; these capabilities are not a promise to bypass them. Use this role only on systems you own or are authorized to test.

Payloads never run during boot, USB enumeration, or card mounting. Select a script on the device and press *RUN* to start it locally. Review scripts before running them because they can type commands into the host. The included Windows-only `hello_world.duck` example minimizes windows, opens Notepad, creates a new document and types a harmless three-line message. Save your work before using it.

[Watch the real USB Tool Short](https://youtube.com/shorts/k0a0o6s1Ayg). It documents this harmless HID test on the owner's Windows computer; it does not show file transfer, data collection or a defense bypass.

The built-in keyboard layout selector provides `US`, `PL Programmer`, `DE`, `FR`, or `ES`. It covers the implemented printable layout mapping and does not provide general UTF-8 typing. The language-code setting supports the pinned Hak5 language adapter separately.

Captured values and feedback are stored in `loot.bin`. A neighboring `loot.idx` records segment kinds, offsets, and a SHA-256 digest. The Manager *USB Tool data* tab can inspect these files offline and export CSV.

For STORAGE-to-HID return, read-only sessions may switch after the payload finishes and storage is idle. After host writes, firmware waits for cache synchronization or host eject before detaching to avoid truncating the card data.
