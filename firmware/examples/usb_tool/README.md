# USB Tool example

`hello_world.duck` is a Windows-only HID demonstration physically tested by the project owner. It minimizes open windows, opens the Run dialog, launches Notepad, creates a new document and types three harmless lines. Save your work before running it on your own unlocked computer. It does not read host files or use the network.

Copy the file into `/duckyscripts` on the microSD card using Manager Drive, eject the card safely on the host, and then switch the device to USB Tool. The payload never starts automatically; it runs only after *RUN* is selected on the AMOLED.

Expected Notepad text:

```text
YOU HAVE BEEN HACKED
Relax. This key only opened Notepad.
The only data stolen was your attention.
```
