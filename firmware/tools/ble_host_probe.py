"""Read actual EvilKey Windows input; no simulated input or firmware changes."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
from pathlib import Path
import struct
import time


def gamepad(seconds, controller):
    class Joy(C.Structure):
        _fields_ = [(n, W.DWORD) for n in
                    ['size', 'flags', 'x', 'y', 'z', 'r', 'u', 'v',
                     'buttons', 'button_number', 'pov', 'reserved1', 'reserved2']]
    dll = C.WinDLL('winmm')
    dll.joyGetPosEx.argtypes = [W.UINT, C.POINTER(Joy)]
    dll.joyGetPosEx.restype = W.UINT
    events, previous = [], {}
    start = time.monotonic()
    print('READY: reading physical gamepad inputs', flush=True)
    while time.monotonic() - start < seconds:
        for ident in [controller]:
            j = Joy(); j.size = C.sizeof(j); j.flags = 255
            if dll.joyGetPosEx(ident, C.byref(j)) != 0:
                continue
            state = {n: getattr(j, n) for n in ['x', 'y', 'z', 'r', 'u', 'v', 'buttons', 'pov']}
            if state != previous.get(ident):
                events.append({'t': round(time.monotonic() - start, 3), 'id': ident, **state})
                previous[ident] = state
        time.sleep(.01)
    return {'mode': 'gamepad', 'seconds': seconds, 'events': events}


def hid_gamepad(seconds, address):
    import hid  # Optional host-only hidapi package.
    identity = address.replace(':', '').lower().encode('ascii')
    devices = [d for d in hid.enumerate() if identity in d['path'].lower()
               and d['usage_page'] == 1 and d['usage'] == 5]
    if len(devices) != 1:
        raise RuntimeError('Expected exactly one gamepad for the specified BLE address')
    handle = hid.device()
    events = []
    handle.open_path(devices[0]['path'])
    start = time.monotonic()
    print('READY: reading physical BLE gamepad HID reports', flush=True)
    try:
        while time.monotonic() - start < seconds:
            report = handle.read(64, 100)
            if report:
                events.append({'t': round(time.monotonic()-start, 3),
                               'report': bytes(report).hex()})
    finally:
        handle.close()
    return {'mode': 'hid-gamepad', 'seconds': seconds,
            'address': address, 'events': events}


def mouse(seconds, address):
    if C.sizeof(C.c_void_p) != 8:
        raise RuntimeError('Raw mouse capture requires 64-bit Python')
    identity = address.replace(':', '').lower()
    user = C.WinDLL('user32', use_last_error=True)
    kernel = C.WinDLL('kernel32', use_last_error=True)
    proc_type = C.WINFUNCTYPE(C.c_ssize_t, W.HWND, W.UINT, W.WPARAM, W.LPARAM)
    class WindowClass(C.Structure):
        _fields_ = [('style', W.UINT), ('proc', proc_type), ('extra', C.c_int),
                    ('window_extra', C.c_int), ('instance', W.HINSTANCE),
                    ('icon', W.HICON), ('cursor', W.HANDLE), ('brush', W.HBRUSH),
                    ('menu', W.LPCWSTR), ('name', W.LPCWSTR)]
    class RawDevice(C.Structure):
        _fields_ = [('page', W.USHORT), ('usage', W.USHORT), ('flags', W.DWORD), ('window', W.HWND)]
    user.DefWindowProcW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
    user.DefWindowProcW.restype = C.c_ssize_t
    user.GetRawInputData.argtypes = [W.HANDLE, W.UINT, W.LPVOID, C.POINTER(W.UINT), W.UINT]
    user.GetRawInputDeviceInfoW.argtypes = [W.HANDLE, W.UINT, W.LPVOID, C.POINTER(W.UINT)]
    user.RegisterClassW.argtypes = [C.POINTER(WindowClass)]
    user.CreateWindowExW.argtypes = [W.DWORD, W.LPCWSTR, W.LPCWSTR, W.DWORD,
                                    C.c_int, C.c_int, C.c_int, C.c_int, W.HWND,
                                    W.HMENU, W.HINSTANCE, W.LPVOID]
    user.CreateWindowExW.restype = W.HWND
    user.RegisterRawInputDevices.argtypes = [C.POINTER(RawDevice), W.UINT, W.UINT]
    user.PeekMessageW.argtypes = [C.POINTER(W.MSG), W.HWND, W.UINT, W.UINT, W.UINT]
    user.DispatchMessageW.argtypes = [C.POINTER(W.MSG)]
    user.DispatchMessageW.restype = C.c_ssize_t
    user.DestroyWindow.argtypes = [W.HWND]
    user.UnregisterClassW.argtypes = [W.LPCWSTR, W.HINSTANCE]
    kernel.GetModuleHandleW.argtypes = [W.LPCWSTR]; kernel.GetModuleHandleW.restype = W.HINSTANCE
    events, names = [], {}
    start = time.monotonic()

    @proc_type
    def callback(hwnd, message, wp, lp):
        if message == 0xFF:  # WM_INPUT
            size = W.UINT()
            user.GetRawInputData(lp, 0x10000003, None, C.byref(size), 24)
            buf = C.create_string_buffer(size.value)
            if user.GetRawInputData(lp, 0x10000003, buf, C.byref(size), 24) != 0xFFFFFFFF:
                raw = buf.raw
                kind, _, handle = struct.unpack_from('<IIQ', raw)
                if handle not in names:
                    length = W.UINT()
                    user.GetRawInputDeviceInfoW(handle, 0x20000007, None, C.byref(length))
                    name = C.create_unicode_buffer(length.value + 1)
                    user.GetRawInputDeviceInfoW(handle, 0x20000007, name, C.byref(length))
                    names[handle] = name.value
                name = names[handle].lower()
                # Ignore the owner's other mouse/keyboard input completely.
                if kind == 0 and identity in name:
                    buttons, wheel = struct.unpack_from('<Hh', raw, 28)
                    dx, dy = struct.unpack_from('<ii', raw, 36)
                    events.append({'t': round(time.monotonic()-start, 3),
                                   'dx': dx, 'dy': dy, 'buttons': buttons,
                                   'wheel': wheel if buttons & 0xC00 else 0})
        return user.DefWindowProcW(hwnd, message, wp, lp)

    instance = kernel.GetModuleHandleW(None)
    name = 'EvilKeyReadOnlyRawInputProbe'
    wc = WindowClass(); wc.proc = callback; wc.instance = instance; wc.name = name
    if not user.RegisterClassW(C.byref(wc)): raise C.WinError(C.get_last_error())
    hwnd = user.CreateWindowExW(0, name, name, 0, 0, 0, 0, 0, W.HWND(-3), None, instance, None)
    if not hwnd: raise C.WinError(C.get_last_error())
    device = RawDevice(1, 2, 0x100, hwnd)  # Background input; no suppression.
    if not user.RegisterRawInputDevices(C.byref(device), 1, C.sizeof(device)):
        raise C.WinError(C.get_last_error())
    print('READY: reading only the specified BLE mouse events', flush=True)
    try:
        msg = W.MSG()
        while time.monotonic() - start < seconds:
            while user.PeekMessageW(C.byref(msg), None, 0, 0, 1):
                user.DispatchMessageW(C.byref(msg))
            time.sleep(.005)
    finally:
        remove = RawDevice(1, 2, 1, None)
        user.RegisterRawInputDevices(C.byref(remove), 1, C.sizeof(remove))
        user.DestroyWindow(hwnd); user.UnregisterClassW(name, instance)
    return {'mode': 'mouse', 'seconds': seconds, 'address': address, 'events': events}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['gamepad', 'hid-gamepad', 'mouse'])
    p.add_argument('--address', help='Exact BLE address required for HID and mouse modes')
    p.add_argument('--controller', type=int, choices=range(16), default=0,
                   help='WinMM joystick ID, verified separately against the paired device')
    p.add_argument('--seconds', type=int, default=60)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if args.seconds <= 0: p.error('--seconds must be positive')
    if args.mode != 'gamepad':
        if not args.address: p.error('--address is required')
        identity = args.address.replace(':', '')
        if len(identity) != 12 or any(c not in '0123456789abcdefABCDEF' for c in identity):
            p.error('--address must be a 48-bit BLE address')
    if args.mode == 'hid-gamepad':
        result = hid_gamepad(args.seconds, args.address)
    else:
        result = gamepad(args.seconds,args.controller) if args.mode == 'gamepad' else mouse(args.seconds,args.address)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'mode': args.mode, 'events': len(result['events']), 'output': str(args.output)}))
