#!/usr/bin/env python3
"""Set/change the genuine FIDO ClientPIN on ONE attached token.
PIN entry here is ON THE COMPUTER. Normal built-in-UV entry is on the panel.
Never accepts a PIN on the command line, never resets/erases a token, no retries.
"""
import argparse
from getpass import getpass
import sys

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('set','change'))
    args=parser.parse_args()
    try:
        from fido2.hid import CtapHidDevice
        from fido2.ctap2 import Ctap2
        from fido2.ctap2.pin import ClientPin
    except ImportError:
        print('Install: python -m pip install "fido2>=2.0,<3.0"',file=sys.stderr);return 2
    devices=list(CtapHidDevice.list_devices())
    try:
        if len(devices)!=1:
            print(f'Expected exactly ONE FIDO token, found {len(devices)}. Nothing changed.',file=sys.stderr);return 2
        dev=devices[0];desc=dev.descriptor
        ctap=Ctap2(dev);client=ClientPin(ctap)
        configured=ctap.info.options.get('clientPin')
        print(f'USB: {desc.vid:04x}:{desc.pid:04x}; PIN configured: {configured}')
        if configured is None or (args.action=='set' and configured) or (args.action=='change' and not configured):
            print('Action does not match ClientPIN state; nothing changed.',file=sys.stderr);return 2
        if input('Confirm this is your TEST token. Type '+args.action.upper()+': ')!=args.action.upper():
            print('Cancelled.');return 0
        if args.action=='change':
            print('PIN retries:',client.get_pin_retries())
        old=getpass('CURRENT FIDO PIN (computer): ') if args.action=='change' else ''
        new=getpass('NEW numeric FIDO PIN, 4..63 digits (6+ recommended): ')
        repeat=getpass('Repeat NEW PIN: ')
        if new!=repeat or not 4<=len(new)<=63 or not all('0'<=x<='9' for x in new):
            print('PINs differ or are outside the numeric keypad range. Nothing changed.',file=sys.stderr);return 2
        if args.action=='set':client.set_pin(new)
        else:client.change_pin(old,new)
        print('ClientPIN operation succeeded. Unplug/reconnect, then test panel UV.')
        # Python cannot guarantee wiping immutable strings from process memory.
        # No PIN is printed, saved to a file or placed on the command line.
        del old,new,repeat
        return 0
    except KeyboardInterrupt:
        print('Interrupted.',file=sys.stderr);return 130
    except Exception as exc:
        print('ClientPIN operation failed:',type(exc).__name__,getattr(exc,'code','no CTAP status'),file=sys.stderr)
        print('No automatic retry was performed. Check retries before trying again.',file=sys.stderr);return 1
    finally:
        for device in devices:device.close()
if __name__=='__main__':raise SystemExit(main())
