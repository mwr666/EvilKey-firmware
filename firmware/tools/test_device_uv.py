#!/usr/bin/env python3
"""Local-UV probe via FIDO HID. Does not set/reset PIN, create/delete credentials,
flash firmware or program eFuses. A WRONG panel PIN consumes a UV retry.
Run on Windows in an elevated terminal with only the intended token attached.
"""
import argparse
import importlib.metadata
import sys
from threading import Event, Timer

def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run',action='store_true',help='Request one token; otherwise read information only')
    ap.add_argument('--protocol',type=int,choices=(1,2),default=2)
    args=ap.parse_args()
    try:
        from fido2.hid import CtapHidDevice
        from fido2.ctap2 import Ctap2
        from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
    except ImportError:
        print('Install: python -m pip install "fido2>=2.0,<3.0"',file=sys.stderr)
        return 2
    devices=list(CtapHidDevice.list_devices())
    try:
        if len(devices)!=1:
            print(f'Expected exactly ONE FIDO HID token; found {len(devices)}. No PIN operation performed.',file=sys.stderr)
            return 2
        dev=devices[0]
        desc=dev.descriptor
        print(f'USB: {desc.vid:04x}:{desc.pid:04x}')
        print('python-fido2:',importlib.metadata.version('fido2'))
        ctap=Ctap2(dev)
        print('Versions:',ctap.info.versions)
        print('ClientPIN configured:',ctap.info.options.get('clientPin'))
        print('Built-in UV ready:',ctap.info.options.get('uv'))
        print('UV token supported:',ctap.info.options.get('pinUvAuthToken'))
        if not args.run:
            print('Read-only probe complete. Use --run to request PIN entry on the panel.')
            return 0
        if not ctap.info.options.get('uv') or not ctap.info.options.get('pinUvAuthToken'):
            print('UV is not ready. Check prepared firmware and existing PIN setup.',file=sys.stderr)
            return 2
        if args.protocol not in ctap.info.pin_uv_protocols:
            print('Selected PIN/UV protocol not advertised.',file=sys.stderr);return 2
        if input('This will request your PIN ON THE PANEL. Wrong entry spends a retry. Type TEST: ')!='TEST':
            print('Cancelled before requesting PIN.');return 0
        proto=PinProtocolV1() if args.protocol==1 else PinProtocolV2()
        client=ClientPin(ctap,proto)
        print('UV retries before request:',client.get_uv_retries())
        event=Event();timer=Timer(130,event.set);timer.daemon=True;timer.start()
        def keepalive(status):
            print('Device waiting for touch/PIN' if int(status)==2 else 'Device processing')
        try:
            token=client.get_uv_token(ClientPin.PERMISSION.CREDENTIAL_MGMT,
                                      event=event,on_keepalive=keepalive)
            # Do not log, save, export or use this authorization token.
            print('Received an encrypted-exchange UV token; decoded length:',len(token))
            del token
            print('Token contents were not printed. No credential-management command was sent.')
            print('Unplug the device after the probe to invalidate the temporary session.')
        finally:
            event.set();timer.cancel()
        return 0
    except KeyboardInterrupt:
        print('Interrupted; unplug the device to end its temporary session.',file=sys.stderr);return 130
    except Exception as exc:
        # No input PIN, raw response or token is placed in the diagnostic output.
        print('UV probe failed:',type(exc).__name__,getattr(exc,'code','no CTAP status'),file=sys.stderr);return 1
    finally:
        for d in devices:d.close()
if __name__=='__main__':raise SystemExit(main())
