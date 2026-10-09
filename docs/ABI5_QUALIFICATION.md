# ABI v5 qualification

Firmware **0.7.5** supports ABI4 apps and ABI5 native scenes. Package revision
5 and the corner exit profile apply to both. Firmware release acceptance and
qualification of an individual 3D app are separate results.

## Existing evidence

Release host checks cover ABI4 regression, native scene bounds, clipping/depth,
cooperative time/work aborts with complete-frame preservation, atomic rejection
of invalid scenes, ABI command gating, package/storage checks and allocation/
cleanup. VM fixture execution is host evidence, not ESP32-S3 game acceptance.
See [release evidence](RELEASE_0.7.5.md).

The exact 0.7.5 firmware has owner acceptance for GUI and Apps operation,
host eject returning SD to local Apps, ordinary Diagnostics and FIDO/PIN.
That does not establish sustained performance, IMU direction or concurrent
FIDO operation of every native-scene game.

## Checklist for an ABI5 app

1. Identify the tested firmware BIN and exact `.ekapp` version/hash. Use the
   guarded installation workflow only if a firmware update is needed.
2. Place the package in `/evilkey/apps/` on FAT32 microSD; retain existing saves.
3. Check launcher icon/name, startup, touch controls and both IMU axes if used.
4. Exercise scene changes, clipping, game logic, pause and exit. Report app
   Scene3D status/timing rather than substituting GUI Jet timing.
5. Save, leave, restart and resume. Check old/corrupt saves according to the
   app's format, and corner exit YES/NO.
6. Play a representative sustained session; record duration, memory, frame
   delays and timeout/work-limit behavior. Check complete-frame presentation
   and system responsiveness.
7. Test USB enumeration and an actual FIDO operation during play and after exit.

Record actual results and artifact identities in the app's qualification
record. Missing device checks stay **NOT RUN**, even when host tests pass.
[ABI v5](../apps/ABI_V5.md) remains the normative scene contract.
