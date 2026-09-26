/* R16_RW_PIN_INIT_FIX
 * The FIDO EF globals are initialized by scan_files_fido()/init_fido(), which is
 * normally reached only after CTAPHID_INIT. Device Settings is usable earlier.
 * Resolve the already-scanned flash records directly so local Settings PIN
 * checks do not depend on a host opening a FIDO channel first.
 */
static file_t *pf_local_uv_pin_file(void) {
    if(ef_pin) return ef_pin;
    file_t *pin=file_search_by_fid(EF_PIN,NULL,SPECIFY_EF);
    if(pin) ef_pin=pin;
    return pin;
}

static bool pf_local_uv_bind_keydev_file(void) {
    if(ef_keydev && file_has_data(ef_keydev) && file_get_data(ef_keydev)) return true;
    file_t *key=file_search_by_fid(EF_KEY_DEV,NULL,SPECIFY_EF);
    if(!key || !file_has_data(key) || !file_get_data(key)) return false;
    ef_keydev=key;
    return true;
}
