/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Included INSIDE cbor_config after its protocol, HMAC and ACFG permission
 * checks. PFM1 handles display settings; PFM2 handles Manager Drive write
 * protection. Every operation requires fresh PIN/UV authorization. */
if(subcommand==0xFF &&
   (vendorCommandId==WS_MANAGER_READ_ID || vendorCommandId==WS_MANAGER_WRITE_ID ||
    vendorCommandId==WS_MANAGER_DRIVE_READ_ID || vendorCommandId==WS_MANAGER_DRIVE_WRITE_ID)) {
    extern uint32_t initial_usage_time_limit;
    if(!paut.in_use || !getUserVerifiedFlagValue() || paut.has_rp_id ||
       (uint32_t)(board_millis()-initial_usage_time_limit)>30000U) {
        CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
    }
    paut.permissions &= (uint8_t)~CTAP_PERMISSION_ACFG;
    fido_object_authorization_session_invalidate();
    if(!vendorCommandIdPresent || vendorParamIntPresent || vendorParamTextString.present) {
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }

    if(vendorCommandId==WS_MANAGER_READ_ID || vendorCommandId==WS_MANAGER_WRITE_ID) {
        if(vendorCommandId==WS_MANAGER_READ_ID) {
            if(vendorParamByteString.present) { CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER); }
        } else {
            if(!vendorParamByteString.present) { CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER); }
            ws_settings_result_t saved=ws_settings_apply(vendorParamByteString.data,vendorParamByteString.len);
            if(saved==WS_SETTINGS_INVALID) { CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER); }
            if(saved==WS_SETTINGS_STALE) { CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED); }
            if(saved!=WS_SETTINGS_OK) { CBOR_ERROR(CTAP2_ERR_PROCESSING); }
        }
        ws_settings_t settings;bool storage_ok=false;
        uint8_t record[WS_SETTINGS_WIRE_SIZE];
        ws_settings_get(&settings,&storage_ok);ws_settings_encode(&settings,record);
        CborEncoder reply;
        CBOR_CHECK(cbor_encoder_create_map(&encoder,&reply,5));
        CBOR_CHECK(cbor_encode_uint(&reply,1));
        CBOR_CHECK(cbor_encode_uint(&reply,WS_MANAGER_API_VERSION));
        CBOR_CHECK(cbor_encode_uint(&reply,2));
        CBOR_CHECK(cbor_encode_byte_string(&reply,record,sizeof(record)));
        CBOR_CHECK(cbor_encode_uint(&reply,3));
        CBOR_CHECK(cbor_encode_text_stringz(&reply,PF_FIRMWARE_VERSION_STRING));
        CBOR_CHECK(cbor_encode_uint(&reply,4));
        CBOR_CHECK(cbor_encode_boolean(&reply,storage_ok));
        CBOR_CHECK(cbor_encode_uint(&reply,5));
        CBOR_CHECK(cbor_encode_uint(&reply,(FIDO_V1_LOCAL_UV?1U:0U)|
            (FIDO_V1_TOUCH_CONFIRM?2U:0U)|(FIDO_V1_BOOT_CONFIRM_FALLBACK?4U:0U)|(FIDO_V1_DISPLAY?8U:0U)));
        CBOR_CHECK(cbor_encoder_close_container(&encoder,&reply));
        resp_size=cbor_encoder_get_buffer_size(&encoder,ctap_resp->init.data+1);
        goto err;
    }

    if(vendorCommandId==WS_MANAGER_DRIVE_READ_ID) {
        if(vendorParamByteString.present) { CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER); }
    } else {
        bool read_only=false;
        if(!vendorParamByteString.present) { CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER); }
        if(!ws_manager_drive_decode(vendorParamByteString.data,vendorParamByteString.len,&read_only)) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        if(!ws_manager_drive_set_read_only(read_only)) { CBOR_ERROR(CTAP2_ERR_PROCESSING); }
        pf_manager_drive_apply_read_only(read_only);
    }
    uint8_t drive_record[WS_MANAGER_DRIVE_WIRE_SIZE];bool drive_storage_ok=ws_manager_drive_storage_ok();
    ws_manager_drive_encode(drive_record);
    CborEncoder drive_reply;
    CBOR_CHECK(cbor_encoder_create_map(&encoder,&drive_reply,6));
    CBOR_CHECK(cbor_encode_uint(&drive_reply,1));
    CBOR_CHECK(cbor_encode_uint(&drive_reply,WS_MANAGER_DRIVE_API_VERSION));
    CBOR_CHECK(cbor_encode_uint(&drive_reply,2));
    CBOR_CHECK(cbor_encode_byte_string(&drive_reply,drive_record,sizeof(drive_record)));
    CBOR_CHECK(cbor_encode_uint(&drive_reply,3));
    CBOR_CHECK(cbor_encode_text_stringz(&drive_reply,PF_FIRMWARE_VERSION_STRING));
    CBOR_CHECK(cbor_encode_uint(&drive_reply,4));
    CBOR_CHECK(cbor_encode_boolean(&drive_reply,drive_storage_ok));
    CBOR_CHECK(cbor_encode_uint(&drive_reply,5));
    CBOR_CHECK(cbor_encode_boolean(&drive_reply,FIDO_V1_MANAGER_DRIVE?true:false));
    CBOR_CHECK(cbor_encode_uint(&drive_reply,6));
    CBOR_CHECK(cbor_encode_boolean(&drive_reply,ws_manager_drive_enabled()));
    CBOR_CHECK(cbor_encoder_close_container(&encoder,&drive_reply));
    resp_size=cbor_encoder_get_buffer_size(&encoder,ctap_resp->init.data+1);
    goto err;
}
