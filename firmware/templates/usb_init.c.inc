void usb_init(void) {
    /* Arduino owns USB device/configuration descriptors; only CTAPHID is exposed. */
    mutex_init(&mutex);
    queue_init(&card_to_usb_q, sizeof(uint32_t), 64);
    queue_init(&usb_to_card_q, sizeof(uint32_t), 64);
    if (!mutex || !card_to_usb_q || !usb_to_card_q) abort();
    ITF_HID_CTAP = ITF_HID = 0;
    ITF_HID_KB = ITF_KEYBOARD = ITF_INVALID;
    ITF_HID_TOTAL = ITF_TOTAL = 1;
    card_locked_itf = ITF_TOTAL;
    timeout_counter = calloc(ITF_TOTAL, sizeof(uint32_t));
    if (!timeout_counter) abort();
    hid_init();
    set_atr();
}
