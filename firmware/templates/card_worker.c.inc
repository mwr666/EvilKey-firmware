#ifdef ESP_PLATFORM
/* Keep the CTAP worker independent of the fragmented runtime heap.  LVGL and
 * optional UI objects are constructed before the first host command arrives;
 * allocating the 16 KiB worker stack only then can fail and leave CTAPHID
 * emitting KEEPALIVE_PROCESSING forever.  A persistent statically-backed
 * dispatcher owns the stack once and runs either the CTAP1 or CTAP2 loop. */
#define PF_CARD_WORKER_STACK_BYTES 16384U
static StaticTask_t s_card_worker_tcb;
static StackType_t s_card_worker_stack[PF_CARD_WORKER_STACK_BYTES];
static void *(*s_card_worker_func)(void *);

static void card_worker_task(void *arg) {
    (void)arg;
    while (true) {
        (void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        void *(*func)(void *) = s_card_worker_func;
        if (func) {
            (void)func(NULL);
        }
    }
}

static bool card_worker_launch(void *(*func)(void *)) {
    if (!hcore1) {
        hcore1 = xTaskCreateStaticPinnedToCore(
            card_worker_task, "fido_card", PF_CARD_WORKER_STACK_BYTES, NULL,
            CONFIG_TINYUSB_TASK_PRIORITY - 2, s_card_worker_stack,
            &s_card_worker_tcb, ESP32_CORE1);
    }
    if (!hcore1) {
        return false;
    }
    s_card_worker_func = func;
    xTaskNotifyGive(hcore1);
    return true;
}
#endif

bool card_start(uint8_t itf, void *(*func)(void *)) {
    timeout_start();
    if (card_locked_itf != itf || card_locked_func != func) {
        if (card_locked_itf != ITF_TOTAL || card_locked_func != NULL) {
            card_exit();
        }
        if (func) {
#ifdef ESP_PLATFORM
            if (!card_worker_launch(func)) {
                timeout_stop();
                card_locked_itf = ITF_TOTAL;
                card_locked_func = NULL;
                return false;
            }
#else
            multicore_reset_core1();
            multicore_launch_func_core1(func);
#endif
        }
        led_set_mode(MODE_MOUNTED);
        card_locked_itf = itf;
        card_locked_func = func;
    }
    return true;
}
