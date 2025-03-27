#ifndef PAGE_FAULT_H
#define PAGE_FAULT_H

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// Tuple to act as the values of the HASH map used to track fault counts for each pid
struct fault_tracking {
    __u64 pg_fault_count;     // Curr fault count
    char comm[TASK_COMM_LEN];      // Process name
};

// Struct sent to the perf buffer for printing
struct page_fault_event_out {
    __u64 timestamp;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u32 page_fault_count;
};

#endif // PAGE_FAULT_H