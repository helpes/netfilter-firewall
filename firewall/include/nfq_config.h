#ifndef NFQ_CONFIG_H
#define NFQ_CONFIG_H

#define PACKET_BUFFER_SIZE 65535
#define MIN_INPUT_QUEUE_NUMBER 0
#define MAX_INPUT_QUEUE_NUMBER 1
#define MIN_OUTPUT_QUEUE_NUMBER 2
#define MAX_OUTPUT_QUEUE_NUMBER 3
#define Q_HANDLE_LEN (MAX_OUTPUT_QUEUE_NUMBER + 1)
// +2は、state_table_cleaner_threadと、command_listener_thread
#define THREAD_LEN (Q_HANDLE_LEN + 2)

#endif