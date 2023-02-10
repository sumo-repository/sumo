#define MAX_LOCAL_SIZE 20000

int get_index(const int i, const int j, const int n_columns)
{
    return i * n_columns + j;
}

#define LOOKUP_ARRAY_SIZE 12288

void kernel outer_loop_subset_sum(
    global const  int* client_nums_array,
    global const int* os_nums_array,
    local int* windowed_client_nums,
    local int* windowed_os_nums,
    const int delta,
    const int buckets_per_window,
    global const int* n_windows,
    global int* score,
    global const int* acc_windows)
{
    int thread_pair_id = get_global_id(0); // first dimension
    int thread_window_id = get_global_id(1); // second dimension
    // TODO: This can be very problematic
    local bool lookup[LOOKUP_ARRAY_SIZE];
    int n_cols = LOOKUP_ARRAY_SIZE / buckets_per_window;
    //printf("thread_window_id %d - thread_window_id %d\n", thread_pair_id, thread_window_id);
    // TODO: CHECK THIS
    if (thread_window_id > n_windows[thread_pair_id]) {
    //if (thread_window_id >= n_windows[thread_pair_id]) {
        //printf("RETURNED thread_window_id: %d; n_windows[thread_pair_id]: %d\n", thread_window_id, n_windows[thread_pair_id]);
        return;
    }
    int start_index = acc_windows[thread_pair_id] + thread_window_id;
    for (int k = 0; k < buckets_per_window; k++) {
        windowed_client_nums[k] = client_nums_array[start_index + k];
        windowed_os_nums[k] = os_nums_array[start_index + k];
        //printf("--- THREAD ID: client_nums_array[start_index + k]: %d; os_nums_array[start_index + k]: %d\n", client_nums_array[start_index + k], os_nums_array[start_index + k]);
    }
    int clientSum = 0;
    int osSum = 0;
    for (int k = 0; k < buckets_per_window; k++)
    {
        clientSum += windowed_client_nums[k];
        osSum += windowed_os_nums[k];
    }
    //printf("--- THREAD ID: clientSum: %d; osSum: %d\n", clientSum, osSum);
    if (clientSum == 0 && osSum == 0) {
        score[start_index] = 0;
        //printf("0 A\n");
        return;  
    }
    else if (clientSum == 0 && osSum > 0) {
        score[start_index] = -1;
        //printf("-1 A\n");
        return;
    }
    else if (clientSum > 0 && osSum == 0) {
        score[start_index] = -1;
        //printf("-1 B\n");
        return;
    }
    else {
        
        for (int j = 0; j <= osSum; j++)
        {
            int lookup_index = get_index(0, j, n_cols);
            lookup[lookup_index] = (windowed_os_nums[0] == j);
        }
        // from here on, 
        for (int i = 1; i < buckets_per_window; i++) {
            for (int j = 0; j <= osSum; j++) { 
                int lookup_index = get_index(i, j, n_cols);
                int lookup_index_up = get_index(i - 1, j, n_cols);
                int lookup_index_left = get_index(i - 1, j - windowed_os_nums[i], n_cols);
                if (0 <= j - windowed_os_nums[i] && j - windowed_os_nums[i] <= osSum) {
                    lookup[lookup_index] = 
                        windowed_os_nums[i] == j ||
                        lookup[lookup_index_up] ||
                        lookup[lookup_index_left];
                }
                else {
                    lookup[lookup_index] = 
                        windowed_os_nums[i] == j ||
                        lookup[lookup_index_up];
                }
            }
        }

        //int start = clientSum - delta;
        // TODO: CHANGE THIS IS JUST TO SEE IF RESULTS ARE THE SAME
        int start = clientSum - delta;
        int end = clientSum + delta;

        /* If our range is out of bounds of the possible values for the given
        set, then it has no solution */
        if ((start < 0 && end < 0) || (start > osSum && end > osSum)) {
            score[start_index] = -1;
            //printf("-1 C\n");
            return;
        }

        /* Ajust our range to the subset's to only search within 
        possible values */
        if (start < 0 && end <= osSum && end >= 0) {
            start = 0;
        }
        if (start >= 0 && start <= osSum && end > osSum) {
            end = osSum;
        }
        if (start < 0 && end > osSum) {
            start = 0;
            end = osSum;
        }

        /* Search if there is a solution in the last line of the lookup table,
        only for the range of values we want */
        for (int j = end; j >= start; j--) {
            int lookup_index = get_index(buckets_per_window - 1, j, n_cols);
            if (lookup[lookup_index] == 1) {
                score[start_index] = 1;
                //printf("1 A\n");
                return;
            }
        }
        // If it reached here, then subset sum has no solution
        score[start_index] = -1;
        //printf("-1 B\n");
        return;
    }
}