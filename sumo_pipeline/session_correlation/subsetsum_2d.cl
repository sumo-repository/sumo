#define MAX_LOCAL_SIZE 20000

int get_index(const int i, const int j, const int n_columns)
{
    return i * n_columns + j;
}

int get_bucket(const int window, const int buckets_per_window, const int buckets_overlap, const int thread_pair_id) {
    return window * (buckets_per_window - buckets_overlap) + (thread_pair_id * buckets_overlap);
}

#define LOOKUP_ARRAY_SIZE 12288

void kernel outer_loop_subset_sum(
    global const  int* client_nums_array,
    global const int* os_nums_array,
    local int* windowed_client_nums,
    local int* windowed_os_nums,
    const int delta,
    const int buckets_per_window,
    const int buckets_overlap,
    global const int* n_windows,
    global int* score,
    global const int* acc_windows)
{
    int thread_pair_id = get_global_id(0); // first dimension
    int thread_window_id = get_global_id(1); // second dimension

    local bool lookup[LOOKUP_ARRAY_SIZE];
    int n_cols = LOOKUP_ARRAY_SIZE / buckets_per_window;

    // Since I have a fixed number of threads per pair of N_WINDOWS, I don't actually want to use the extra ones
    if (thread_window_id > n_windows[thread_pair_id] - 1) {
        return;
    }
    int start_bucket_index = acc_windows[thread_pair_id] + get_bucket(thread_window_id, buckets_per_window, buckets_overlap, thread_pair_id);
    int start_window_index = acc_windows[thread_pair_id] + thread_window_id;
    for (int k = 0; k < buckets_per_window; k++) {
        windowed_client_nums[k] = client_nums_array[start_bucket_index + k];
        windowed_os_nums[k] = os_nums_array[start_bucket_index + k];
    }
    int clientSum = 0;
    int osSum = 0;
    for (int k = 0; k < buckets_per_window; k++)
    {
        clientSum += windowed_client_nums[k];
        osSum += windowed_os_nums[k];
    }
    if (clientSum == 0 && osSum == 0) {
        score[start_window_index] = 0;
        return;  
    }
    else if (clientSum == 0 && osSum > 0) {
        score[start_window_index] = -1;
        return;
    }
    else if (clientSum > 0 && osSum == 0) {
        score[start_window_index] = -1;
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

        int start = clientSum - delta;
        int end = clientSum + delta;

        /* If our range is out of bounds of the possible values for the given
        set, then it has no solution */
        if ((start < 0 && end < 0) || (start > osSum && end > osSum)) {
            score[start_window_index] = -1;
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
                score[start_window_index] = 1;
                return;
            }
        }
        // If it reached here, then subset sum has no solution
        score[start_window_index] = -1;
        return;
    }
}
