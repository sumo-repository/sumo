//#define MAX_LOCAL_SIZE 50000
#define MAX_LOCAL_SIZE 20000

int get_index(const int i, const int j, const int n_columns)
{
    return i * n_columns + j;
}

void kernel inner_loop_subset_sum(global const int* client_nums_array, global const int* os_nums_array, local int* windowed_client_nums, local int* windowed_os_nums, const int delta, const int buckets_per_window, const int n_windows, global int* score)
{
    int monitored_thread = 0; // only for debug purposes
    //int monitored_thread = get_global_id(0); // only for debug purposes
    int thread_global_id = get_global_id(0);
    int work_dim = get_work_dim(); // work dim can be 1D, 2D or 3D
    // TODO: This can be very problematic
    //local bool lookup[MAX_LOCAL_SIZE];
    local char lookup[MAX_LOCAL_SIZE];
    int n_cols = MAX_LOCAL_SIZE / buckets_per_window;
    //printf("--- thread global id: %d; local id: %d; work dim: %d\n", thread_global_id, thread_local_id, work_dim);
    //volatile global int* counterPtr = &counter2; 
    //atomic_inc(counterPtr);
    //printf("inner_loop_subset_sum: %d\n", thread_global_id);
    for (int k = 0; k < buckets_per_window; k++) {
        windowed_client_nums[k] = client_nums_array[thread_global_id + k];
        windowed_os_nums[k] = os_nums_array[thread_global_id + k];
    }
    int clientSum = 0;
    int osSum = 0;
    for (int k = 0; k < buckets_per_window; k++)
    {
        clientSum += windowed_client_nums[k];
        osSum += windowed_os_nums[k];
    }
    if (clientSum == 0 && osSum == 0) {
        score[thread_global_id] = 0;
        //score[thread_global_id] = 1;
        return;  
    }
    else if (clientSum == 0 && osSum > 0) {
        score[thread_global_id] = -1;
        return;
    }
    else if (clientSum > 0 && osSum == 0) {
        score[thread_global_id] = -1;
        return;
    }
    else {
        //if (thread_global_id == monitored_thread)
        //{
        //    printf("\nELSE\n");
        //}
        //printf("\n--%d\n", monitored_thread);
        
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
                //printf("--- i: %d, j: %d;; j - windowed_os_nums[i]: %d; osSum: %d; n_cols: %d", i, j, j - windowed_os_nums[i], osSum, n_cols);
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

        // print lookup table
        //if (thread_global_id == monitored_thread)
        //{
        //    for (int i = 0; i < buckets_per_window; i++) 
        //    {
        //        for (int j = 0; j <= osSum; j++)
        //        {
        //            int lookup_index = get_index(i, j, n_cols);
        //            printf("i: %d; j:%d --> %d;;;;;;\n", i, j, lookup[lookup_index]);
        //        }
        //    }
        //}

        int start = clientSum - delta;
        int end = clientSum + delta;

        /* If our range is out of bounds of the possible values for the given
        set, then it has no solution */
        if ((start < 0 && end < 0) || (start > osSum && end > osSum)) {
            score[thread_global_id] = -1;
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
            //std::cout << "lookup last line " << j << " : " << this->_lookup[this->_N - 1][j - this->_min] << std::endl;
            if (lookup[lookup_index] == 1) {
                score[thread_global_id] = 1;
                return;
            }
        }
        // If it reached here, then subset sum has no solution
        score[thread_global_id] = -1;
        return;
    }
}