/**
 * 
    SubsetSum.cpp is a C++ implementation of a dynamic programming algorithm
    for solving the subset sum problem. See ``https://en.wikipedia.org/wiki/
    Subset_sum_problem#Pseudo-polynomial_time_dynamic_programming_solution''
    @author Joseph Boyd
    
    Taken from ``https://github.com/jcboyd/study-no-2'' github repo
*/

#include <vector>
#include <iomanip>
#include <fstream>
#include <streambuf>
#include <string>
#include <cassert>
#include <ctime>
#define CL_HPP_ENABLE_EXCEPTIONS
#define CL_HPP_TARGET_OPENCL_VERSION 200
#include "opencl.hpp" // OpenCL Khronos C++ Wrapper API for Mac
#include <omp.h>
#include "subsetsum.h"

#define OCL_CHECK(result, fn, ...) \
    if(((result) = (fn)) != CL_SUCCESS) { std::cerr << "[line " << __LINE__ << "]" << getErrorString(result) << std::endl; __VA_ARGS__ ; }

#define OCL_ERROR(result, fn) \
    try { OCL_CHECK(result, fn); } catch (cl::Error &exception) \
    { \
        std::cerr << "[line " << __LINE__ << "]" << exception.what() << " | " << getErrorString(exception.err()) << std::endl; \
    }

#define TIMER_T                         struct timespec
#define TIMER_READ(_time)               clock_gettime(CLOCK_MONOTONIC, &(_time))
#define TIMER_DIFF_SECONDS(_start, _stop) \
    (((double)(_stop.tv_sec)  + (double)(_stop.tv_nsec / 1E9)) - \
     ((double)(_start.tv_sec) + (double)(_start.tv_nsec / 1E9)))

const char *getErrorString(cl_int error)
{
switch(error){
    // run-time and JIT compiler errors
    case 0: return "CL_SUCCESS";
    case -1: return "CL_DEVICE_NOT_FOUND";
    case -2: return "CL_DEVICE_NOT_AVAILABLE";
    case -3: return "CL_COMPILER_NOT_AVAILABLE";
    case -4: return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
    case -5: return "CL_OUT_OF_RESOURCES";
    case -6: return "CL_OUT_OF_HOST_MEMORY";
    case -7: return "CL_PROFILING_INFO_NOT_AVAILABLE";
    case -8: return "CL_MEM_COPY_OVERLAP";
    case -9: return "CL_IMAGE_FORMAT_MISMATCH";
    case -10: return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
    case -11: return "CL_BUILD_PROGRAM_FAILURE";
    case -12: return "CL_MAP_FAILURE";
    case -13: return "CL_MISALIGNED_SUB_BUFFER_OFFSET";
    case -14: return "CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST";
    case -15: return "CL_COMPILE_PROGRAM_FAILURE";
    case -16: return "CL_LINKER_NOT_AVAILABLE";
    case -17: return "CL_LINK_PROGRAM_FAILURE";
    case -18: return "CL_DEVICE_PARTITION_FAILED";
    case -19: return "CL_KERNEL_ARG_INFO_NOT_AVAILABLE";

    // compile-time errors
    case -30: return "CL_INVALID_VALUE";
    case -31: return "CL_INVALID_DEVICE_TYPE";
    case -32: return "CL_INVALID_PLATFORM";
    case -33: return "CL_INVALID_DEVICE";
    case -34: return "CL_INVALID_CONTEXT";
    case -35: return "CL_INVALID_QUEUE_PROPERTIES";
    case -36: return "CL_INVALID_COMMAND_QUEUE";
    case -37: return "CL_INVALID_HOST_PTR";
    case -38: return "CL_INVALID_MEM_OBJECT";
    case -39: return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
    case -40: return "CL_INVALID_IMAGE_SIZE";
    case -41: return "CL_INVALID_SAMPLER";
    case -42: return "CL_INVALID_BINARY";
    case -43: return "CL_INVALID_BUILD_OPTIONS";
    case -44: return "CL_INVALID_PROGRAM";
    case -45: return "CL_INVALID_PROGRAM_EXECUTABLE";
    case -46: return "CL_INVALID_KERNEL_NAME";
    case -47: return "CL_INVALID_KERNEL_DEFINITION";
    case -48: return "CL_INVALID_KERNEL";
    case -49: return "CL_INVALID_ARG_INDEX";
    case -50: return "CL_INVALID_ARG_VALUE";
    case -51: return "CL_INVALID_ARG_SIZE";
    case -52: return "CL_INVALID_KERNEL_ARGS";
    case -53: return "CL_INVALID_WORK_DIMENSION";
    case -54: return "CL_INVALID_WORK_GROUP_SIZE";
    case -55: return "CL_INVALID_WORK_ITEM_SIZE";
    case -56: return "CL_INVALID_GLOBAL_OFFSET";
    case -57: return "CL_INVALID_EVENT_WAIT_LIST";
    case -58: return "CL_INVALID_EVENT";
    case -59: return "CL_INVALID_OPERATION";
    case -60: return "CL_INVALID_GL_OBJECT";
    case -61: return "CL_INVALID_BUFFER_SIZE";
    case -62: return "CL_INVALID_MIP_LEVEL";
    case -63: return "CL_INVALID_GLOBAL_WORK_SIZE";
    case -64: return "CL_INVALID_PROPERTY";
    case -65: return "CL_INVALID_IMAGE_DESCRIPTOR";
    case -66: return "CL_INVALID_COMPILER_OPTIONS";
    case -67: return "CL_INVALID_LINKER_OPTIONS";
    case -68: return "CL_INVALID_DEVICE_PARTITION_COUNT";

    // extension errors
    case -1000: return "CL_INVALID_GL_SHAREGROUP_REFERENCE_KHR";
    case -1001: return "CL_PLATFORM_NOT_FOUND_KHR";
    case -1002: return "CL_INVALID_D3D10_DEVICE_KHR";
    case -1003: return "CL_INVALID_D3D10_RESOURCE_KHR";
    case -1004: return "CL_D3D10_RESOURCE_ALREADY_ACQUIRED_KHR";
    case -1005: return "CL_D3D10_RESOURCE_NOT_ACQUIRED_KHR";
    default: return "Unknown OpenCL error";
    }
}

extern "C"
{
    void wholeLoopSubsetSum(const SessionPair* sessionPairs, const int nPairs, const int delta, const int buckets_per_window, const int buckets_overlap, Scores* scores)
	{
        std::vector<cl::Platform> platforms;
        cl::Platform::get(&platforms);
        cl_int result;

        for(auto platform : platforms)
        {
            std::cout << "Platform: " << platform.getInfo<CL_PLATFORM_NAME>().data() << std::endl;
        }

        std::vector<cl::Device> devices;
        platforms.front().getDevices(CL_DEVICE_TYPE_GPU, &devices);
        for(auto device : devices)
        {
            std::cout << "Device: " << device.getInfo<CL_DEVICE_NAME>().data() << std::endl;
        }

        cl::Device device = devices[0];
        std::cout << "Chosen device: " << device.getInfo<CL_DEVICE_NAME>().data() << std::endl;

        // To know size for lookup table
        // Max size CMU hakone: 49152 bytes
        // 49152 bytes * 32 = 1572864 chars
        // 1572864 / 24 threads = 65536 chars per thread
        cl_ulong local_memory_size;
        OCL_CHECK(result, clGetDeviceInfo(device(), CL_DEVICE_LOCAL_MEM_SIZE, sizeof(cl_ulong), &local_memory_size, NULL));
        std::cout << "Max local memory: " << local_memory_size << std::endl;

        // cl_int max_buffer_size;
        // OCL_CHECK(result, clGetDeviceInfo(device(), CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(cl_int), &max_buffer_size, NULL));
        // std::cout << "Max buffer size: " << max_buffer_size << std::endl;

        cl::Context context(device);

        std::ifstream t("subsetsum.cl");
        std::string kernel_code((std::istreambuf_iterator<char>(t)),
                 std::istreambuf_iterator<char>());

        cl::Program::Sources sources;
        sources.push_back({ kernel_code.c_str(), kernel_code.length() });

        cl::Program program(context, sources);

        OCL_CHECK(result, program.build({ device }), {
            std::cout << " Error building: " << program.getBuildInfo<CL_PROGRAM_BUILD_LOG>(device) << "\n";
            exit(1);
        });

        int n_threads = 24;
        omp_set_num_threads(n_threads); // Hakone machine
        // My mac has 6 cores
        //omp_set_num_threads(6); // my computer
        //omp_set_num_threads(1);

        // Iterates through all possible session combinations
        // Each thread handles a different portion of the loop
        int i;
        int counter = 0;
        int total_buckets = 0;
        int monitored_thread = 0;
        int total_windows = 0;
        
        #pragma omp parallel
        //#pragma omp parallel reduction(+:iteration)
        {
            //iteration++;
            cl::Kernel inner_loop_subset_sum_kernel = cl::Kernel(program, "inner_loop_subset_sum");
            cl::CommandQueue queue(context, device);
            #pragma omp for reduction(+:counter,total_buckets,total_windows)
            for (i = 0; i < nPairs; i++) {
                //counter++;
                //std::cout << "---------- i ---------- " << i << ": " << omp_get_thread_num() << std::endl;
                //std::cout << "sessionPairs[i].n_buckets " << sessionPairs[i].n_buckets << std::endl;
                cl::Buffer clientNumsArray_d(context, CL_MEM_READ_ONLY, sizeof(int) * sessionPairs[i].n_buckets);
                //std::cout << "sessionPairs[i].n_buckets 2 " << sessionPairs[i].n_buckets << std::endl;
                cl::Buffer osNumsArray_d(context, CL_MEM_READ_ONLY, sizeof(int) * sessionPairs[i].n_buckets);
                //std::cout << "sessionPairs[i].n_windows " << sessionPairs[i].n_windows << std::endl;
                cl::Buffer scoresArray_d(context, CL_MEM_READ_WRITE, sizeof(int) * sessionPairs[i].n_windows);
                // write to a buffer object from host memory
                total_buckets += sessionPairs[i].n_buckets;
                total_windows += sessionPairs[i].n_windows;
                OCL_ERROR(result, queue.enqueueWriteBuffer(clientNumsArray_d, CL_TRUE, 0, sizeof(int) * sessionPairs[i].n_buckets, sessionPairs[i].client_nums_array));
                OCL_ERROR(result, queue.enqueueWriteBuffer(osNumsArray_d, CL_TRUE, 0, sizeof(int) * sessionPairs[i].n_buckets, sessionPairs[i].os_nums_array));
                inner_loop_subset_sum_kernel.setArg(0, clientNumsArray_d);
                inner_loop_subset_sum_kernel.setArg(1, osNumsArray_d);
                // https://stackoverflow.com/questions/72113696/defining-size-of-array-using-clsetkernelarg
                // windowed_client_nums
                clSetKernelArg(inner_loop_subset_sum_kernel(), 2, sizeof(int) * buckets_per_window, NULL);
                // windowed_os_nums
                clSetKernelArg(inner_loop_subset_sum_kernel(), 3, sizeof(int) * buckets_per_window, NULL);
                inner_loop_subset_sum_kernel.setArg(4, delta);
                inner_loop_subset_sum_kernel.setArg(5, buckets_per_window);
                inner_loop_subset_sum_kernel.setArg(6, sessionPairs[i].n_windows);
                //inner_loop_subset_sum_kernel.setArg(6, sessionPairs[i].n_windows);
                inner_loop_subset_sum_kernel.setArg(7, scoresArray_d);
                int global = sessionPairs[i].n_windows;
                //int global = {nPairs, sessionPairs[i].n_windows}
                //int windows_per_thread = int(n_threads / sessionPairs[i].n_windows)
                OCL_ERROR(result, queue.enqueueNDRangeKernel(inner_loop_subset_sum_kernel, cl::NullRange, cl::NDRange(global), cl::NDRange(1)));
                OCL_ERROR(result, queue.enqueueReadBuffer(scoresArray_d, CL_FALSE, 0, sizeof(int) * sessionPairs[i].n_windows, scores[i].scores));
                //OCL_ERROR(result, queue.enqueueReadBuffer(scoresArray_d, CL_TRUE, 0, sizeof(int) * sessionPairs[i].n_windows, scores[i].scores));
            }
            clFinish(queue());
	    }
        printf("wholeLoopSubsetSum: nPairs=%i total_buckets=%i total_windows=%i delta=%i buckets_per_window=%i\n",
            counter, total_buckets, total_windows, delta, buckets_per_window);
    } 
};

static int gen(int low, int high)
{
    assert(high > low && "invalid input value");
    return (rand() % (high-low)) + low;
}

int main(int argc, char** argv)
{
    int nPairs = 100000;
    const int delta = 10;
    const int buckets_per_window = 4;
    const int buckets_overlap = 10;
    std::vector<SessionPair>* sessionPairs = new std::vector<SessionPair>(nPairs);
    std::vector<Scores>* scores = new std::vector<Scores>(nPairs);

    printf("Usage %s [MULT_N_PAIRS]\n", argv[0]);

    if (argc > 1)
        nPairs *= atoi(argv[1]);

    srand (1234);

    auto s = scores->begin();
    for (auto it = sessionPairs->begin(); it != sessionPairs->end(); ++it, ++s)
    {
        const int factor = 10;
        int nWindows = gen(1, 10);
        int nBuckets = nWindows * factor; // between 1000-10000
        it->n_buckets = nBuckets;
        it->n_windows = nWindows;
        it->client_nums_array = new int[nBuckets];
        it->os_nums_array = new int[nBuckets];
        s->scores = new int[it->n_windows];
        for (int i = 0; i < nBuckets; ++i)
        {
            it->client_nums_array[i] = gen(10, 200); // between 10-200
            it->os_nums_array[i] = gen(10, 200); // between 10-200
        }
    }

    TIMER_T t1, t2;
    TIMER_READ(t1);
    wholeLoopSubsetSum(&(*sessionPairs)[0], nPairs, delta, buckets_per_window, buckets_overlap, &(*scores)[0]);
    TIMER_READ(t2);
    printf("Exec time (s): %f\n", TIMER_DIFF_SECONDS(t1, t2));
 
    for (auto s : *sessionPairs)
    {
        delete [] s.client_nums_array;
        delete [] s.os_nums_array;
    }
    for (auto s : *scores)
    {
        delete [] s.scores;
    }

    delete sessionPairs;
    delete scores;
    return 0;
}