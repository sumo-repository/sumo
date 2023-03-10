import ctypes
from ctypes import alignment, cdll


lib = ctypes.CDLL('./subsetsumopencl.so')

class SessionPair(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('client_nums_array', ctypes.POINTER(ctypes.c_int)),
                ('os_nums_array', ctypes.POINTER(ctypes.c_int)),
                ('n_buckets', ctypes.c_int),
                ('n_windows', ctypes.c_int)]


class Scores(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('scores', ctypes.POINTER(ctypes.c_int))]


lib.wholeLoopSubsetSum.argtypes = [ctypes.POINTER(SessionPair), ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.POINTER(Scores)]
lib.wholeLoopSubsetSum.restype = None


def whole_loop_subset_sum(packetListClient, packetListOS, nPairs, nBuckets, delta, buckets_per_window, buckets_overlap, nWindows):
    pairs = []
    scores = []
    for i in range(nPairs):
        client_nums_array = (ctypes.c_int * nBuckets[i])(*packetListClient[i])
        os_nums_array = (ctypes.c_int * nBuckets[i])(*packetListOS[i])

        pairs.append(SessionPair(client_nums_array, os_nums_array, nBuckets[i], nWindows[i]))
        scores_array = (ctypes.c_int * nWindows[i])()
        scores.append(Scores(scores_array))

    pairs_array = (SessionPair * nPairs)(*pairs)
    scores_array = (Scores * nPairs)(*scores)
    lib.wholeLoopSubsetSum(pairs_array, nPairs, delta, buckets_per_window, buckets_overlap, scores_array)

    return list(scores)


def sample_test():
    print("Main")


if __name__ == "__main__":
    sample_test()
