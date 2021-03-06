#!/usr/bin/env python

from claripy import BVS, BVV, Solver, Or, RotateLeft
import IPython, sys, time, datetime
from binascii import unhexlify

test = False #True

def concat(l):
    l = list(l)
    return l[0].concat(*l[1:])

def map4x4(i,x):
    # see moebius4.py for calculation of the polynomials below
    m = [
        concat(( ((x[0:0]) ^ (x[0:0]&x[1:1]) ^ (x[2:2]) ^ (x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[0:0]&x[1:1]&x[3:3]) ^ (x[2:2]&x[3:3])),
                 (1 ^ (x[0:0]) ^ (x[1:1]) ^ (x[0:0]&x[1:1]) ^ (x[0:0]&x[2:2]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[0:0]&x[3:3]) ^ (x[2:2]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3])),
                 (1 ^ (x[1:1]) ^ (x[0:0]&x[1:1]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[3:3]) ^ (x[0:0]&x[1:1]&x[3:3]) ^ (x[2:2]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3])),
                 ((x[1:1]) ^ (x[0:0]&x[1:1]) ^ (x[0:0]&x[2:2]) ^ (x[1:1]&x[2:2]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[0:0]&x[1:1]&x[3:3]) ^ (x[2:2]&x[3:3])))),

        concat(( ((x[2:2]) ^ (x[0:0]&x[2:2]) ^ (x[1:1]&x[2:2]) ^ (x[3:3]) ^ (x[2:2]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3])),
                 ((x[0:0]) ^ (x[2:2]) ^ (x[1:1]&x[2:2]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[3:3]) ^ (x[0:0]&x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[2:2]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3])),
                 (1 ^ (x[1:1]) ^ (x[0:0]&x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[2:2]&x[3:3])),
                 ((x[0:0]) ^ (x[2:2]) ^ (x[0:0]&x[2:2]) ^ (x[1:1]&x[3:3]) ^ (x[2:2]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3])))),

        concat(((1 ^ (x[0:0]) ^ (x[1:1]) ^ (x[2:2]) ^ (x[0:0]&x[2:2]) ^ (x[1:1]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3])),
                ((x[0:0]&x[1:1]) ^ (x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3])),
                ((x[1:1]) ^ (x[0:0]&x[1:1]) ^ (x[2:2]) ^ (x[0:0]&x[2:2]) ^ (x[1:1]&x[2:2]) ^ (x[0:0]&x[3:3]) ^ (x[2:2]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3])),
                (1 ^ (x[0:0]&x[1:1]) ^ (x[2:2]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[0:0]&x[3:3]) ^ (x[2:2]&x[3:3])))),

        concat(((1 ^ (x[0:0]) ^ (x[2:2]) ^ (x[1:1]&x[2:2]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[3:3]) ^ (x[2:2]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3])),
                ((x[0:0]) ^ (x[0:0]&x[1:1]) ^ (x[2:2]) ^ (x[0:0]&x[2:2]) ^ (x[3:3]) ^ (x[0:0]&x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3])),
                (1 ^ (x[1:1]) ^ (x[2:2]) ^ (x[0:0]&x[2:2]) ^ (x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3])),
                (1 ^ (x[0:0]) ^ (x[3:3]) ^ (x[0:0]&x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3])))),
    ]
    return m[i]

def next_lfsr(s, in_state):
    # for more info on this fn see the file lfsr-next-bits.py
    rules = [
        [0, 1, 24, 33, 49, 56, 80, 89, 97, 104, 112, 113, 120, 121],
        [16, 25, 32, 41, 56, 73, 81, 89, 104, 105, 113],
        [2, 10, 18, 27, 43, 58, 59, 67, 82, 90, 91, 98, 99, 107, 115, 122],
        [3, 11, 19, 27, 42, 50, 122],
        [5, 13, 21, 28, 29, 36, 61, 77, 84, 92, 100, 101],
        [29, 37, 44, 61, 69, 76, 85, 108, 116, 124],
        [14, 15, 23, 31, 38, 55, 63, 79, 86, 87, 102, 118],
        [6, 7, 15, 22, 30, 38, 46, 62, 70, 78, 79, 87, 126],
        [0, 1, 8, 9, 25, 32, 40, 48, 49, 56, 65, 72, 73, 80, 88, 97, 105, 112, 113],
        [24, 33, 40, 49, 64, 81, 89, 97, 112, 113, 121],
        [2, 10, 18, 26, 34, 43, 83, 90, 106],
        [3, 11, 19, 27, 35, 50, 58],
        [4, 13, 29, 36, 37, 44, 45, 69, 76, 77, 92, 93, 100],
        [5, 37, 45, 52, 69, 77, 84, 93, 116, 124],
        [6, 15, 23, 38, 46, 54, 62, 70, 78, 87, 126],
        [6, 7, 14, 22, 23, 30, 31, 39, 46, 62, 63, 71, 86, 87, 94, 110],
        [8, 9, 16, 17, 33, 40, 48, 56, 57, 64, 73, 80, 81, 88, 96, 105, 113, 120, 121],
        [0, 25, 32, 40, 49, 56, 64, 65, 73, 80, 89, 97, 105, 113],
        [10, 18, 26, 34, 42, 51, 91, 98, 114],
        [11, 19, 27, 35, 43, 58, 66],
        [12, 21, 37, 44, 45, 52, 53, 77, 84, 85, 100, 101, 108],
        [5, 13, 45, 53, 60, 77, 85, 92, 101, 124],
        [6, 7, 14, 15, 22, 23, 38, 39, 46, 63, 71, 86, 94, 110],
        [6, 14, 30, 47, 62, 63, 78, 79, 102, 110, 118],
        [0, 1, 16, 17, 24, 40, 49, 57, 73, 80, 81, 88, 89, 96, 104, 120],
        [8, 33, 40, 48, 57, 64, 72, 73, 81, 88, 97, 105, 113, 121],
        [18, 26, 34, 42, 50, 59, 99, 106, 122],
        [19, 27, 35, 43, 51, 66, 74],
        [4, 20, 21, 29, 52, 53, 60, 61, 76, 77, 92, 116],
        [4, 5, 13, 45, 53, 61, 68, 76, 77, 100, 108],
        [14, 15, 22, 23, 30, 31, 46, 47, 54, 71, 79, 94, 102, 118],
        [14, 22, 38, 55, 70, 71, 86, 87, 110, 118, 126],
        [1, 8, 9, 24, 25, 32, 48, 57, 65, 81, 88, 89, 96, 97, 104, 112],
        [0, 16, 25, 40, 49, 57, 64, 73, 81, 89, 96, 105, 120],
        [3, 26, 34, 42, 50, 58, 67, 107, 114],
        [27, 35, 43, 51, 59, 74, 82],
        [12, 28, 29, 37, 60, 61, 68, 69, 84, 85, 100, 124],
        [12, 13, 21, 53, 61, 69, 76, 84, 85, 108, 116],
        [22, 23, 30, 31, 38, 39, 54, 55, 62, 79, 87, 102, 110, 126],
        [6, 7, 15, 30, 31, 38, 39, 46, 54, 62, 70, 71, 79, 110, 118, 126],
        [9, 16, 17, 32, 33, 40, 56, 65, 73, 89, 96, 97, 104, 105, 112, 120],
        [1, 8, 24, 33, 48, 57, 65, 72, 81, 89, 97, 104, 113],
        [11, 34, 42, 50, 58, 66, 75, 115, 122],
        [35, 43, 51, 59, 67, 82, 90],
        [5, 20, 36, 37, 45, 68, 69, 76, 77, 92, 93, 108],
        [20, 21, 29, 61, 69, 77, 84, 92, 93, 116, 124],
        [6, 7, 15, 22, 30, 46, 47, 54, 71, 78, 87, 94, 118],
        [7, 14, 15, 23, 38, 39, 46, 47, 54, 62, 70, 78, 79, 87, 118, 126],
        [1, 17, 24, 25, 40, 41, 48, 64, 73, 81, 97, 104, 105, 112, 113, 120],
        [9, 16, 32, 41, 56, 65, 73, 80, 89, 97, 105, 112, 121],
        [2, 19, 34, 35, 42, 43, 50, 51, 58, 67, 74, 75, 98, 99, 107, 115],
        [43, 51, 59, 67, 75, 90, 98],
        [13, 28, 44, 45, 53, 76, 77, 84, 85, 100, 101, 116],
        [5, 28, 29, 37, 69, 77, 85, 92, 100, 101, 124],
        [6, 14, 22, 23, 30, 31, 39, 55, 63, 70, 71, 78, 79, 86, 94, 102, 110, 126],
        [6, 7, 23, 38, 39, 46, 47, 55, 63, 71, 86, 87, 94, 110, 126],
        [1, 9, 25, 32, 33, 48, 49, 56, 72, 81, 89, 105, 112, 113, 120, 121],
        [0, 17, 24, 25, 41, 48, 56, 57, 65, 72, 80, 81, 88, 97, 105, 121],
        [2, 3, 10, 27, 34, 35, 42, 50, 58, 59, 67, 82, 98, 99, 106],
        [51, 59, 67, 75, 83, 98, 106],
        [4, 36, 45, 52, 53, 61, 76, 77, 84, 92, 124],
        [4, 5, 13, 21, 36, 37, 76, 100],
        [7, 14, 22, 30, 31, 38, 39, 47, 63, 71, 78, 79, 86, 87, 94, 102, 110, 118],
        [6, 7, 14, 22, 38, 39, 46, 47, 55, 62, 70, 78, 79, 102, 110, 118],
        [0, 1, 9, 17, 25, 33, 48, 49, 65, 72, 73, 89, 97],
        [0, 8, 32, 33, 40, 41, 48, 57, 72, 88, 89, 96, 105, 120, 121],
        [10, 11, 18, 35, 42, 43, 50, 58, 66, 67, 75, 90, 106, 107, 114],
        [59, 67, 75, 83, 91, 106, 114],
        [5, 12, 44, 53, 60, 61, 69, 84, 85, 92, 100],
        [12, 13, 21, 29, 44, 45, 84, 108],
        [6, 30, 31, 46, 47, 54, 55, 62, 63, 70, 78, 79, 86, 87, 102, 118, 126],
        [14, 15, 22, 30, 46, 47, 54, 55, 63, 70, 78, 86, 87, 110, 118, 126],
        [8, 9, 17, 25, 33, 41, 56, 57, 73, 80, 81, 97, 105],
        [0, 1, 8, 16, 25, 57, 64, 72, 73, 96, 97, 104, 120, 121],
        [18, 19, 26, 43, 50, 51, 58, 66, 74, 75, 83, 98, 114, 115, 122],
        [67, 75, 83, 91, 99, 114, 122],
        [13, 20, 52, 61, 68, 69, 77, 92, 93, 100, 108],
        [20, 21, 29, 37, 52, 53, 92, 116],
        [6, 7, 14, 15, 22, 31, 55, 86, 87, 126],
        [6, 7, 15, 23, 30, 31, 39, 55, 70, 86, 110, 118, 126],
        [16, 17, 25, 33, 41, 49, 64, 65, 81, 88, 89, 105, 113],
        [0, 1, 8, 9, 16, 24, 25, 33, 40, 41, 48, 49, 56, 57, 64, 73, 81, 104, 105, 112, 113, 120, 121],
        [2, 26, 27, 35, 43, 58, 59, 67, 74, 75, 82, 91, 98, 99, 106, 107, 115, 122],
        [3, 75, 83, 91, 99, 107, 122],
        [21, 28, 60, 69, 76, 77, 85, 100, 101, 108, 116],
        [28, 29, 37, 45, 60, 61, 100, 124],
        [6, 7, 14, 23, 30, 31, 38, 54, 62, 70, 71, 78, 110],
        [7, 14, 15, 23, 31, 38, 39, 47, 63, 78, 94, 118, 126],
        [24, 25, 33, 41, 49, 57, 72, 73, 89, 96, 97, 113, 121],
        [0, 1, 8, 9, 16, 17, 24, 25, 32, 33, 40, 73, 80, 81, 89, 112],
        [2, 10, 82, 90, 98, 106, 114],
        [3, 11, 83, 91, 99, 107, 115],
        [4, 21, 29, 36, 45, 68, 76, 84, 116, 124],
        [5, 36, 37, 45, 53, 68, 69, 108],
        [14, 15, 22, 31, 38, 39, 46, 62, 70, 78, 79, 86, 118],
        [7, 15, 22, 23, 31, 39, 46, 47, 55, 71, 86, 102, 126],
        [0, 25, 32, 33, 40, 48, 56, 64, 72, 73, 81, 97, 104, 105, 113, 120],
        [8, 9, 16, 17, 24, 25, 32, 33, 40, 41, 48, 81, 88, 89, 97, 120],
        [10, 18, 90, 98, 106, 114, 122],
        [2, 3, 11, 19, 34, 35, 43, 51, 66, 67, 75, 83, 91, 98],
        [5, 12, 29, 37, 44, 53, 76, 84, 92, 124],
        [13, 44, 45, 53, 61, 76, 77, 116],
        [22, 23, 30, 39, 46, 47, 54, 70, 78, 86, 87, 94, 126],
        [7, 15, 23, 30, 31, 39, 47, 54, 55, 63, 79, 94, 110],
        [1, 8, 33, 40, 41, 48, 56, 64, 72, 80, 81, 89, 105, 112, 113, 121],
        [1, 16, 17, 24, 25, 32, 33, 40, 41, 48, 49, 56, 89, 96, 97, 105],
        [3, 18, 26, 98, 106, 114, 122],
        [10, 11, 19, 27, 42, 43, 51, 59, 74, 75, 83, 91, 99, 106],
        [5, 13, 20, 37, 45, 52, 61, 84, 92, 100],
        [21, 52, 53, 61, 69, 84, 85, 124],
        [6, 7, 15, 22, 30, 39, 47, 55, 63, 70, 71, 86, 102, 110],
        [15, 23, 31, 38, 39, 47, 55, 62, 63, 71, 87, 102, 118],
        [0, 9, 16, 25, 40, 57, 65, 73, 88, 89, 97],
        [9, 24, 25, 32, 33, 40, 41, 48, 49, 56, 57, 64, 97, 104, 105, 113],
        [3, 11, 26, 34, 106, 114, 122],
        [18, 19, 27, 35, 50, 51, 59, 67, 82, 83, 91, 99, 107, 114],
        [13, 21, 28, 45, 53, 60, 69, 92, 100, 108],
        [5, 29, 60, 61, 69, 77, 92, 93],
        [14, 15, 23, 30, 38, 47, 55, 63, 71, 78, 79, 94, 110, 118],
        [6, 15, 22, 23, 38, 46, 47, 54, 55, 62, 78, 79, 94, 126],
        [8, 17, 24, 33, 48, 65, 73, 81, 96, 97, 105],
        [17, 32, 33, 40, 41, 48, 49, 56, 57, 64, 65, 72, 105, 112, 113, 121],
        [3, 11, 19, 34, 42, 114, 122],
        [26, 27, 35, 43, 58, 59, 67, 75, 90, 91, 99, 107, 115, 122],
        [21, 29, 36, 53, 61, 68, 77, 100, 108, 116],
        [13, 37, 68, 69, 77, 85, 100, 101],
        [22, 23, 31, 38, 46, 55, 63, 71, 79, 86, 87, 102, 118, 126],
        [7, 14, 23, 30, 31, 46, 54, 55, 62, 63, 70, 86, 87, 102]]
    res = []
    for i in reversed(range(128)):
        r = 0
        for b in rules[i]:
            r ^= in_state[b:b]
        res.append(r)
    return concat(res)

def F(i,x):
    m = [
        (x[0:0]) ^ (x[1:1]) ^ (x[0:0]&x[2:2]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[2:2]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]) ^ (x[4:4]) ^ (x[1:1]&x[4:4]) ^ (x[0:0]&x[1:1]&x[4:4]) ^ (x[0:0]&x[2:2]&x[4:4]) ^ (x[1:1]&x[2:2]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]) ^ (x[0:0]&x[3:3]&x[4:4]) ^ (x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[5:5]) ^ (x[0:0]&x[1:1]&x[5:5]) ^ (x[2:2]&x[5:5]) ^ (x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[3:3]&x[5:5]) ^ (x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[5:5]) ^ (x[1:1]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]&x[5:5]) ^ (x[3:3]&x[4:4]&x[5:5]) ^ (x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]&x[5:5]),
        1 ^ (x[1:1]) ^ (x[0:0]&x[1:1]) ^ (x[2:2]) ^ (x[3:3]) ^ (x[0:0]&x[1:1]&x[3:3]) ^ (x[2:2]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3]) ^ (x[4:4]) ^ (x[0:0]&x[4:4]) ^ (x[2:2]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]) ^ (x[3:3]&x[4:4]) ^ (x[0:0]&x[3:3]&x[4:4]) ^ (x[2:2]&x[3:3]&x[4:4]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[5:5]) ^ (x[0:0]&x[1:1]&x[5:5]) ^ (x[0:0]&x[2:2]&x[5:5]) ^ (x[1:1]&x[2:2]&x[5:5]) ^ (x[3:3]&x[5:5]) ^ (x[1:1]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[5:5]) ^ (x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[4:4]&x[5:5]) ^ (x[2:2]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]&x[5:5]) ^ (x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]&x[5:5]),
        1 ^ (x[0:0]) ^ (x[0:0]&x[2:2]) ^ (x[1:1]&x[2:2]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[2:2]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]) ^ (x[0:0]&x[4:4]) ^ (x[1:1]&x[4:4]) ^ (x[2:2]&x[4:4]) ^ (x[0:0]&x[2:2]&x[4:4]) ^ (x[1:1]&x[2:2]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]) ^ (x[3:3]&x[4:4]) ^ (x[0:0]&x[3:3]&x[4:4]) ^ (x[1:1]&x[3:3]&x[4:4]) ^ (x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[5:5]) ^ (x[1:1]&x[5:5]) ^ (x[0:0]&x[1:1]&x[5:5]) ^ (x[0:0]&x[2:2]&x[5:5]) ^ (x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[3:3]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[5:5]) ^ (x[4:4]&x[5:5]) ^ (x[0:0]&x[4:4]&x[5:5]) ^ (x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]&x[5:5]),
        (x[0:0]) ^ (x[2:2]) ^ (x[0:0]&x[2:2]) ^ (x[1:1]&x[2:2]) ^ (x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[0:0]&x[1:1]&x[3:3]) ^ (x[2:2]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3]) ^ (x[4:4]) ^ (x[1:1]&x[2:2]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]) ^ (x[3:3]&x[4:4]) ^ (x[0:0]&x[3:3]&x[4:4]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[5:5]) ^ (x[0:0]&x[1:1]&x[5:5]) ^ (x[2:2]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[4:4]&x[5:5]) ^ (x[2:2]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]&x[5:5]) ^ (x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]&x[5:5]),
        1 ^ (x[0:0]) ^ (x[1:1]) ^ (x[2:2]) ^ (x[0:0]&x[2:2]) ^ (x[4:4]) ^ (x[1:1]&x[4:4]) ^ (x[0:0]&x[1:1]&x[4:4]) ^ (x[1:1]&x[2:2]&x[4:4]) ^ (x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[5:5]) ^ (x[0:0]&x[2:2]&x[5:5]) ^ (x[1:1]&x[2:2]&x[5:5]) ^ (x[3:3]&x[5:5]) ^ (x[1:1]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[5:5]) ^ (x[2:2]&x[3:3]&x[5:5]) ^ (x[4:4]&x[5:5]) ^ (x[2:2]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[4:4]&x[5:5]) ^ (x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]&x[5:5]),
        (x[1:1]) ^ (x[2:2]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[3:3]) ^ (x[0:0]&x[1:1]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]) ^ (x[0:0]&x[1:1]&x[4:4]) ^ (x[0:0]&x[2:2]&x[4:4]) ^ (x[1:1]&x[2:2]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]) ^ (x[3:3]&x[4:4]) ^ (x[1:1]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[5:5]) ^ (x[1:1]&x[5:5]) ^ (x[0:0]&x[1:1]&x[5:5]) ^ (x[2:2]&x[5:5]) ^ (x[0:0]&x[2:2]&x[5:5]) ^ (x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[5:5]) ^ (x[3:3]&x[5:5]) ^ (x[0:0]&x[3:3]&x[5:5]) ^ (x[2:2]&x[3:3]&x[5:5]) ^ (x[4:4]&x[5:5]) ^ (x[0:0]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[4:4]&x[5:5]) ^ (x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]&x[5:5]),
        (x[0:0]) ^ (x[1:1]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[1:1]&x[4:4]) ^ (x[2:2]&x[4:4]) ^ (x[0:0]&x[2:2]&x[4:4]) ^ (x[3:3]&x[4:4]) ^ (x[1:1]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]) ^ (x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[1:1]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[5:5]) ^ (x[1:1]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[5:5]) ^ (x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[2:2]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]&x[5:5]) ^ (x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]&x[5:5]),
        1 ^ (x[0:0]) ^ (x[1:1]) ^ (x[0:0]&x[1:1]) ^ (x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[0:0]&x[1:1]&x[3:3]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]) ^ (x[0:0]&x[1:1]&x[4:4]) ^ (x[2:2]&x[4:4]) ^ (x[1:1]&x[2:2]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]) ^ (x[1:1]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[5:5]) ^ (x[1:1]&x[5:5]) ^ (x[2:2]&x[5:5]) ^ (x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[5:5]) ^ (x[3:3]&x[5:5]) ^ (x[1:1]&x[3:3]&x[5:5]) ^ (x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[5:5]) ^ (x[4:4]&x[5:5]) ^ (x[1:1]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[4:4]&x[5:5]) ^ (x[2:2]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[4:4]&x[5:5]) ^ (x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]&x[5:5]),
    ]
    return m[i]

start = time.time()
print("[i] 00:00:00 initializing...")

key = BVS("key", 64)
ciphertext = BVS("ciphertext", 17*8)
plaintext = BVS("plaintext", len(ciphertext))

# test vectors
# concat(n for i,n in enumerate(BVV("PX1000CrPassword").chop(4)) if i%2==1)
# == 0x0810003201337f24
vk = 0x0810003201337f24
if test: vk = 0x082ef9c7a3229dcf
# This is a test message, which will be converted by the PX1k into ciphertext
ct=BVV(unhexlify('b1d3db3529ad74bc49345c3431d8129ac2')) # full unhexlify('b1d3db3529ad74bc49345c3431d8129ac2dbfc3694ed1530778dd2804271850a7117c371d231916a16dcec8b483da2c88287b0951fd3b6584f44057a66d124a9c9c933f21d9aa641d15dc03d4a'))
if test: ct=BVV(unhexlify('c1bd19dc2b17ed9941e14e9944d7669c7c'))
# full unhexlify('c1bd19dc2b17ed9941e14e9944d7669c7c00d737a8d227eb1404e7ee'))
vp = BVV(b"(This is a test m")
# full BVV(b"(This is a test message, which will be converted by the PX1k into ciphertext\x8d")
# == 285468697320697320612074657374206d6573736167652c2077686963682077696c6c20626520636f6e76657274656420627920746865205058316b20696e746f20636970686572746578748d
if test: vp = BVV(b'(Test asdf 012345')
# full (b'(Test asdf 0123456789aBcDeF\x8d')

s=Solver()

# constrain plaintext to mostly printable ascii chars
b=plaintext.chop(8)
# plaintext most probably starts with 40 - margin
s.add(b[0]==b'(')
# final byte is always `0xd | 0x80`
#s.add(b[-1]==b'\x8d')
# all other bytes are strictly ascii, thus top bit is always 0
for byte in b[1:]: #-1]:
    s.add(byte < 128)
    s.add(Or(byte >= 32, byte == b'\n'))

# initialize lfsr state
lfsr_state = concat([q for i in range(15,0,-1) for q in (~key[i*4+3:i*4], key[i*4+3:i*4])] + [0xf, 0xf])
assert s.solution(lfsr_state, 0xf078d21e0f693c875ac3d2d2692d3cff, extra_constraints=[key == 0x082ef9c7a3229dcf])

# initialize V
k = key.chop(4)
V = concat((
      concat(q for i in range(4) for q in ( ~(k[i+4] ^ k[i]), k[i+4] ^ k[i])),
      concat(q for i in range(8,12) for q in ( ~(k[i+4] ^ k[i]), k[i+4] ^ k[i])),
))
assert s.solution(V, 0x0fe11e69c31e1e2d, extra_constraints=[key == 0x082ef9c7a3229dcf])

# Initialize CTFIFO
v = V.chop(8)
CTFIFO = concat(v[i] ^ v[i+4] ^ 0xf0 for i in range(4))
assert s.solution(CTFIFO, 0x3c0ff0b4, extra_constraints=[key == 0x082ef9c7a3229dcf])

#s.simplify()

for curChar in range(len(ciphertext)//8):
    delta = datetime.timedelta(seconds=time.time() - start)
    print(f'[{curChar:03d}] {str(delta)} adding to constraints', end='')
    lfsr_state = next_lfsr(s, lfsr_state)
    #s.simplify()

    if test:
        if curChar == 0: assert s.solution(lfsr_state, 0xdc5bf4e8330fe0807497b02eb71085b0, extra_constraints=[key == 0x082ef9c7a3229dcf])
        if curChar == 1: assert s.solution(lfsr_state, 0xf3b974ed1cabd9d7f00207e0d8b78e31, extra_constraints=[key == 0x082ef9c7a3229dcf])
        if curChar == 2: assert s.solution(lfsr_state, 0x52db1c7689673312713f5edd43dc84aa, extra_constraints=[key == 0x082ef9c7a3229dcf])

    lfsr_out = concat(lfsr_state.get_byte(i) ^ RotateLeft(lfsr_state.get_byte(i+7),2) for i in range(4))

    if test:
        if curChar == 0: assert s.solution(lfsr_out, 0xde8aaa2a, extra_constraints=[key == 0x082ef9c7a3229dcf])
        if curChar == 1: assert s.solution(lfsr_out, 0xac7a7cf1, extra_constraints=[key == 0x082ef9c7a3229dcf])

    pbuf=[]
    for i in range(4):
        tmp = V.get_byte(i) ^ CTFIFO.get_byte(i)
        acc = map4x4(i, tmp[7:4]).concat(map4x4(i, tmp[3:0]))
        tmp = V.get_byte(i+4)
        pbuf.append(acc ^ tmp)

    pbuf = concat(pbuf)
    if test:
        if curChar == 0: assert s.solution(pbuf, 0xe15ae15a, extra_constraints=[key == 0x082ef9c7a3229dcf])
        if curChar == 1: assert s.solution(pbuf, 0x693cf01c, extra_constraints=[key == 0x082ef9c7a3229dcf])

    acc = concat(F(i, concat((l for j in range(1,4) for l in (lfsr_out.get_byte(j)[i:i], pbuf.get_byte(j)[i:i]) ))) for i in reversed(range(8)))
    if test:
        if curChar == 0: assert s.solution(acc, 0xd6, extra_constraints=[key == 0x082ef9c7a3229dcf])
        if curChar == 1: assert s.solution(acc, 0x31, extra_constraints=[key == 0x082ef9c7a3229dcf])

    #s.simplify()
    k = acc ^ pbuf.get_byte(0) ^ lfsr_out.get_byte(0)

    tmp = (curChar) & 7
    k = RotateLeft(k, tmp)
    if test:
        if curChar == 0:
            assert s.solution(k, 0xe9, extra_constraints=[key == 0x082ef9c7a3229dcf])
            assert s.solution(ciphertext.get_byte(0) ^ k, 40, extra_constraints=[key == 0x082ef9c7a3229dcf])
        if curChar == 1: assert s.solution(k, 0xe9, extra_constraints=[key == 0x082ef9c7a3229dcf])

    s.add(plaintext.get_byte(curChar) == ciphertext.get_byte(curChar) ^ k)

    #s.simplify()

    if test and curChar == 0: assert s.solution(plaintext.get_byte(0), 40, extra_constraints=[key == 0x082ef9c7a3229dcf])

    if not s.solution(plaintext.get_byte(curChar), vp.get_byte(curChar), extra_constraints=[key == vk, ciphertext==ct]):
        print()
        IPython.embed()
    #print(s.constraints)

    # update ciphertext fifo
    c = CTFIFO.chop(8)
    CTFIFO = concat((RotateLeft(c[1], 1), RotateLeft(c[2], 1), RotateLeft(c[3], 1), RotateLeft(ciphertext.get_byte(curChar), 1)))
    if test:
        if curChar == 0: assert s.solution(CTFIFO, 0x1ee16983, extra_constraints=[key == 0x082ef9c7a3229dcf])
        if curChar == 1: assert s.solution(CTFIFO, 0xc3d2077b, extra_constraints=[key == 0x082ef9c7a3229dcf])

    #s.simplify()

    print(f", so far: {len(s.constraints)}")

    if not s.satisfiable(extra_constraints=[ciphertext==ct]):
        delta = datetime.timedelta(seconds=time.time() - start)
        print(f"[X] {str(delta)} meh. we are unsat, are you sure this is a px1k encrypted ciphertext?")
        sys.exit(1)

    if curChar == 16:
        sol = s.eval(key, 1, extra_constraints=[ciphertext == ct])
        delta = datetime.timedelta(seconds=time.time() - start)
        print(f'[!] {str(delta)} we have a solution for the key: {sol[0]:016x}')
        delta = datetime.timedelta(seconds=time.time() - start)
        pt = s.eval(plaintext, 1, extra_constraints=[key == sol[0], ciphertext == ct])
        print(f"[!] {str(delta)} plaintext is:", repr(pt[0].to_bytes(len(plaintext)//8, byteorder='big')))
        #print(s.constraints)
        sys.exit(0)

delta = datetime.timedelta(seconds=time.time() - start)
print(f"[/] {str(delta)} bummer no unambigous solution found, here's 65536 keys")
for k in s.eval(key, 65536, extra_constraints=[ciphertext==ct]):
    print(f"{k:016x}")
