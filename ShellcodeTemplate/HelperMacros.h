// (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
#pragma once

#define PP_STR(x) #x
#define PP_STR(x) #x
#define PP_CONCATENATE(x, y) x ## y
#define PP_CONCAT(x, y) PP_CONCATENATE(x, y)
#define PP_ADD_SUFFIX(func, T) PP_CONCAT(func, PP_CONCAT(_, T))
#define PP_UNUSED_VAR(var) (void)(var)
#define PP_EMPTY
#define PP_DEFINE_POINTER(T) typedef T* PP_CONCAT(P, T)
