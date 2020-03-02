cmake_minimum_required(VERSION 3.7)
project(nginx_js C)

set(CMAKE_C_STANDARD 11)


add_library(nginx_js SHARED library.c)

target_include_directories(
        nginx_js
        PUBLIC
        /home/simon/Downloads/nginx-1.16.1/objs
        /home/simon/Downloads/nginx-1.16.1/src
        /home/simon/Downloads/nginx-1.16.1/src/core
        /home/simon/Downloads/nginx-1.16.1/src/event
        /home/simon/Downloads/nginx-1.16.1/src/http
        /home/simon/Downloads/nginx-1.16.1/src/http/modules
        /home/simon/Downloads/nginx-1.16.1/src/misc
        /home/simon/Downloads/nginx-1.16.1/src/os/unix
        /home/simon/Downloads/nginx-1.16.1/src/stream
)
