cmake_minimum_required(VERSION 3.18...3.22)
project(rspcode)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.14)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# Detect the installed nanobind package and import it into CMake
# execute_process(
# COMMAND "${Python_EXECUTABLE}" -c "import nanobind; print(nanobind.cmake_dir())"
# OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE NB_DIR)
# list(APPEND CMAKE_PREFIX_PATH "${NB_DIR}")
# find_package(nanobind CONFIG REQUIRED)
if(MSVC)
  add_compile_options(/O2 /D_HAS_STD_BYTE=0 /DLOCAL_ZLIB=1 /DNO_GZIP=1)
else()
  add_compile_options(-O3 -Wall -Wno-sign-compare -D__TERMINAL__ -DLOCAL_ZLIB=1 -DNO_GZIP=1)
endif()

include_directories(thirdparty)

set(ZLIB
  zlib/adler32.c
  zlib/deflate.c
  zlib/inffast.c
  zlib/inflate.c
  zlib/inftrees.c
  zlib/trees.c
  zlib/zutil.c
)

set(SLEIGH_COMMON
  sleigh/address.cc
  sleigh/compression.cc
  sleigh/context.cc
  sleigh/float.cc
  sleigh/globalcontext.cc
  sleigh/marshal.cc
  sleigh/opcodes.cc
  sleigh/pcodecompile.cc
  sleigh/pcodeparse.cc
  sleigh/pcoderaw.cc
  sleigh/semantics.cc
  sleigh/slaformat.cc
  sleigh/sleigh.cc
  sleigh/sleighbase.cc
  sleigh/slghpatexpress.cc
  sleigh/slghpattern.cc
  sleigh/slghsymbol.cc
  sleigh/space.cc
  sleigh/translate.cc
  sleigh/xml.cc
)

add_executable(sleigh
  sleigh/filemanage.cc
  sleigh/slgh_compile.cc
  sleigh/slghparse.cc
  sleigh/slghscan.cc
  ${SLEIGH_COMMON}
  ${ZLIB}
)
install(TARGETS sleigh DESTINATION bin)

add_library(rspcode_native
  simple_context.cpp
  ${SLEIGH_COMMON}
  ${ZLIB}
)
install(TARGETS rspcode_native DESTINATION .)

install(DIRECTORY processors DESTINATION .)
