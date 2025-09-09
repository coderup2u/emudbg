cmake_minimum_required(VERSION 3.8)

project(emudbg LANGUAGES C CXX ASM_MASM)
set(CMAKE_CXX_STANDARD 17)

# Check MSVC for ASM
if(MSVC)
    set_source_files_properties(asm_function.asm PROPERTIES LANGUAGE ASM_MASM)
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to Release by default")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()

# Create the main executable
add_executable(emudbg "emudbg.cpp" "headers/CPU.hpp" "headers/PE.hpp" "headers/Registers.hpp" "headers/SaveRVA.hpp" "headers/Structs.hpp" "headers/XState.hpp" "asm_function.asm")

# Optional: Use C++20 if available
if (CMAKE_VERSION VERSION_GREATER 3.12)
    set_property(TARGET emudbg PROPERTY CXX_STANDARD 20)
endif()

include_directories(headers/)
target_link_libraries(emudbg PRIVATE
    $<$<CONFIG:Debug>:${CMAKE_SOURCE_DIR}/libs/zydis_wrapper_d.lib>
    $<$<CONFIG:Release>:${CMAKE_SOURCE_DIR}/libs/zydis_wrapper.lib>
)
