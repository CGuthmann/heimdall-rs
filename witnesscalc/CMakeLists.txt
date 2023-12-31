cmake_minimum_required(VERSION 3.5)

include(cmake/platform.cmake)

set(USE_ASM ON CACHE BOOL "Use asm implementation for Fr and Fq")

project(witnesscalc LANGUAGES CXX ASM)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

message("USE_ASM=" ${USE_ASM})
message("CMAKE_CROSSCOMPILING=" ${CMAKE_CROSSCOMPILING})

message("GMP_PREFIX=" ${GMP_PREFIX})
message("GMP_INCLUDE_DIR=" ${GMP_INCLUDE_DIR})
message("GMP_LIB_DIR=" ${GMP_LIB_DIR})

if (NOT EXISTS ${GMP_INCLUDE_FILE_FULLPATH})
    message("WARNING: ${GMP_INCLUDE_FILE_FULLPATH} is not found and so system ${GMP_INCLUDE_FILE} is used.")
endif()

if (NOT EXISTS ${GMP_LIB_FILE_FULLPATH})
    message("WARNING: ${GMP_LIB_FILE_FULLPATH} is not found and so system ${GMP_LIB_FILE} is used.")
    set(GMP_LIB gmp)
endif()


include_directories(BEFORE ${GMP_INCLUDE_DIR})

add_subdirectory(src)


install(TARGETS
    presentation_attribute
    witnesscalc_presentation_attribute
    witnesscalc_presentation_attributeStatic
    presentation_range
    witnesscalc_presentation_range
    witnesscalc_presentation_rangeStatic
    presentation_polygon
    witnesscalc_presentation_polygon
    witnesscalc_presentation_polygonStatic
    presentation_delegation
    witnesscalc_presentation_delegation
    witnesscalc_presentation_delegationStatic
    poseidon_bench
    witnesscalc_poseidon_bench
    witnesscalc_poseidon_benchStatic
    fr
    RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    BUNDLE DESTINATION ${CMAKE_INSTALL_PREFIX}/app
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)

install(FILES "${GMP_LIB_DIR}/${GMP_LIB_FILE}"
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)

install(FILES
    src/presentation_attribute.dat
    src/presentation_range.dat
    src/presentation_polygon.dat
    src/presentation_delegation.dat
    src/poseidon_bench.dat
    DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)

install(FILES
    src/witnesscalc.h
    src/witnesscalc_presentation_attribute.h
    src/witnesscalc_presentation_range.h
    src/witnesscalc_presentation_polygon.h
    src/witnesscalc_presentation_delegation.h
    src/witnesscalc_poseidon_bench.h
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
