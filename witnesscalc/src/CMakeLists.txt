include_directories(
    ../src
    ../build
    ../depends/json/single_include)

link_libraries(${GMP_LIB})

add_definitions(${GMP_DEFINIONS})

if(USE_ASM)
    if(ARCH MATCHES "arm64")
            add_definitions(-DUSE_ASM -DARCH_ARM64)
    elseif(ARCH MATCHES "x86_64")
            add_definitions(-DUSE_ASM -DARCH_X86_64)
    endif()
endif()

if(USE_ASM AND ARCH MATCHES "x86_64")

    if (CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin")
        set(NASM_FLAGS "-fmacho64 --prefix _")
    else()
        set(NASM_FLAGS -felf64)
    endif()

    add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/build/fq_asm.o
        COMMAND nasm ${NASM_FLAGS} fq.asm -o fq_asm.o
        DEPENDS ${CMAKE_SOURCE_DIR}/build/fq.asm
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/build)

    add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/build/fr_asm.o
        COMMAND nasm ${NASM_FLAGS} fr.asm -o fr_asm.o
        DEPENDS ${CMAKE_SOURCE_DIR}/build/fr.asm
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/build)
endif()

set(FR_SOURCES
    ../build/fr.hpp
    ../build/fr.cpp
    )

if(USE_ASM)
    if(ARCH MATCHES "arm64")
        set(FR_SOURCES ${FR_SOURCES} ../build/fr_raw_arm64.s ../build/fr_raw_generic.cpp ../build/fr_generic.cpp)
    elseif(ARCH MATCHES "x86_64")
        set(FR_SOURCES ${FR_SOURCES} ../build/fr_asm.o)
    endif()
else()
    set(FR_SOURCES ${FR_SOURCES} ../build/fr_generic.cpp ../build/fr_raw_generic.cpp)
endif()

add_library(fr STATIC ${FR_SOURCES})
set_target_properties(fr PROPERTIES POSITION_INDEPENDENT_CODE ON)

link_libraries(fr)


#add_executable(tests tests.cpp)
#add_executable(test_platform test_platform.cpp)


set(LIB_SOURCES
    calcwit.cpp
    witnesscalc.h
    witnesscalc.cpp
    )

# presentation_attribute
set(PRESENTATION_ATTRIBUTE_SOURCES ${LIB_SOURCES}
    presentation_attribute.cpp
    witnesscalc_presentation_attribute.h
    witnesscalc_presentation_attribute.cpp
    )
add_library(witnesscalc_presentation_attribute SHARED ${PRESENTATION_ATTRIBUTE_SOURCES})
add_library(witnesscalc_presentation_attributeStatic STATIC ${PRESENTATION_ATTRIBUTE_SOURCES})
set_target_properties(witnesscalc_presentation_attributeStatic PROPERTIES OUTPUT_NAME presentation_attribute)
add_executable(presentation_attribute main.cpp)
target_link_libraries(presentation_attribute witnesscalc_presentation_attributeStatic)
target_compile_definitions(witnesscalc_presentation_attribute PUBLIC CIRCUIT_NAME=presentation_attribute)
target_compile_definitions(witnesscalc_presentation_attributeStatic PUBLIC CIRCUIT_NAME=presentation_attribute)
target_compile_definitions(presentation_attribute PUBLIC CIRCUIT_NAME=presentation_attribute)

# presentation_range
set(PRESENTATION_RANGE_SOURCES ${LIB_SOURCES}
    presentation_range.cpp
    witnesscalc_presentation_range.h
    witnesscalc_presentation_range.cpp
    )
add_library(witnesscalc_presentation_range SHARED ${PRESENTATION_RANGE_SOURCES})
add_library(witnesscalc_presentation_rangeStatic STATIC ${PRESENTATION_RANGE_SOURCES})
set_target_properties(witnesscalc_presentation_rangeStatic PROPERTIES OUTPUT_NAME presentation_range)
add_executable(presentation_range main.cpp)
target_link_libraries(presentation_range witnesscalc_presentation_rangeStatic)
target_compile_definitions(witnesscalc_presentation_range PUBLIC CIRCUIT_NAME=presentation_range)
target_compile_definitions(witnesscalc_presentation_rangeStatic PUBLIC CIRCUIT_NAME=presentation_range)
target_compile_definitions(presentation_range PUBLIC CIRCUIT_NAME=presentation_range)

# presentation_polygon
set(PRESENTATION_POLYGON_SOURCES ${LIB_SOURCES}
    presentation_polygon.cpp
    witnesscalc_presentation_polygon.h
    witnesscalc_presentation_polygon.cpp
    )
add_library(witnesscalc_presentation_polygon SHARED ${PRESENTATION_POLYGON_SOURCES})
add_library(witnesscalc_presentation_polygonStatic STATIC ${PRESENTATION_POLYGON_SOURCES})
set_target_properties(witnesscalc_presentation_polygonStatic PROPERTIES OUTPUT_NAME presentation_polygon)
add_executable(presentation_polygon main.cpp)
target_link_libraries(presentation_polygon witnesscalc_presentation_polygonStatic)
target_compile_definitions(witnesscalc_presentation_polygon PUBLIC CIRCUIT_NAME=presentation_polygon)
target_compile_definitions(witnesscalc_presentation_polygonStatic PUBLIC CIRCUIT_NAME=presentation_polygon)
target_compile_definitions(presentation_polygon PUBLIC CIRCUIT_NAME=presentation_polygon)

# presentation_delegation
set(PRESENTATION_DELEGATION_SOURCES ${LIB_SOURCES}
    presentation_delegation.cpp
    witnesscalc_presentation_delegation.h
    witnesscalc_presentation_delegation.cpp
    )
add_library(witnesscalc_presentation_delegation SHARED ${PRESENTATION_DELEGATION_SOURCES})
add_library(witnesscalc_presentation_delegationStatic STATIC ${PRESENTATION_DELEGATION_SOURCES})
set_target_properties(witnesscalc_presentation_delegationStatic PROPERTIES OUTPUT_NAME presentation_delegation)
add_executable(presentation_delegation main.cpp)
target_link_libraries(presentation_delegation witnesscalc_presentation_delegationStatic)
target_compile_definitions(witnesscalc_presentation_delegation PUBLIC CIRCUIT_NAME=presentation_delegation)
target_compile_definitions(witnesscalc_presentation_delegationStatic PUBLIC CIRCUIT_NAME=presentation_delegation)
target_compile_definitions(presentation_delegation PUBLIC CIRCUIT_NAME=presentation_delegation)


# poseidon_bench
set(POSEIDON_BENCH_SOURCES ${LIB_SOURCES}
    poseidon_bench.cpp
    witnesscalc_poseidon_bench.h
    witnesscalc_poseidon_bench.cpp
    )
add_library(witnesscalc_poseidon_bench SHARED ${POSEIDON_BENCH_SOURCES})
add_library(witnesscalc_poseidon_benchStatic STATIC ${POSEIDON_BENCH_SOURCES})
set_target_properties(witnesscalc_poseidon_benchStatic PROPERTIES OUTPUT_NAME poseidon_bench)
add_executable(poseidon_bench main.cpp)
target_link_libraries(poseidon_bench witnesscalc_poseidon_benchStatic)
target_compile_definitions(witnesscalc_poseidon_bench PUBLIC CIRCUIT_NAME=poseidon_bench)
target_compile_definitions(witnesscalc_poseidon_benchStatic PUBLIC CIRCUIT_NAME=poseidon_bench)
target_compile_definitions(poseidon_bench PUBLIC CIRCUIT_NAME=poseidon_bench)
