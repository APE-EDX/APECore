file(GLOB CPP_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
file(GLOB HPP_INCLUDES ${PROJECT_SOURCE_DIR}/include/*.hpp)
set(ALL_SOURCES ${CPP_SOURCES} ${HPP_SOURCES} ${DUKTAPE_SOURCES})

include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}

    ${DUKTAPE_INCLUDE}
    ${PROJECT_SOURCE_DIR}/deps/capstone/include
)

add_library(APECore STATIC ${ALL_SOURCES})

if(UNIX)
    set_target_properties(capstone-static PROPERTIES
        POSITION_INDEPENDENT_CODE ON
    )
endif()

target_link_libraries(APECore PUBLIC capstone-static)
target_compile_features(APECore PRIVATE cxx_range_for)

if("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
    set(ARCH_BITS 64)
    add_definitions("-DBUILD_64")
else ()
    set(ARCH_BITS 32)
endif()

set(OUTPUT_NAME "APECore_${ARCH_BITS}")
set_target_properties(APECore PROPERTIES
    OUTPUT_NAME ${OUTPUT_NAME}
    POSITION_INDEPENDENT_CODE ON
    ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin
    ARCHIVE_OUTPUT_DIRECTORY_DEBUG ${PROJECT_SOURCE_DIR}/bin
    ARCHIVE_OUTPUT_DIRECTORY_RELEASE ${PROJECT_SOURCE_DIR}/bin
)
