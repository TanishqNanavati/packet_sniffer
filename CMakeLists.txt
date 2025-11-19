cmake_minimum_required(VERSION 3.5)
project(TCP_IP_STACK C)

# Use C11
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Compiler warnings (optional)
if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Sources
set(SRC_FILES
  main.c
  src/parser.c
  src/sniffer.c
  src/pcap_writer.c
  src/util.c
)

# Executable
add_executable(sniffer ${SRC_FILES})

# Include headers directory
target_include_directories(sniffer PRIVATE
  ${CMAKE_SOURCE_DIR}/headers
)

# Expose _GNU_SOURCE for sniffer.c if needed
target_compile_definitions(sniffer PRIVATE _GNU_SOURCE=1)

# Link pthread on UNIX systems (not strictly required for this code but harmless)
if (UNIX)
  target_link_libraries(sniffer PRIVATE pthread)
endif()

# Optional installation
install(TARGETS sniffer RUNTIME DESTINATION bin)