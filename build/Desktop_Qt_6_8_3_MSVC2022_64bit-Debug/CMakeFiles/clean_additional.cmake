# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles\\EloaneDecryptor_autogen.dir\\AutogenUsed.txt"
  "CMakeFiles\\EloaneDecryptor_autogen.dir\\ParseCache.txt"
  "EloaneDecryptor_autogen"
  )
endif()
