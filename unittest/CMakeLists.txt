# Create variable in caller scope name where
# "." are converted into "_" in input_file.
function(make_cxx_name input_file name)
#  string(REGEX REPLACE "\\." "_" ${name} ${input_file})
  string(REPLACE "." "_" ${name} ${input_file})
  set(${name} ${${name}} PARENT_SCOPE)
endfunction()

function(make_includable input_file output_file cxx_name)
  file(READ ${input_file} content)
  set(delim "for_c++_include")
  set(content
      "static const char ${cxx_name}[] = R\"${delim}(\n${content})${delim}\";"
    )
  file(WRITE ${output_file} "#pragma once\n${content}\n")
endfunction()

function(dat_to_h files)
  foreach(f ${files})
    get_filename_component(basename ${f} NAME)
    make_cxx_name(${basename} cxx_name)
    message("** Creating ${basename}.h with cxx name ${cxx_name}")
    make_includable(${f} "${CMAKE_BINARY_DIR}/inc/${basename}.h" ${cxx_name})
  endforeach()
endfunction()

function(create_resource_h data_files)
  message("** Creating resource.h")
  set(resource_file ${CMAKE_BINARY_DIR}/inc/resource.h)
  file(WRITE ${resource_file} "#pragma once\n")

  foreach(f ${data_files})
    get_filename_component(basename ${f} NAME)
    file(APPEND ${resource_file} "#include \"${basename}.h\"\n")
  endforeach()

  file(APPEND ${resource_file} "\n")

  file(APPEND ${resource_file}
    "static inline\n"
    )

  file(APPEND ${resource_file}
    "size_t GetResourceBytes(const char *resourceName, const char **bytes)\n{\n"
    )

  set(t "    ")

  foreach(f ${data_files})
    get_filename_component(basename ${f} NAME)
    make_cxx_name(${basename} cxx_name)
    file(APPEND ${resource_file}
      "${t}if (strcasecmp(resourceName, \"${basename}\") == 0) {\n"
      )
    file(APPEND ${resource_file}
      "${t}${t}*bytes = ${cxx_name};\n"
      )
    file(APPEND ${resource_file}
      "${t}${t}return sizeof(${cxx_name});\n"
      )
    file(APPEND ${resource_file}
      "${t}}\n"
      )
  endforeach()
  file(APPEND ${resource_file}
    "${t}return 0;\n}\n"
    )
endfunction()

file(GLOB DATA_FILES *.dat)

if(NOT WIN32)
    dat_to_h("${DATA_FILES}")
    create_resource_h("${DATA_FILES}")
endif()

if(WIN32 AND CMAKE_SYSTEM_PROCESSOR MATCHES "X86")
  # Required on x86 to avoid "error LNK2026: module unsafe for SAFESEH image."
  add_link_options(/SAFESEH:NO)
endif()

include_directories(${CMAKE_SOURCE_DIR}/unittest/inc)
include_directories(${CMAKE_SOURCE_DIR}/unittest/lib)
include_directories(${CMAKE_SOURCE_DIR}/unittest/resource)

add_subdirectory(lib)

if(WIN32)
  add_subdirectory(exe_test)
  add_subdirectory(exe_legacy)
  add_subdirectory(exe_Win7nlater)
  add_subdirectory(exe_Win8_1nLater)
else()
  add_subdirectory(exe_linux)

  if(NOT SYMCRYPT_TARGET_ENV MATCHES "Generic" AND NOT CMAKE_BUILD_TYPE MATCHES Sanitize)
    add_subdirectory(exe_moduletest)
  endif()
endif()