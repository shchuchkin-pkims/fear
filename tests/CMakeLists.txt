# Юнит-тесты чистой крипто-логики: identity, encrypted backup, contacts cipher.
# Собираются только на POSIX - харнесс использует mkdtemp/stat, а CI гоняет
# тесты на Linux (Windows-сборка идёт с FEAR_GUI_ONLY и тесты не строит).
if(WIN32)
    return()
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM libsodium)
if(LIBSODIUM_FOUND)
    set(TEST_SODIUM_LIBS ${LIBSODIUM_LIBRARIES})
    set(TEST_SODIUM_INCLUDE ${LIBSODIUM_INCLUDE_DIRS})
else()
    find_library(SODIUM_LIB sodium)
    find_path(SODIUM_INCLUDE_DIR sodium.h PATH_SUFFIXES sodium)
    if(NOT SODIUM_LIB)
        message(FATAL_ERROR "libsodium is required for tests. Install with: sudo apt-get install libsodium-dev")
    endif()
    set(TEST_SODIUM_LIBS ${SODIUM_LIB})
    set(TEST_SODIUM_INCLUDE ${SODIUM_INCLUDE_DIR})
endif()

set(IDENTITY_DIR ${CMAKE_SOURCE_DIR}/identity)

function(add_fear_test name)
    add_executable(${name} ${ARGN})
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${IDENTITY_DIR}
        ${TEST_SODIUM_INCLUDE})
    target_link_libraries(${name} PRIVATE ${TEST_SODIUM_LIBS})
    add_test(NAME ${name} COMMAND ${name})
endfunction()

add_fear_test(test_identity test_identity.c ${IDENTITY_DIR}/identity.c)
add_fear_test(test_backup   test_backup.c   ${IDENTITY_DIR}/identity_backup.c ${IDENTITY_DIR}/identity.c)
add_fear_test(test_contacts test_contacts.c ${IDENTITY_DIR}/contacts_cipher.c)

# Интеграционный smoke-тест: сервер + два консольных клиента (ECDH create/join,
# доставка сообщений в обе стороны). Требует собранного таргета fear.
add_test(NAME integration_smoke
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/smoke_chat.sh $<TARGET_FILE:fear>)
set_tests_properties(integration_smoke PROPERTIES TIMEOUT 60)
