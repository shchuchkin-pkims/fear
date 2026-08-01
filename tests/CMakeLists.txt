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
add_fear_test(test_key_schedule test_key_schedule.c ${IDENTITY_DIR}/key_schedule.c)
add_fear_test(test_rotation     test_rotation.c     ${IDENTITY_DIR}/rotation.c)
add_fear_test(test_media_keys   test_media_keys.c   ${IDENTITY_DIR}/media_keys.c)
add_fear_test(test_media_hello  test_media_hello.c  ${IDENTITY_DIR}/media_hello.c ${IDENTITY_DIR}/media_keys.c)
add_fear_test(test_media_senders test_media_senders.c ${IDENTITY_DIR}/media_senders.c ${IDENTITY_DIR}/media_keys.c)
add_fear_test(test_call_invite  test_call_invite.c  ${IDENTITY_DIR}/call_invite.c ${IDENTITY_DIR}/media_keys.c)
add_fear_test(test_media_packet test_media_packet.c ${IDENTITY_DIR}/media_packet.c ${IDENTITY_DIR}/media_keys.c)
add_fear_test(test_chat_frame   test_chat_frame.c   ${IDENTITY_DIR}/chat_frame.c ${IDENTITY_DIR}/key_schedule.c)

# Разборщики, которые видят сеть до всякой аутентификации. Санитайзеры
# включены только для этой цели: собирать под ними весь проект дорого, а
# ловить нечего - остальное не читает чужие байты вслепую.
add_fear_test(fuzz_parsers fuzz_parsers.c
    ${IDENTITY_DIR}/media_hello.c ${IDENTITY_DIR}/media_keys.c
    ${IDENTITY_DIR}/media_packet.c ${IDENTITY_DIR}/call_invite.c
    ${IDENTITY_DIR}/chat_frame.c ${IDENTITY_DIR}/key_schedule.c
    ${CMAKE_SOURCE_DIR}/client-console/src/common.c)
target_include_directories(fuzz_parsers PRIVATE ${CMAKE_SOURCE_DIR}/client-console/include)
# check_c_compiler_flag only compiles, and these flags need the runtime at
# link time - it reported success while the binary came out without a trace
# of a sanitizer in it.
include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-fsanitize=address,undefined")
set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=address,undefined")
check_c_source_compiles("int main(void){return 0;}" HAVE_ASAN_UBSAN)
unset(CMAKE_REQUIRED_FLAGS)
unset(CMAKE_REQUIRED_LINK_OPTIONS)
if(HAVE_ASAN_UBSAN)
    target_compile_options(fuzz_parsers PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(fuzz_parsers PRIVATE -fsanitize=address,undefined)
endif()
set_tests_properties(fuzz_parsers PROPERTIES TIMEOUT 120)

# Интеграционный smoke-тест: сервер + два консольных клиента (ECDH create/join,
# доставка сообщений в обе стороны). Требует собранного таргета fear.
add_test(NAME integration_smoke
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/smoke_chat.sh $<TARGET_FILE:fear>)
set_tests_properties(integration_smoke PROPERTIES TIMEOUT 60)

# Трёхсторонний медиа-loopback: три процесса через hub, каждый расшифровывает
# двух других. Единственный тест, способный поймать инверсию ролей или
# несогласованную соль - модульные тесты живут внутри одного процесса.
#
# Регистрируются только когда соответствующие таргеты вообще собираются.
# При FEAR_GUI_ONLY=ON подпроекты audio_call/video_call пропускаются, и
# безусловный $<TARGET_FILE:audio_call> валит не тест, а саму генерацию
# сборки - то есть все четыре пайплайна разом, ещё до компиляции.
if(TARGET audio_call)
    add_test(NAME media_loopback
             COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/media_loopback.sh $<TARGET_FILE:audio_call>)
    set_tests_properties(media_loopback PROPERTIES TIMEOUT 120)
endif()

# То же для video_call: три процесса, аудио-тракт через пер-отправительские
# декодеры и микшер. Видео здесь не проверяется - на машине без камеры и
# дисплея VP8 не кодируется вовсе, и тест об этом честно молчит.
if(TARGET video_call)
    add_test(NAME video_loopback
             COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/video_loopback.sh $<TARGET_FILE:video_call>)
    set_tests_properties(video_loopback PROPERTIES TIMEOUT 120)
endif()

# Протокольный тест M10: BLOB_GET доступен только владельцу pk (подписанный
# challenge). Бинарь ходит на живой сервер через реальные sp_*-функции;
# сервер поднимает обёртка blob_auth.sh.
add_executable(test_blob_auth test_blob_auth.c
    ${IDENTITY_DIR}/identity.c
    ${IDENTITY_DIR}/server_proto.c)
target_include_directories(test_blob_auth PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${IDENTITY_DIR}
    ${TEST_SODIUM_INCLUDE})
target_link_libraries(test_blob_auth PRIVATE ${TEST_SODIUM_LIBS})
add_test(NAME blob_auth
         COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/blob_auth.sh
                 $<TARGET_FILE:fear> $<TARGET_FILE:test_blob_auth>)
set_tests_properties(blob_auth PROPERTIES TIMEOUT 60)
