# Хранилище секретов платформы, которым обёрнут ключ личности на диске
# (identity/identity_at_rest.c).
#
# Живёт отдельным модулем, потому что подключается из двух мест: корневого
# проекта и gui/src, который собирается самостоятельно. Определение в одном
# из них означало бы, что второй не линкуется, - ровно так и вышло в первый
# раз.
#
# Зависимость необязательная: без неё файл остаётся в том же виде, в каком
# был всегда, и код это оговаривает вслух. Отсутствие libsecret - не ошибка
# сборки: headless-машины и контейнеры существуют, и отказываться там
# работать было бы хуже.

if(TARGET fear_secret_store)
    return()
endif()

add_library(fear_secret_store INTERFACE)

if(WIN32)
    # DPAPI: CryptProtectData / CryptUnprotectData.
    target_link_libraries(fear_secret_store INTERFACE crypt32)
else()
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBSECRET libsecret-1)
    endif()
    if(LIBSECRET_FOUND)
        target_compile_definitions(fear_secret_store INTERFACE FEAR_HAVE_LIBSECRET)
        target_include_directories(fear_secret_store INTERFACE ${LIBSECRET_INCLUDE_DIRS})
        target_link_libraries(fear_secret_store INTERFACE ${LIBSECRET_LIBRARIES})
        message(STATUS "libsecret found - the identity key is wrapped at rest")
    else()
        message(STATUS "libsecret not found - the identity key stays in the clear on disk")
    endif()
endif()
