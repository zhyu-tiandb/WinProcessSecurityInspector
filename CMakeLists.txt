cmake_minimum_required(VERSION 3.20)

project(WinProcessSecurityInspector
    VERSION 0.1.0
    DESCRIPTION "Windows process security context and desktop session diagnostic tool"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

option(WPSI_BUILD_CLI "Build WPSI command line tool" ON)
option(WPSI_BUILD_GUI "Build WPSI Qt GUI" OFF)
option(WPSI_BUILD_TESTS "Build WPSI tests" ON)

add_library(wpsi_core INTERFACE)

target_include_directories(wpsi_core
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(wpsi_core
    INTERFACE
        Advapi32
        User32
        Wintrust
)

if(WPSI_BUILD_CLI)
    add_executable(wpsi_cli
        src/cli/main.cpp
    )

    target_link_libraries(wpsi_cli
        PRIVATE
            wpsi_core
    )
endif()

if(WPSI_BUILD_TESTS)
    enable_testing()

    add_test(
        NAME wpsi_verify_msvc_runtime
        COMMAND ${CMAKE_COMMAND}
            -DCMAKE_MSVC_RUNTIME_LIBRARY=${CMAKE_MSVC_RUNTIME_LIBRARY}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/verify_msvc_runtime.cmake
    )

    add_executable(wpsi_unit_tests
        tests/unit/test_phase1_core.cpp
    )

    target_link_libraries(wpsi_unit_tests
        PRIVATE
            wpsi_core
    )

    add_test(NAME wpsi_unit_tests COMMAND wpsi_unit_tests)

    add_executable(wpsi_integration_tests
        tests/integration/test_current_process_inspection.cpp
    )

    target_link_libraries(wpsi_integration_tests
        PRIVATE
            wpsi_core
    )

    add_test(NAME wpsi_integration_tests COMMAND wpsi_integration_tests)

    if(WPSI_BUILD_CLI)
        add_test(NAME wpsi_cli_inspect COMMAND wpsi_cli inspect)
        set_tests_properties(wpsi_cli_inspect PROPERTIES
            PASS_REGULAR_EXPRESSION "PID"
        )

        add_test(NAME wpsi_cli_inspect_json COMMAND wpsi_cli inspect --format json)
        set_tests_properties(wpsi_cli_inspect_json PROPERTIES
            PASS_REGULAR_EXPRESSION "\"processes\""
        )

        add_test(NAME wpsi_cli_compare_self COMMAND wpsi_cli compare --pid 0 --pid 0)
        set_tests_properties(wpsi_cli_compare_self PROPERTIES
            PASS_REGULAR_EXPRESSION "Source Name"
        )

        add_test(NAME wpsi_cli_compare_name_self COMMAND wpsi_cli compare --name wpsi_cli.exe --name wpsi_cli.exe)
        set_tests_properties(wpsi_cli_compare_name_self PROPERTIES
            PASS_REGULAR_EXPRESSION "Comparison"
        )

        add_test(NAME wpsi_cli_compare_name_pid_self COMMAND wpsi_cli compare --name wpsi_cli.exe --pid 0)
        set_tests_properties(wpsi_cli_compare_name_pid_self PROPERTIES
            PASS_REGULAR_EXPRESSION "Comparison"
        )

        add_test(
            NAME wpsi_cli_json_output_file
            COMMAND powershell -NoProfile -ExecutionPolicy Bypass -Command
                "$out = Join-Path $env:CTEST_BINARY_DIRECTORY 'wpsi-inspect-output.json'; Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue; $exe = Join-Path $env:CTEST_BINARY_DIRECTORY 'Debug/wpsi_cli.exe'; & $exe inspect --format json --output $out; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; if (!(Test-Path -LiteralPath $out)) { exit 10 }; $text = Get-Content -Raw -LiteralPath $out; if ($text -notmatch '\"processes\"') { exit 11 }"
        )

        add_test(NAME wpsi_cli_inspect_name COMMAND wpsi_cli inspect --name wpsi_cli.exe --format json)
        set_tests_properties(wpsi_cli_inspect_name PROPERTIES
            PASS_REGULAR_EXPRESSION "\"processes\""
        )

        add_test(NAME wpsi_cli_inspect_name_text COMMAND wpsi_cli inspect --name wpsi_cli.exe)
        set_tests_properties(wpsi_cli_inspect_name_text PROPERTIES
            PASS_REGULAR_EXPRESSION "Session ID"
        )

        add_test(NAME wpsi_cli_windows_self COMMAND wpsi_cli windows --pid 0)
        set_tests_properties(wpsi_cli_windows_self PROPERTIES
            PASS_REGULAR_EXPRESSION "Windows"
        )

        add_test(NAME wpsi_cli_tree_self COMMAND wpsi_cli tree --pid 0)
        set_tests_properties(wpsi_cli_tree_self PROPERTIES
            PASS_REGULAR_EXPRESSION "Tree"
        )

        add_test(NAME wpsi_cli_browser_self COMMAND wpsi_cli browser --network-pid 0 --format json)
        set_tests_properties(wpsi_cli_browser_self PROPERTIES
            PASS_REGULAR_EXPRESSION "\"browser\""
        )

        add_test(
            NAME wpsi_cli_markdown_output_file
            COMMAND powershell -NoProfile -ExecutionPolicy Bypass -Command
                "$out = Join-Path $env:CTEST_BINARY_DIRECTORY 'wpsi-inspect-output.md'; Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue; $exe = Join-Path $env:CTEST_BINARY_DIRECTORY 'Debug/wpsi_cli.exe'; & $exe inspect --format markdown --output $out; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; if (!(Test-Path -LiteralPath $out)) { exit 10 }; $text = Get-Content -Raw -LiteralPath $out; if ($text -notmatch 'WPSI Diagnosis Report') { exit 11 }"
        )

        add_test(
            NAME wpsi_cli_html_output_file
            COMMAND powershell -NoProfile -ExecutionPolicy Bypass -Command
                "$out = Join-Path $env:CTEST_BINARY_DIRECTORY 'wpsi-inspect-output.html'; Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue; $exe = Join-Path $env:CTEST_BINARY_DIRECTORY 'Debug/wpsi_cli.exe'; & $exe inspect --format html --output $out; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; if (!(Test-Path -LiteralPath $out)) { exit 10 }; $text = Get-Content -Raw -LiteralPath $out; if ($text -notmatch '<!doctype html>') { exit 11 }"
        )
    endif()
endif()
