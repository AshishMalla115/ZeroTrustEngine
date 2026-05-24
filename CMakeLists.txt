cmake_minimum_required(VERSION 3.16)
project(ZeroTrustEngine C)

set(CMAKE_C_STANDARD 11)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

include_directories(include)

add_library(riskscore SHARED
	src/risk_engine.c
	src/scoring.c
	src/profile.c
	src/session.c
	src/security.c
	src/model.c
)

add_executable(test_engine
	tests/main.c
)

target_link_libraries(riskscore OpenSSL::Crypto)
target_link_libraries(test_engine riskscore)
target_link_libraries(test_engine OpenSSL::Crypto)
target_link_libraries(riskscore Threads::Threads)
target_link_libraries(riskscore m)
