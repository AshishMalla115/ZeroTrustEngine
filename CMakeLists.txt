cmake_minimum_required(VERSION 3.16)
project(ZeroTrustEngine C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

add_library(riskscore SHARED
	src/risk_engine.c
	src/scoring.c
	src/profile.c
	src/session.c
)

add_executable(test_engine
	tests/main.c
)

target_link_libraries(test_engine riskscore)
