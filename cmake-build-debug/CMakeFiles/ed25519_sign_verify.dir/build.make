# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.15

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /snap/clion/99/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /snap/clion/99/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/haojun/Developer/ed25519_sign_verify

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/haojun/Developer/ed25519_sign_verify/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/ed25519_sign_verify.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/ed25519_sign_verify.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ed25519_sign_verify.dir/flags.make

CMakeFiles/ed25519_sign_verify.dir/main.c.o: CMakeFiles/ed25519_sign_verify.dir/flags.make
CMakeFiles/ed25519_sign_verify.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haojun/Developer/ed25519_sign_verify/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/ed25519_sign_verify.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ed25519_sign_verify.dir/main.c.o   -c /home/haojun/Developer/ed25519_sign_verify/main.c

CMakeFiles/ed25519_sign_verify.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ed25519_sign_verify.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/haojun/Developer/ed25519_sign_verify/main.c > CMakeFiles/ed25519_sign_verify.dir/main.c.i

CMakeFiles/ed25519_sign_verify.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ed25519_sign_verify.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/haojun/Developer/ed25519_sign_verify/main.c -o CMakeFiles/ed25519_sign_verify.dir/main.c.s

CMakeFiles/ed25519_sign_verify.dir/src/verify.c.o: CMakeFiles/ed25519_sign_verify.dir/flags.make
CMakeFiles/ed25519_sign_verify.dir/src/verify.c.o: ../src/verify.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haojun/Developer/ed25519_sign_verify/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/ed25519_sign_verify.dir/src/verify.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ed25519_sign_verify.dir/src/verify.c.o   -c /home/haojun/Developer/ed25519_sign_verify/src/verify.c

CMakeFiles/ed25519_sign_verify.dir/src/verify.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ed25519_sign_verify.dir/src/verify.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/haojun/Developer/ed25519_sign_verify/src/verify.c > CMakeFiles/ed25519_sign_verify.dir/src/verify.c.i

CMakeFiles/ed25519_sign_verify.dir/src/verify.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ed25519_sign_verify.dir/src/verify.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/haojun/Developer/ed25519_sign_verify/src/verify.c -o CMakeFiles/ed25519_sign_verify.dir/src/verify.c.s

CMakeFiles/ed25519_sign_verify.dir/src/sign.c.o: CMakeFiles/ed25519_sign_verify.dir/flags.make
CMakeFiles/ed25519_sign_verify.dir/src/sign.c.o: ../src/sign.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haojun/Developer/ed25519_sign_verify/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/ed25519_sign_verify.dir/src/sign.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ed25519_sign_verify.dir/src/sign.c.o   -c /home/haojun/Developer/ed25519_sign_verify/src/sign.c

CMakeFiles/ed25519_sign_verify.dir/src/sign.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ed25519_sign_verify.dir/src/sign.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/haojun/Developer/ed25519_sign_verify/src/sign.c > CMakeFiles/ed25519_sign_verify.dir/src/sign.c.i

CMakeFiles/ed25519_sign_verify.dir/src/sign.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ed25519_sign_verify.dir/src/sign.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/haojun/Developer/ed25519_sign_verify/src/sign.c -o CMakeFiles/ed25519_sign_verify.dir/src/sign.c.s

# Object files for target ed25519_sign_verify
ed25519_sign_verify_OBJECTS = \
"CMakeFiles/ed25519_sign_verify.dir/main.c.o" \
"CMakeFiles/ed25519_sign_verify.dir/src/verify.c.o" \
"CMakeFiles/ed25519_sign_verify.dir/src/sign.c.o"

# External object files for target ed25519_sign_verify
ed25519_sign_verify_EXTERNAL_OBJECTS =

ed25519_sign_verify: CMakeFiles/ed25519_sign_verify.dir/main.c.o
ed25519_sign_verify: CMakeFiles/ed25519_sign_verify.dir/src/verify.c.o
ed25519_sign_verify: CMakeFiles/ed25519_sign_verify.dir/src/sign.c.o
ed25519_sign_verify: CMakeFiles/ed25519_sign_verify.dir/build.make
ed25519_sign_verify: /usr/lib/x86_64-linux-gnu/libcrypto.a
ed25519_sign_verify: CMakeFiles/ed25519_sign_verify.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/haojun/Developer/ed25519_sign_verify/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable ed25519_sign_verify"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ed25519_sign_verify.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ed25519_sign_verify.dir/build: ed25519_sign_verify

.PHONY : CMakeFiles/ed25519_sign_verify.dir/build

CMakeFiles/ed25519_sign_verify.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ed25519_sign_verify.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ed25519_sign_verify.dir/clean

CMakeFiles/ed25519_sign_verify.dir/depend:
	cd /home/haojun/Developer/ed25519_sign_verify/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/haojun/Developer/ed25519_sign_verify /home/haojun/Developer/ed25519_sign_verify /home/haojun/Developer/ed25519_sign_verify/cmake-build-debug /home/haojun/Developer/ed25519_sign_verify/cmake-build-debug /home/haojun/Developer/ed25519_sign_verify/cmake-build-debug/CMakeFiles/ed25519_sign_verify.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ed25519_sign_verify.dir/depend

