# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.7

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
CMAKE_COMMAND = /home/jyc/software/clion/bin/cmake/bin/cmake

# The command to remove a file.
RM = /home/jyc/software/clion/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/jyc/myproject/Master

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jyc/myproject/Master/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/Master.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/Master.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/Master.dir/flags.make

CMakeFiles/Master.dir/Master.cpp.o: CMakeFiles/Master.dir/flags.make
CMakeFiles/Master.dir/Master.cpp.o: ../Master.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jyc/myproject/Master/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/Master.dir/Master.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Master.dir/Master.cpp.o -c /home/jyc/myproject/Master/Master.cpp

CMakeFiles/Master.dir/Master.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Master.dir/Master.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jyc/myproject/Master/Master.cpp > CMakeFiles/Master.dir/Master.cpp.i

CMakeFiles/Master.dir/Master.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Master.dir/Master.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jyc/myproject/Master/Master.cpp -o CMakeFiles/Master.dir/Master.cpp.s

CMakeFiles/Master.dir/Master.cpp.o.requires:

.PHONY : CMakeFiles/Master.dir/Master.cpp.o.requires

CMakeFiles/Master.dir/Master.cpp.o.provides: CMakeFiles/Master.dir/Master.cpp.o.requires
	$(MAKE) -f CMakeFiles/Master.dir/build.make CMakeFiles/Master.dir/Master.cpp.o.provides.build
.PHONY : CMakeFiles/Master.dir/Master.cpp.o.provides

CMakeFiles/Master.dir/Master.cpp.o.provides.build: CMakeFiles/Master.dir/Master.cpp.o


CMakeFiles/Master.dir/socket.cpp.o: CMakeFiles/Master.dir/flags.make
CMakeFiles/Master.dir/socket.cpp.o: ../socket.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jyc/myproject/Master/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/Master.dir/socket.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Master.dir/socket.cpp.o -c /home/jyc/myproject/Master/socket.cpp

CMakeFiles/Master.dir/socket.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Master.dir/socket.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jyc/myproject/Master/socket.cpp > CMakeFiles/Master.dir/socket.cpp.i

CMakeFiles/Master.dir/socket.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Master.dir/socket.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jyc/myproject/Master/socket.cpp -o CMakeFiles/Master.dir/socket.cpp.s

CMakeFiles/Master.dir/socket.cpp.o.requires:

.PHONY : CMakeFiles/Master.dir/socket.cpp.o.requires

CMakeFiles/Master.dir/socket.cpp.o.provides: CMakeFiles/Master.dir/socket.cpp.o.requires
	$(MAKE) -f CMakeFiles/Master.dir/build.make CMakeFiles/Master.dir/socket.cpp.o.provides.build
.PHONY : CMakeFiles/Master.dir/socket.cpp.o.provides

CMakeFiles/Master.dir/socket.cpp.o.provides.build: CMakeFiles/Master.dir/socket.cpp.o


# Object files for target Master
Master_OBJECTS = \
"CMakeFiles/Master.dir/Master.cpp.o" \
"CMakeFiles/Master.dir/socket.cpp.o"

# External object files for target Master
Master_EXTERNAL_OBJECTS =

../bin/Master: CMakeFiles/Master.dir/Master.cpp.o
../bin/Master: CMakeFiles/Master.dir/socket.cpp.o
../bin/Master: CMakeFiles/Master.dir/build.make
../bin/Master: /usr/local/lib/libglib-2.0.so
../bin/Master: /usr/local/lib/libgthread-2.0.so
../bin/Master: CMakeFiles/Master.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/jyc/myproject/Master/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable ../bin/Master"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/Master.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/Master.dir/build: ../bin/Master

.PHONY : CMakeFiles/Master.dir/build

CMakeFiles/Master.dir/requires: CMakeFiles/Master.dir/Master.cpp.o.requires
CMakeFiles/Master.dir/requires: CMakeFiles/Master.dir/socket.cpp.o.requires

.PHONY : CMakeFiles/Master.dir/requires

CMakeFiles/Master.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/Master.dir/cmake_clean.cmake
.PHONY : CMakeFiles/Master.dir/clean

CMakeFiles/Master.dir/depend:
	cd /home/jyc/myproject/Master/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jyc/myproject/Master /home/jyc/myproject/Master /home/jyc/myproject/Master/cmake-build-debug /home/jyc/myproject/Master/cmake-build-debug /home/jyc/myproject/Master/cmake-build-debug/CMakeFiles/Master.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/Master.dir/depend

