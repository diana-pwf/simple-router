# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /router

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /router/cmake-build-debug-vm

# Include any dependencies generated for this target.
include CMakeFiles/router.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/router.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/router.dir/flags.make

CMakeFiles/router.dir/build/pox.cpp.o: CMakeFiles/router.dir/flags.make
CMakeFiles/router.dir/build/pox.cpp.o: ../build/pox.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/router/cmake-build-debug-vm/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/router.dir/build/pox.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/router.dir/build/pox.cpp.o -c /router/build/pox.cpp

CMakeFiles/router.dir/build/pox.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/router.dir/build/pox.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /router/build/pox.cpp > CMakeFiles/router.dir/build/pox.cpp.i

CMakeFiles/router.dir/build/pox.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/router.dir/build/pox.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /router/build/pox.cpp -o CMakeFiles/router.dir/build/pox.cpp.s

CMakeFiles/router.dir/build/pox.cpp.o.requires:

.PHONY : CMakeFiles/router.dir/build/pox.cpp.o.requires

CMakeFiles/router.dir/build/pox.cpp.o.provides: CMakeFiles/router.dir/build/pox.cpp.o.requires
	$(MAKE) -f CMakeFiles/router.dir/build.make CMakeFiles/router.dir/build/pox.cpp.o.provides.build
.PHONY : CMakeFiles/router.dir/build/pox.cpp.o.provides

CMakeFiles/router.dir/build/pox.cpp.o.provides.build: CMakeFiles/router.dir/build/pox.cpp.o


CMakeFiles/router.dir/arp-cache.cpp.o: CMakeFiles/router.dir/flags.make
CMakeFiles/router.dir/arp-cache.cpp.o: ../arp-cache.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/router/cmake-build-debug-vm/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/router.dir/arp-cache.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/router.dir/arp-cache.cpp.o -c /router/arp-cache.cpp

CMakeFiles/router.dir/arp-cache.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/router.dir/arp-cache.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /router/arp-cache.cpp > CMakeFiles/router.dir/arp-cache.cpp.i

CMakeFiles/router.dir/arp-cache.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/router.dir/arp-cache.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /router/arp-cache.cpp -o CMakeFiles/router.dir/arp-cache.cpp.s

CMakeFiles/router.dir/arp-cache.cpp.o.requires:

.PHONY : CMakeFiles/router.dir/arp-cache.cpp.o.requires

CMakeFiles/router.dir/arp-cache.cpp.o.provides: CMakeFiles/router.dir/arp-cache.cpp.o.requires
	$(MAKE) -f CMakeFiles/router.dir/build.make CMakeFiles/router.dir/arp-cache.cpp.o.provides.build
.PHONY : CMakeFiles/router.dir/arp-cache.cpp.o.provides

CMakeFiles/router.dir/arp-cache.cpp.o.provides.build: CMakeFiles/router.dir/arp-cache.cpp.o


CMakeFiles/router.dir/routing-table.cpp.o: CMakeFiles/router.dir/flags.make
CMakeFiles/router.dir/routing-table.cpp.o: ../routing-table.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/router/cmake-build-debug-vm/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/router.dir/routing-table.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/router.dir/routing-table.cpp.o -c /router/routing-table.cpp

CMakeFiles/router.dir/routing-table.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/router.dir/routing-table.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /router/routing-table.cpp > CMakeFiles/router.dir/routing-table.cpp.i

CMakeFiles/router.dir/routing-table.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/router.dir/routing-table.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /router/routing-table.cpp -o CMakeFiles/router.dir/routing-table.cpp.s

CMakeFiles/router.dir/routing-table.cpp.o.requires:

.PHONY : CMakeFiles/router.dir/routing-table.cpp.o.requires

CMakeFiles/router.dir/routing-table.cpp.o.provides: CMakeFiles/router.dir/routing-table.cpp.o.requires
	$(MAKE) -f CMakeFiles/router.dir/build.make CMakeFiles/router.dir/routing-table.cpp.o.provides.build
.PHONY : CMakeFiles/router.dir/routing-table.cpp.o.provides

CMakeFiles/router.dir/routing-table.cpp.o.provides.build: CMakeFiles/router.dir/routing-table.cpp.o


CMakeFiles/router.dir/simple-router.cpp.o: CMakeFiles/router.dir/flags.make
CMakeFiles/router.dir/simple-router.cpp.o: ../simple-router.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/router/cmake-build-debug-vm/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/router.dir/simple-router.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/router.dir/simple-router.cpp.o -c /router/simple-router.cpp

CMakeFiles/router.dir/simple-router.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/router.dir/simple-router.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /router/simple-router.cpp > CMakeFiles/router.dir/simple-router.cpp.i

CMakeFiles/router.dir/simple-router.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/router.dir/simple-router.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /router/simple-router.cpp -o CMakeFiles/router.dir/simple-router.cpp.s

CMakeFiles/router.dir/simple-router.cpp.o.requires:

.PHONY : CMakeFiles/router.dir/simple-router.cpp.o.requires

CMakeFiles/router.dir/simple-router.cpp.o.provides: CMakeFiles/router.dir/simple-router.cpp.o.requires
	$(MAKE) -f CMakeFiles/router.dir/build.make CMakeFiles/router.dir/simple-router.cpp.o.provides.build
.PHONY : CMakeFiles/router.dir/simple-router.cpp.o.provides

CMakeFiles/router.dir/simple-router.cpp.o.provides.build: CMakeFiles/router.dir/simple-router.cpp.o


CMakeFiles/router.dir/core/utils.cpp.o: CMakeFiles/router.dir/flags.make
CMakeFiles/router.dir/core/utils.cpp.o: ../core/utils.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/router/cmake-build-debug-vm/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/router.dir/core/utils.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/router.dir/core/utils.cpp.o -c /router/core/utils.cpp

CMakeFiles/router.dir/core/utils.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/router.dir/core/utils.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /router/core/utils.cpp > CMakeFiles/router.dir/core/utils.cpp.i

CMakeFiles/router.dir/core/utils.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/router.dir/core/utils.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /router/core/utils.cpp -o CMakeFiles/router.dir/core/utils.cpp.s

CMakeFiles/router.dir/core/utils.cpp.o.requires:

.PHONY : CMakeFiles/router.dir/core/utils.cpp.o.requires

CMakeFiles/router.dir/core/utils.cpp.o.provides: CMakeFiles/router.dir/core/utils.cpp.o.requires
	$(MAKE) -f CMakeFiles/router.dir/build.make CMakeFiles/router.dir/core/utils.cpp.o.provides.build
.PHONY : CMakeFiles/router.dir/core/utils.cpp.o.provides

CMakeFiles/router.dir/core/utils.cpp.o.provides.build: CMakeFiles/router.dir/core/utils.cpp.o


CMakeFiles/router.dir/core/interface.cpp.o: CMakeFiles/router.dir/flags.make
CMakeFiles/router.dir/core/interface.cpp.o: ../core/interface.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/router/cmake-build-debug-vm/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/router.dir/core/interface.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/router.dir/core/interface.cpp.o -c /router/core/interface.cpp

CMakeFiles/router.dir/core/interface.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/router.dir/core/interface.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /router/core/interface.cpp > CMakeFiles/router.dir/core/interface.cpp.i

CMakeFiles/router.dir/core/interface.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/router.dir/core/interface.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /router/core/interface.cpp -o CMakeFiles/router.dir/core/interface.cpp.s

CMakeFiles/router.dir/core/interface.cpp.o.requires:

.PHONY : CMakeFiles/router.dir/core/interface.cpp.o.requires

CMakeFiles/router.dir/core/interface.cpp.o.provides: CMakeFiles/router.dir/core/interface.cpp.o.requires
	$(MAKE) -f CMakeFiles/router.dir/build.make CMakeFiles/router.dir/core/interface.cpp.o.provides.build
.PHONY : CMakeFiles/router.dir/core/interface.cpp.o.provides

CMakeFiles/router.dir/core/interface.cpp.o.provides.build: CMakeFiles/router.dir/core/interface.cpp.o


CMakeFiles/router.dir/core/dumper.cpp.o: CMakeFiles/router.dir/flags.make
CMakeFiles/router.dir/core/dumper.cpp.o: ../core/dumper.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/router/cmake-build-debug-vm/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object CMakeFiles/router.dir/core/dumper.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/router.dir/core/dumper.cpp.o -c /router/core/dumper.cpp

CMakeFiles/router.dir/core/dumper.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/router.dir/core/dumper.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /router/core/dumper.cpp > CMakeFiles/router.dir/core/dumper.cpp.i

CMakeFiles/router.dir/core/dumper.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/router.dir/core/dumper.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /router/core/dumper.cpp -o CMakeFiles/router.dir/core/dumper.cpp.s

CMakeFiles/router.dir/core/dumper.cpp.o.requires:

.PHONY : CMakeFiles/router.dir/core/dumper.cpp.o.requires

CMakeFiles/router.dir/core/dumper.cpp.o.provides: CMakeFiles/router.dir/core/dumper.cpp.o.requires
	$(MAKE) -f CMakeFiles/router.dir/build.make CMakeFiles/router.dir/core/dumper.cpp.o.provides.build
.PHONY : CMakeFiles/router.dir/core/dumper.cpp.o.provides

CMakeFiles/router.dir/core/dumper.cpp.o.provides.build: CMakeFiles/router.dir/core/dumper.cpp.o


CMakeFiles/router.dir/core/main.cpp.o: CMakeFiles/router.dir/flags.make
CMakeFiles/router.dir/core/main.cpp.o: ../core/main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/router/cmake-build-debug-vm/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object CMakeFiles/router.dir/core/main.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/router.dir/core/main.cpp.o -c /router/core/main.cpp

CMakeFiles/router.dir/core/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/router.dir/core/main.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /router/core/main.cpp > CMakeFiles/router.dir/core/main.cpp.i

CMakeFiles/router.dir/core/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/router.dir/core/main.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /router/core/main.cpp -o CMakeFiles/router.dir/core/main.cpp.s

CMakeFiles/router.dir/core/main.cpp.o.requires:

.PHONY : CMakeFiles/router.dir/core/main.cpp.o.requires

CMakeFiles/router.dir/core/main.cpp.o.provides: CMakeFiles/router.dir/core/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/router.dir/build.make CMakeFiles/router.dir/core/main.cpp.o.provides.build
.PHONY : CMakeFiles/router.dir/core/main.cpp.o.provides

CMakeFiles/router.dir/core/main.cpp.o.provides.build: CMakeFiles/router.dir/core/main.cpp.o


# Object files for target router
router_OBJECTS = \
"CMakeFiles/router.dir/build/pox.cpp.o" \
"CMakeFiles/router.dir/arp-cache.cpp.o" \
"CMakeFiles/router.dir/routing-table.cpp.o" \
"CMakeFiles/router.dir/simple-router.cpp.o" \
"CMakeFiles/router.dir/core/utils.cpp.o" \
"CMakeFiles/router.dir/core/interface.cpp.o" \
"CMakeFiles/router.dir/core/dumper.cpp.o" \
"CMakeFiles/router.dir/core/main.cpp.o"

# External object files for target router
router_EXTERNAL_OBJECTS =

../router: CMakeFiles/router.dir/build/pox.cpp.o
../router: CMakeFiles/router.dir/arp-cache.cpp.o
../router: CMakeFiles/router.dir/routing-table.cpp.o
../router: CMakeFiles/router.dir/simple-router.cpp.o
../router: CMakeFiles/router.dir/core/utils.cpp.o
../router: CMakeFiles/router.dir/core/interface.cpp.o
../router: CMakeFiles/router.dir/core/dumper.cpp.o
../router: CMakeFiles/router.dir/core/main.cpp.o
../router: CMakeFiles/router.dir/build.make
../router: CMakeFiles/router.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/router/cmake-build-debug-vm/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Linking CXX executable ../router"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/router.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/router.dir/build: ../router

.PHONY : CMakeFiles/router.dir/build

CMakeFiles/router.dir/requires: CMakeFiles/router.dir/build/pox.cpp.o.requires
CMakeFiles/router.dir/requires: CMakeFiles/router.dir/arp-cache.cpp.o.requires
CMakeFiles/router.dir/requires: CMakeFiles/router.dir/routing-table.cpp.o.requires
CMakeFiles/router.dir/requires: CMakeFiles/router.dir/simple-router.cpp.o.requires
CMakeFiles/router.dir/requires: CMakeFiles/router.dir/core/utils.cpp.o.requires
CMakeFiles/router.dir/requires: CMakeFiles/router.dir/core/interface.cpp.o.requires
CMakeFiles/router.dir/requires: CMakeFiles/router.dir/core/dumper.cpp.o.requires
CMakeFiles/router.dir/requires: CMakeFiles/router.dir/core/main.cpp.o.requires

.PHONY : CMakeFiles/router.dir/requires

CMakeFiles/router.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/router.dir/cmake_clean.cmake
.PHONY : CMakeFiles/router.dir/clean

CMakeFiles/router.dir/depend:
	cd /router/cmake-build-debug-vm && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /router /router /router/cmake-build-debug-vm /router/cmake-build-debug-vm /router/cmake-build-debug-vm/CMakeFiles/router.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/router.dir/depend

