# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.25

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
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
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/pavel/Desktop/projects/snifferV2

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/pavel/Desktop/projects/snifferV2/build

# Include any dependencies generated for this target.
include CMakeFiles/sniffer.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/sniffer.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/sniffer.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/sniffer.dir/flags.make

CMakeFiles/sniffer.dir/sniffer.c.o: CMakeFiles/sniffer.dir/flags.make
CMakeFiles/sniffer.dir/sniffer.c.o: /home/pavel/Desktop/projects/snifferV2/sniffer.c
CMakeFiles/sniffer.dir/sniffer.c.o: CMakeFiles/sniffer.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/pavel/Desktop/projects/snifferV2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/sniffer.dir/sniffer.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/sniffer.dir/sniffer.c.o -MF CMakeFiles/sniffer.dir/sniffer.c.o.d -o CMakeFiles/sniffer.dir/sniffer.c.o -c /home/pavel/Desktop/projects/snifferV2/sniffer.c

CMakeFiles/sniffer.dir/sniffer.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/sniffer.dir/sniffer.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/pavel/Desktop/projects/snifferV2/sniffer.c > CMakeFiles/sniffer.dir/sniffer.c.i

CMakeFiles/sniffer.dir/sniffer.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/sniffer.dir/sniffer.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/pavel/Desktop/projects/snifferV2/sniffer.c -o CMakeFiles/sniffer.dir/sniffer.c.s

CMakeFiles/sniffer.dir/utils/handle_signal.c.o: CMakeFiles/sniffer.dir/flags.make
CMakeFiles/sniffer.dir/utils/handle_signal.c.o: /home/pavel/Desktop/projects/snifferV2/utils/handle_signal.c
CMakeFiles/sniffer.dir/utils/handle_signal.c.o: CMakeFiles/sniffer.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/pavel/Desktop/projects/snifferV2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/sniffer.dir/utils/handle_signal.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/sniffer.dir/utils/handle_signal.c.o -MF CMakeFiles/sniffer.dir/utils/handle_signal.c.o.d -o CMakeFiles/sniffer.dir/utils/handle_signal.c.o -c /home/pavel/Desktop/projects/snifferV2/utils/handle_signal.c

CMakeFiles/sniffer.dir/utils/handle_signal.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/sniffer.dir/utils/handle_signal.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/pavel/Desktop/projects/snifferV2/utils/handle_signal.c > CMakeFiles/sniffer.dir/utils/handle_signal.c.i

CMakeFiles/sniffer.dir/utils/handle_signal.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/sniffer.dir/utils/handle_signal.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/pavel/Desktop/projects/snifferV2/utils/handle_signal.c -o CMakeFiles/sniffer.dir/utils/handle_signal.c.s

# Object files for target sniffer
sniffer_OBJECTS = \
"CMakeFiles/sniffer.dir/sniffer.c.o" \
"CMakeFiles/sniffer.dir/utils/handle_signal.c.o"

# External object files for target sniffer
sniffer_EXTERNAL_OBJECTS =

sniffer: CMakeFiles/sniffer.dir/sniffer.c.o
sniffer: CMakeFiles/sniffer.dir/utils/handle_signal.c.o
sniffer: CMakeFiles/sniffer.dir/build.make
sniffer: CMakeFiles/sniffer.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/pavel/Desktop/projects/snifferV2/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable sniffer"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sniffer.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/sniffer.dir/build: sniffer
.PHONY : CMakeFiles/sniffer.dir/build

CMakeFiles/sniffer.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/sniffer.dir/cmake_clean.cmake
.PHONY : CMakeFiles/sniffer.dir/clean

CMakeFiles/sniffer.dir/depend:
	cd /home/pavel/Desktop/projects/snifferV2/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/pavel/Desktop/projects/snifferV2 /home/pavel/Desktop/projects/snifferV2 /home/pavel/Desktop/projects/snifferV2/build /home/pavel/Desktop/projects/snifferV2/build /home/pavel/Desktop/projects/snifferV2/build/CMakeFiles/sniffer.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/sniffer.dir/depend

