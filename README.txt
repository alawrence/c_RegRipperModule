Reg Ripper Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module is a report/post-processing module that runs the RegRipper 
executable against the common set of Windows registry files (i.e., NTUSER, 
SYSTEM, SAM and SOFTWARE).

This module allows you to extract information from the system's registry.

DEPLOYMENT REQUIREMENTS

This module requires that RegRipper be installed on the system. You can 
download it from:

    http://regripper.wordpress.com/


USAGE

Add this module to a post-processing/reporting pipeline.  See the TSK 
Framework documents for information on adding the module 
to the pipeline:

    http://www.sleuthkit.org/sleuthkit/docs/framework-docs/


This module takes optional configuration arguments in a semi-colon separated 
list of arguments:

	-e Path to the RegRipper executable
	-o Path to directory in which to place RegRipper output

If the executable path is omitted the module will look for RegRipper/rip.exe
in the program directory. 

If the output directory path is omitted, the module will store the results in
a "RegRipper" directory in the output directory specified in the framework 
system properties.   

This module currently pulls out operating system information and posts it to
the blackboard. The OS name and version will be available with the base version
of RegRipper. If you want to get the processor architecture as well place the 
included RegRipper plugin (processorarchitecture.pl) in the RegRipper plugins
directory and update the "system" file in that directory to include
"processorarchitecture" as it's own line.

RESULTS

The RegRipper output will be located in the location as described in the 
previous section. Currently, the module does not interpret any of the results.
It simply runs the tool.  It will save the analysis results from each 
hive to its own text file. Errors from RegRipper will be logged to 
RegRipperErrors.txt in the output directory.


TODO
- Make the module find RegRipper if is in the module's configuration directory.
