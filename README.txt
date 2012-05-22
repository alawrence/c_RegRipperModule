Reg Ripper Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


MODULE DESCRIPTION

This module is a post-processing module that performs runs the RegRipper 
executable against the common set of Windows registry files (i.e., NTUSER, 
SYSTEM, SAM and SOFTWARE).

MODULE USAGE

Configure the post-processing pipeline to include this module by adding a 
"MODULE" element to the pipeline configuration file. Optionally set the 
"arguments" attribute of the "MODULE" element to a semi-colon separated list 
of arguments:

	-e Path to the RegRipper executable
	-o Path to directory in which to place RegRipper output

If the executable path is omitted the module will look for RegRipper/rip.exe
in the program directory. If the output directory path is omitted, the module
will use the output directory specified in the framework system properties,
usually obtained form the framework configuration file. 