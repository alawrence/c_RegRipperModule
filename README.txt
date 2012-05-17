Reg Ripper Module
Sleuth Kit Framework C++ Module
May 2012


This module is for the C++ Sleuth Kit Framework.


DESCRIPTION

This module is a reporting module that performs runs the RegRipper 
executable against the common set of Windows registry files 
(i.e., NTUSER, SYSTEM, SAM and SOFTWARE).

USAGE

Configure the reporting pipeline to include this module.

This module takes an optional semicolon separated list of arguments:
	-e Path to the RegRipper executable
	-o Directory in which to place RegRipper output

