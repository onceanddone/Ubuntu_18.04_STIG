# Ubuntu_18.04_STIG

Currently working on Canonical Ubuntu 18.04 LTS Security Technical Implementation Guide :: Version 1, Release: 2 Benchmark Date: 24 Jul 2020

The initial goal is to create two scripts:
  The first script can scan an Ubuntu install and generate a file to show the results of the scan.  At this time a second file (fixfile) is created that lists the failing controls and their status (automatable, manual settings required, etc.).  
  The second script uses the fixfile to automatically repair as many issues as possible on the installed Ubuntu system.  Customization can be done by editing the fixfile prior to running the second script.
  At this time the process requires a reboot, and a second run of the fix script due to some issues around when files are created and addressed based on STIG Vulnerability ID's and topics.  Some issues are attempted to be dealt with before the system has actually had a chance to create the configurations necessary to fix the problems.
  
  THIS SCRIPT SHOULD BE ACCEPTED WITH NO WARRRANTY!!!!  I'm trying to solve a problem here, and this is currently my best shot at it.  Things could break.  If your system is critical, don't use a script.  Or don't use mine.  Or at least, don't blame me if it breaks!
  
  IF you find corrections that will help to make the script more accurate or more streamlined, or just better, please submit changes! 
