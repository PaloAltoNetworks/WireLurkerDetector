How to (technically) detect Windows variant of WireLruker
===================

## Background ##
This is a document for technical guys. 

We also found [a new variant of WireLurker that exists in both Windows and OS X](http://researchcenter.paloaltonetworks.com/2014/11/wirelurker-windows/). While the OS X detection code was updated to cover this variant, we decide to only fully disclose how to technically detect its Windows samples.

We also encourage others in the community write GUI/CLI tools or scripts for the detection. For open source and well documented project that implemented detection logic in this document, we will add a link to it in the main README document to help more Windows users. Please just open an issue or pull request to let us know you. 

This document may be updated if we found more variants on Windows.

## Detection Logic ##

1. Scan all PE executable files in the Windows system by following steps.

2. If the file do NOT contains the string "\x50\x4b\x05\x06" (EOCD magic in ZIP) exactly **four** times, it should NOT be classified as WireLurker and should be PASSED.

3. If the file contains ALL of these two strings: "Payload/apps.app/sfbase.dylib" and "Payload/apps.app/sfbase.plist", it should be classified as WireLurker. Otherwise, it should NOT be.

## Suggestions on Performance ##

1. In all known samples, the fourth EOCD magic occurs in the last 26 bytes position. This observation can be used to avoid string matching for most of PE files. However, it may bring potential false negative.

2. You can chose to only scan or to not scan any specific directories with potential false negative.

## Samples for Testing ##

You can find a original sample from <http://contagiominidump.blogspot.com>
