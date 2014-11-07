WireLurker Detector
===================

## Description ##

This project provides script and/or tool to detect the WireLurker malware family found by Palo Alto Networks in Nov 2014.

For details of the WireLurker: 

- http://researchcenter.paloaltonetworks.com/2014/11/wirelurker-new-era-os-x-ios-malware/
- http://researchcenter.paloaltonetworks.com/2014/11/wirelurker-windows/

## Usage for OS X users ##

1. Open the Terminal application in your OS X system;

2. Execute this command to download the script:

  ```
  curl -O https://raw.githubusercontent.com/PaloAltoNetworks-BD/WireLurkerDetector/master/WireLurkerDetectorOSX.py
  ```
3. Run the script in the Terminal:

  ```
  python WireLurkerDetectorOSX.py
  ```
4. Read the output messages and detection result.

## For Windows users ##
We described how to technically detect the Windows variant of WireLurker in this document: [HOWTO-Windows.md](https://github.com/PaloAltoNetworks-BD/WireLurkerDetector/blob/master/HOWTO-Windows.md) . Please take a look at it if you would like to contribute on it.

Here are some Windows detection tools developed by others. Remember to thanks them!

- https://github.com/ltfish/WireLurkerCleaner by ltfish

## Issues ##
For any issue on the code and its result, please create a issue here: https://github.com/PaloAltoNetworks-BD/WireLurkerDetector/issues
