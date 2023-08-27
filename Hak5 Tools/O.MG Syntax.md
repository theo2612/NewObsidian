STRING  
Type a sequence of letters  
STRING Hello World!  
  
ENTER  
Send the enter key  
  
DELAY  
Delay for a number of milliseconds  
DELAY 500  
  
USB  
Turn USB on/off (enumerate the implant as a USB device to the host)  
USB ON  
USB OFF  
  
VID  
Set Vendor ID  
VID 1234  
  
PID  
Set Product ID  
PID ABCD  
  
MAN  
Set iManufacturer descriptor (length 40)  
MAN O.MG  
  
PRO  
Set iProduct descriptor (length 40)  
PRO O.MG-CABLE  
  
SER  
Set iSerial descriptor (length 40)  
SER 0123456789  
  
IF_PRESENT  
Run the payload if a SSID/BSSID is seen. This only scans once.  
IF_PRESENT SSID="SSIDNAME"  
IF_PRESENT BSSID="AA:BB:CC:DD:EE:FF"  
  
IF_NOTPRESENT  
Run the payload if a SSID/BSSID is not seen. This only scans once.  
IF_NOTPRESENT SSID="SSIDNAME"  
IF_NOTPRESENT BSSID="AA:BB:CC:DD:EE:FF"  
  
WAIT_FOR_PRESENT  
Wait for a SSID/BSSID before continuing the rest of the payload. Specify MINUTES for a timeout, or it will run forever. Specify INTERVAL in seconds for how often the scan will happen. An INTERVAL less than 60sec tends to make it hard for most clients to retain a connection to the Web UI.  
WAIT_FOR_PRESENT SSID="MySSID"  
WAIT_FOR_PRESENT SSID="MySSID" MINUTES="2" INTERVAL="90"  
WAIT_FOR_PRESENT BSSID="AA:BB:CC:DD:EE:FF" MINUTES="2" INTERVAL="90"  
  
WAIT_FOR_NOTPRESENT  
Similar to WAIT_FOR_PRESENT, except the payload waits for a specific SSID/BSSID to NOT be seen  
WAIT_FOR_NOTPRESENT SSID="MySSID"  
WAIT_FOR_NOTPRESENT="AA:BB:CC:DD:EE:FF"  
  
JIGGLER  
Turn mouse jiggler on or off. This will move the mouse randomly one pixel left or right every 25 seconds to keep the screen lock feature of the os from turning on.  
JIGGLER ON  
JIGGLER OFF  
  
SELF-DESTRUCT  
Completely erase all chip data and disconnect the cable's data lines. This would "break" the data functionality of the cable for any device trying to use it.  
SELF-DESTRUCT  
*** WARNING ***  
ALL SAVED CONFIGURATIONS AND PAYLOADS WILL BE ERASED!  
  
NEUTER  
Partially erase all chip data but leave the cable's data lines in working condition.  
NEUTER  
*** WARNING ***  
ALL SAVED CONFIGURATIONS AND PAYLOADS WILL BE ERASED!  
  
GUI/WINDOWS  
Use windows key or Mac CMD key  
GUI  
GUI A  
GUI SPACE  
  
ALT  
Use the alt key  
ALT ABC  
  
CTRL  
Use the ctrl key  
CTRL ABC  
  
SHIFT  
Use the shift key  
SHIFT ABC  
  
TAB  
Use the tab key  
TAB  
  
SPACE  
Use the space key  
SPACE  
  
CAPSLOCK  
Use the capslock key  
CAPSLOCK  
  
DELETE  
Use the delete key  
DELETE  
  
HOME  
Use the home key  
HOME  
  
INSERT  
Use the insert key  
INSERT  
  
NUMLOCK  
Use the numlock key  
NUMLOCK  
  
PAGEUP  
Use the pageup key  
PAGEUP  
  
PAGEDOWN  
Use the pagedown key  
PAGEDOWN  
  
SCROLLLOCK  
Use the scrolllock key  
SCROLLOCK  
  
PAUSE/BREAK  
Use the pause/break key  
PAUSE/BREAK  
  
ESC/ESCAPE  
Use the esc/escape key  
ESC/ESCAPE  
  
RIGHT/RIGHTARROW  
Use the right arrow key  
RIGHT/RIGHTARROW  
  
LEFT/LEFTARROW  
Use the left arrow key  
LEFT/LEFTARROW  
  
UP/UPARROW  
Use the up arrow key  
UP/UPARROW  
  
DOWN/DOWNARROW  
Use the down arrow key  
DOWN/DOWNARROW  
  
A-Z  
Use the A-Z keys  
HELLO  
  
F1-F12  
Use the F1-F12 keys  
F1  
F2