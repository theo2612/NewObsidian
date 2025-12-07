twitch chat
phillips - 
home network

"As a streamer I need a way for chat to be able to turn off my lights" 
The requirements to support that are that an event in chat will trigger a message to the lights to do an activity. 

Phillips bulbs
- 1 
	- Version 1.32.0
	- Model ID B123140
	- MAC B8011BA0773
	- IP 192.168.0.6
	- Home ID 3124016
	- RSSI -77
- 2 
	- Version 1.32.0
	- Model ID B23065
	- MAC 6C29902FFCF8
	- IP 192.168.0.10
	- Home ID 3124016
	- RSSI -76

Philips A19 bulb use the WIZ 

Key activities
- Receive Twitch Chat message
	- EventSub [[https]]://dev.twitch.tv/docs/eventsub/
	- !blue
- send signal to light
	- 