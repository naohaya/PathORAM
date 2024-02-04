#!/bin/sh
if [ ! -d /tmp/serverStorage ]; then
	mkdir /tmp/serverStorage
fi
java -cp .:./lib/guava-33.0.0-jre.jar com.client.Client
