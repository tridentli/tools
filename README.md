# Trident Tools

## expiryfixer

This is there to counter new keys being set to an expiry of 0 (1970-01-01) as the key tools do not parse the date correctly.
Runs this from a crontab every once in a while and correct (and minute accurate vs day-accurate with old portal code) will appear in the DB.

Building: ```go get; build go .```
Requirements: $GOPATH should have the trident.li/pitchfork library

