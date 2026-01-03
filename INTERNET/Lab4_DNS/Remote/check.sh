#!/bin/bash

echo 'dump the cache'
rndc dumpdb -cache
cat /var/cache/bind/dump.db | grep attacker
echo 'if there is no result, the attack has not succeeded yet'
