#!/bin/bash

cd challenge && docker build -t mincraft-hacked . \
	&& docker tag mincraft-hacked gcr.io/idekctf-374221/mincraft-hacked \
	&& docker push gcr.io/idekctf-374221/mincraft-hacked