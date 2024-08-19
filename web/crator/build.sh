#!/bin/bash

cd challenge && docker build -t crator . \
	&& docker tag crator gcr.io/idekctf-374221/crator \
	&& docker push gcr.io/idekctf-374221/crator