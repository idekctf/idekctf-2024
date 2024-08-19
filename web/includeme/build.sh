#!/bin/bash

cd challenge && docker build -t includeme . \
	&& docker tag includeme gcr.io/idekctf-374221/includeme \
	&& docker push gcr.io/idekctf-374221/includeme