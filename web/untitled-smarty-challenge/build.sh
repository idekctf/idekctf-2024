#!/bin/bash

cd challenge && docker build -t untitled-smarty-challenge . \
	&& docker tag untitled-smarty-challenge gcr.io/idekctf-374221/untitled-smarty-challenge \
	&& docker push gcr.io/idekctf-374221/untitled-smarty-challenge