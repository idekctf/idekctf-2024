#!/bin/bash

cd image && docker build -t admin-bot . \
	&& docker tag admin-bot gcr.io/idekctf-374221/admin-bot \
	&& docker push gcr.io/idekctf-374221/admin-bot