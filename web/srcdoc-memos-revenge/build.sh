#!/bin/bash

cd challenge && docker build -t srcdoc-memos-revenge . \
	&& docker tag srcdoc-memos-revenge gcr.io/idekctf-374221/srcdoc-memos-revenge \
	&& docker push gcr.io/idekctf-374221/srcdoc-memos-revenge