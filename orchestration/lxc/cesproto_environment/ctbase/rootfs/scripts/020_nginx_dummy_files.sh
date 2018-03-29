#!/bin/bash

# Create dummy files for nginx

mkdir /var/www/html -p
truncate -s 1M  /var/www/html/1M
truncate -s 10M /var/www/html/10M
