#!/bin/bash
ssh-keygen -t rsa -N '' -f e2e <<<y && cat e2e.pub > authorized_keys && chmod 600 authorized_keys