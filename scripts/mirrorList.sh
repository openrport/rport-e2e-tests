#!/bin/bash

# https://flutterq.com/failed-to-download-metadata-for-repo-appstream-cannot-prepare-internal-mirrorlist-no-urls-in-mirrorlist/
# Failed to download metadata for repo ‘appstream’: Cannot prepare internal mirrorlist: No URLs in mirrorlist

sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-Linux-*
sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-Linux-*
#yum upgrade -y
yum clean all