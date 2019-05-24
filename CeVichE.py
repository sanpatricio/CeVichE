#!/usr/bin/python

# Author: Patrick Riggs
# 23 May 2019
#
# CeVichE was written in an effort to automate
# away the toil of analyzing CVEs and
# whether or not they apply to back-ported
# Red Hat Enterprise Linux distros.
#
# Input: List of CVEs contained inside CVEs.txt
#        in the same folder.
#
# Output: Standard out echo of CVE status from
#         Red Hat website.

import bs4 as bs
import urllib2, sys, lxml, re

baseURL  = 'https://access.redhat.com/security/cve/'
filename = "CVEs.txt"

with open(filename) as inputfile:
        for cve in inputfile:
                cve = cve.rstrip()
                fullURL    = baseURL + cve

                # Red Hat's website does not appreciate being scraped by
                # automatons.  *Poof!*  We are now a Mozilla browser.
                agentSpoof = {'User-Agent': 'Mozilla/5.0'}

                sauce = urllib2.Request(fullURL,headers=agentSpoof)
                page  = urllib2.urlopen(sauce)
                soup  = bs.BeautifulSoup(page,'lxml')

                theRows = soup.find_all('tr')
                for row in theRows:
                        technology = row.find('th', text=re.compile(r"Red Hat Enterprise Linux [67]"))
                        if technology:
                                os    = technology.string
                                state = row.find('td', attrs={'headers':'th-state'}).string
                                print ("%s: %s is %s" % (cve, os, state))
