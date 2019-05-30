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
import urllib2, sys, lxml, re, json

def buildLink(cve):
        nistURL = "https://nvd.nist.gov/vuln/detail/"
        link = nistURL + cve
        return link

baseURL  = 'https://access.redhat.com/security/cve/'
filename = "CVEs.txt"

with open(filename) as inputfile:
        for cve in inputfile:
                cve = cve.rstrip()
                fullURL    = baseURL + cve

                # Red Hat's website does not appreciate being scraped by
                # automatons.  *Poof!*  We are now a Mozilla browser.
                # TODO: Use their API before you get got. /Omar
                agentSpoof = {'User-Agent': 'Mozilla/5.0'}
                sauce = urllib2.Request(fullURL,headers=agentSpoof)
                
                # Grabbing the page and dealing with any errors that may occur.
                try:
                        # Make contact with the Red Hat page
                        page  = urllib2.urlopen(sauce)
                except urllib2.HTTPError, e:
                        # An HTTP error has occurred, likely a 404 indicating
                        # the CVE doesn't exist on Red Hat's website
                        status_code = e.code
                        print ("%s: An HTTP error has occured - %s" % (cve, status_code))
                except urllib2.URLError, e:
                        # Something is wrong with the URL
                        # TODO: e.code doesn't exist.  Returned no useful info when tripped.
                        status_code = e.code
                        print ("%s: A URL error has occured - %s" % (cve, status_code))
                except (TypeError, AttributeError, KeyError) as e:
                        # Something happened that I didn't anticipate
                        status_code = e.code
                        print ("%s: An unspecified error has occured - %s" % (cve, status_code))
                else:
                        # Success
                        status_code = page.code
                        soup  = bs.BeautifulSoup(page,'lxml')
                        theRows = soup.find_all('tr')

                                                # Cycle through all "tr" elements found
                        for row in theRows:
                                # The following regex seeks only rows labeled "Red Hat Enterprise Linux 6" or "7".
                                # An end-of-line $ was used to prevent matching on RHEL "7.3 Telco Extended Update..."
                                tech = row.find('th', text=re.compile(r"Red Hat Enterprise Linux [67]$"))

                                if 'None' in str(tech):
                                        continue
                                else:
                                        state = row.find('td', attrs={'headers':'th-state'}).string
                                        package = row.find('td', attrs={'headers':'th-package'}).string
                                        link = ""
                                        if state == "Affected":
                                                link = buildLink(cve)
                                        #print ("[%s] %s %s package: %s %s" % (cve, tech.string, package, state, link))
                                        rawOutput = {
                                                "cve": cve,
                                                "tech": tech.string,
                                                "package": package,
                                                "state": state,
                                                "link": link
                                        }
                                output = json.dumps(rawOutput, indent=4, sort_keys=True)
                        print(output)
