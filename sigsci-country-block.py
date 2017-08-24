#!/usr/bin/env python
# Signal Sciences Country Block(er)

import os
import time
import datetime
import argparse
import json
from modules.SigSci import SigSciAPI
import geoip2.database

reader         = geoip2.database.Reader('data/GeoLite2-City.mmdb')
sigsci_feed    = 'data/sigsci-feed.json'
sigsci_bl      = 'data/sigsci-bl.json'
sigsci_bl_post = 'data/sigsci-bl-post.json'
BL_MAX         = 1000
ATTACK_TAGS    = ['XSS', 'SQLI', 'TRAVERSAL', 'CMDEXE', 'USERAGENT', 'BACKDOOR', 'CODEINJECTION', 'RESPONSESPLIT']

if __name__ == '__main__':
    # parse CLI arguments
    parser = argparse.ArgumentParser(description='Signal Sciences Country Block(er).', prefix_chars='--')
    parser.add_argument('--country', help='The country iso code, e.g. IR, CN, US, etc.', default=None)
    arguments = parser.parse_args()

    if None == arguments.country:
        print('No country code provided!')
        quit()

    # we need sigsci api creds, corp, and site!
    if 'SIGSCI_EMAIL' not in os.environ:
        print('You must set the SIGSCI_EMAIL environment variable.')
        quit()
    
    if 'SIGSCI_PASSWORD' not in os.environ:
        print('You must set the SIGSCI_PASSWORD environment variable.')
        quit()
    
    if 'SIGSCI_CORP' not in os.environ:
        print('You must set the SIGSCI_CORP environment variable.')
        quit()
    
    if 'SIGSCI_SITE' not in os.environ:
        print('You must set the SIGSCI_SITE environment variable.')
        quit()

    # good to go, let's get some sigsci data!
    sigsci = SigSciAPI()

    sigsci.email = os.environ['SIGSCI_EMAIL']
    sigsci.pword = os.environ['SIGSCI_PASSWORD']
    sigsci.corp  = os.environ['SIGSCI_CORP']
    sigsci.site  = os.environ['SIGSCI_SITE']
    sigsci.tags  = ATTACK_TAGS

    if sigsci.authenticate():
        while True:
            # get latest black list
            sigsci.file = sigsci_bl
            if os.path.isfile(sigsci_bl):
                os.remove(sigsci_bl)
            
            sigsci.get_blacklist()

            # open up the blacklist
            with open(sigsci_bl) as json_file:
                blacklist = json.load(json_file)['data']

            # do time stuff
            now              = datetime.datetime.now()
            tm               = now - datetime.timedelta(hours=1,minutes=10)
            stm              = tm.strftime("%Y-%m-%d %H:%M:00")
            sigsci.from_time = int(tm.strptime(stm, "%Y-%m-%d %H:%M:00").strftime("%s"))

            tm = now - datetime.timedelta(minutes=5)
            stm = tm.strftime("%Y-%m-%d %H:%M:00")
            sigsci.until_time = int(tm.strptime(stm, "%Y-%m-%d %H:%M:00").strftime("%s"))
            
            # set output file
            sigsci.file = sigsci_feed
            # get feed data, but clean up first
            if os.path.isfile(sigsci_feed):
                os.remove(sigsci_feed)
            
            sigsci.get_feed_requests()
            # loop through feed and find that country!
            with open(sigsci_feed) as json_file:
                data = json.load(json_file)

            for request in data:
                # get suspect ip
                suspect_ip = request['remoteIP']

                for header in request['headersIn']:
                    if header[0] == 'X-Forwarded-For':
                        suspect_ip = header[1]

                # do country lookup by ip
                # test IR ip: 2.144.5.5
                # suspect_ip = '2.144.5.5'
                country_code = reader.city(suspect_ip)

                if arguments.country == country_code.country.iso_code:
                    if len(blacklist) >= BL_MAX:
                        print('Blacklist is full, but I wanted to blacklist {}'.format(suspect_ip))
                    else:
                        print('Blacklisting {}'.format(suspect_ip))
                        expires = datetime.datetime.utcnow() + datetime.timedelta(hours=5)
                        #print expires.strftime('%Y-%m-%dT%H:%M:%S.500Z')
                        blip = {}
                        blip['source']  = suspect_ip
                        # format: 2017-08-24T16:04:44.501Z
                        blip['expires'] = expires.strftime('%Y-%m-%dT%H:%M:%S.500Z')
                        blip['note']    = 'Auto block {} ip'.format(country_code.country.iso_code)

                        json_obj = { 'data': []}
                        json_obj['data'].append(blip)
                        # overwrite if exists
                        with open(sigsci_bl_post, 'w') as outfile:
                            json.dump(json_obj, outfile)
                        # update blacklist!
                        sigsci.file = sigsci_bl_post
                        sigsci.post_blacklist()

            # check again in 5 minutes
            time.sleep(300)