#!/usr/bin/env python3
import hashlib
import logging
import requests
import socket
import json
import os

from datetime import datetime
from urllib.parse import urlparse, urljoin
from queue import Queue
from bs4 import BeautifulSoup
from multiprocessing import Pool

'''
collect_kits was derived from Jordan Wright <jwright@duo.com>'s https://github.com/duo-labs/phish-collect. This file is a modified version of his 
collector.py
'''

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[logging.FileHandler("collector.log"), logging.StreamHandler()])
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

BLACKLIST = []


class Collector(object):
    ''' A class that handles collecting phishing sites '''

    def __init__(self):
        ''' Creates a new instance of the collector'''
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent':
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36'
        })
        self.config = {
                'kit_directory': 'kits',
                'html_directory': 'html',
                'visits_directory': 'visits',
                'max_links_per_directory': 100
                }
        
        try:
            with open('wordlist.txt', 'r') as fout:
                self.wordlist = fout.read().split('\n')
        except:
            self.wordlist = []
        
    def collect(self, url):
        ''' Collects the data associated with a phishkit '''

        try:
            with open('kits_processed', 'r') as kits_json:
                kits = json.load(kits_json)
        except:
            logging.error('Error loading urls json')
            kits = []

        try:
            with open('urls_processed', 'r') as urls_json:
                urls_processed = json.load(urls_json)
        except:
            logging.error('Error loading urls json')
            urls_processed = []

        try:
            parts = urlparse(url)
            if parts.netloc in BLACKLIST:
                raise Exception('Sample URL is blacklisted from analysis.')
            for u in urls_processed:
                if url == u['url']:
                    logging.info('URL already processed: {}'.format(url))
                    return False
            url_ex = {}
            url_ex['url'] = url
            url_ex['status'], url_ex['html'] = self.collect_html(url, parts.netloc)
            url_ex['ip'] = self.lookup_ip(url)
            url_ex['url_sha1'] = hashlib.sha1(url.encode("utf-8")).hexdigest()

            kits += self.collect_kits(url_ex)
            urls_processed.append(url_ex)

            with open('kits_processed', 'w') as kout:
                json.dump(kits, kout)

            with open('urls_processed', 'w') as uout:
                json.dump(urls_processed, uout)

            return True

        except Exception as e:
            logging.exception('Error in collect')
            # Give a reasonable error status
            return True

    def lookup_ip(self, url):
        '''
        Returns the IP address the URL resolves to. 
        '''
        try:
            parts = urlparse(url)
            return socket.gethostbyname(parts.netloc)

        except Exception:
            return None

    def download_kit(self, url, url_ex):
        '''
        Attempts to fetch a file at the current URL
        '''
        kit = None
        try:
            response = self.session.get(url, stream=True, verify=False, timeout=5)
            if not response.ok:
                logging.info('Invalid response for zip URL: {} : {}'.format(url, str(response.status_code)))
                return kit
            # Shoutout to everyone who doesn't know how to status code
            if 'text/html' in response.headers.get('Content-Type'):
                return kit
            filename = url.split('/')[-1]
            filepath = '{}/{}-{}'.format(self.config['kit_directory'], url_ex['url_sha1'], filename)
            filesize = 0

            kit_hash = hashlib.sha1()
            first = True
            with open(filepath, 'wb') as kit_file:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        if first and not chunk.startswith(b'PK'):
                            logging.info('Invalid zip file, aborting download')
                            return kit
                        first = False
                        kit_hash.update(chunk)
                        kit_file.write(chunk)
                        filesize += len(chunk)
            logging.info('Found kit for {}'.format(url))
            kit = {
                'url': url,
                'source_url': url_ex['url'],
                'source_url_hash': url_ex['url_sha1'],
                'source_url_status': url_ex['status'], 
                'source_url_html_hash': url_ex['html'],
                'source_url_hash': url_ex['url_sha1'],
                'source_url_ip': url_ex['ip'],
                'filepath': filepath,
                'filename': filename,
                'filesize': filesize,
                'hash': kit_hash.hexdigest()}
        except Exception as e:
            logging.error('error for {} : {}'.format(url, e))
        return kit

    def indexing_enabled(self, url):
        '''
        Fetches the requested URL and determined if indexing is enabled.
        If it is, we return the links found
        '''
        links = []
        response = self.session.get(url, verify=False, timeout=5)
        if not response.ok:
            return links
        soup = BeautifulSoup(response.text, 'html.parser')
        if 'Index of' not in response.text:
            return links
        # Get all the links
        for a in soup.find_all('a'):
            if 'Parent Directory' in a.text:
                continue
            href = a['href']
            if href and href[0] == '?':
                continue
            # TODO: Normalize this url to support only relative urls
            links.append(urljoin(url, href))
        return links

    def collect_kits(self, url_ex):
        '''
        Crawls the site looking for open directories or zip files
        left available to the public, and looks for visits files
        '''
        url = url_ex['url']
        queue = Queue()
        parts = urlparse(url)
        paths = parts.path.split('/')[1:]
        url_hash = url_ex['url_sha1']
        kit_urls = []
        crawled = []
        kits = []

        #fix paths
        if paths == ['']:
            paths = []

        #add subdomains, domain to wordlist
        thewordlist = list(self.wordlist)
        thewordlist.append(parts.netloc)
        for sub in parts.netloc.split('.'):
            if len(sub) < 4: #exlude www, com, org, ner, etc
                continue
            thewordlist.append(sub)
        
        #enumerate wordlist and add to crawled queue against root domain
        for w in thewordlist:
            phish_url = '{}://{}/{}/'.format(parts.scheme, parts.netloc, w)
            crawled.append(phish_url)
            logging.info('Added url to crawled: {}'.format(phish_url))

        # Add the initial paths to our queue, including filename without extension 
        logging.info('collect_kits found the following paths: {}'.format(paths))
        for i in range(0, len(paths)):
            pathing, fext = os.path.splitext('/'.join(paths[:len(paths) - i]))
            phish_url = '{}://{}/{}/'.format(parts.scheme, parts.netloc, pathing)
            queue.put(phish_url)
            crawled.append(phish_url)
            logging.info('Added url to queue and crawled: {}'.format(phish_url))

        # Try to get the ZIP by looking for open directories - if we find other sub-
        # directories in an open index, add those to the queue.
        while not queue.empty():
            phish_url = queue.get()
            logging.info('Checking for open directory at: {}'.format(phish_url))

            links = self.indexing_enabled(phish_url)
            if not links:
                continue

            directory_links = 0
            for link in links:
                if link in crawled:
                    continue
                if link.endswith('.zip'):
                    kit = self.download_kit(link, url_ex)
                    if kit:
                        kits.append(kit)
                        kit_urls.append(link)
                    continue
                if link[-1] == '/':
                    # Short circuit if this directory is huge - won't stop us from finding
                    # a kit if it's in the same directory
                    directory_links += 1
                    if directory_links > self.config['max_links_per_directory']:
                        continue
                    logging.info('Adding URL to Queue: {}'.format(link))
                    queue.put(link)
                    crawled.append(link)

        for phish_url in crawled:
            #check for visitors/visits file
            names = ['res', 'results', 'vu', 'visits', 'visitors', 'rezults', 'result']
            for name in names:
                visit_url = '{}{}.txt'.format(phish_url, name)
                visit_status, visit_hash = self.collect_html(visit_url, parts.netloc, True)
                if visit_hash:
                    logging.info('Found Visits file: {} status: {} hash: {}'.format(visit_url, visit_status, visit_hash))
            # Remove the trailing slash and add .zip
            phish_url = '{}.zip'.format(phish_url[:-1])
            if phish_url in kit_urls:
                logging.info(
                    'Skipping URL since the kit was already downloaded: {}'.
                    format(phish_url))
                continue
            logging.info('Fetching kit by zip {}'.format(phish_url))

            kit = self.download_kit(phish_url, url_ex)
            if kit:
                kits.append(kit)
        return kits

    def collect_html(self, url, dom, visits=False):
        '''
        Fetches the HTML of a phishing page
        '''

        logging.info('Fetching {}'.format(url))
        status_code = None
        content_hash = None
        content = None

        try:
            response = self.session.get(url, verify=False, timeout=3)
            if response.ok:
                content = response.text
                content_hash = hashlib.sha1(content.encode("utf-8")).hexdigest()
                status_code = response.status_code
            else:
                logging.info('Unsuccessful response for sample: {} : {}'.format(url, content))
        except Exception:
            logging.error('Invalid response for sample: {}'.format(url))

        try:
            if content:
                if visits:
                    extension = 'txt'
                    if 'DOCTYPE' in content:
                        return None, None
                    logging.info('Writing visits {}'.format(url))
                    directory = self.config['visits_directory']
                else:
                    extension = 'html'
                    logging.info('Writing html {}'.format(url))
                    directory = self.config['html_directory']
                filepath = '{}/{}_{}.{}'.format(directory, dom, content_hash, extension)
                with open(filepath, 'w') as html_f:
                    html_f.write(content)
        except Exception:
            logging.error('Unsuccessful writing html: {}'.format(url))
        return status_code, content_hash


def process_sample(url):
    c = Collector()
    try:
        logging.info('Processing sample: {}'.format(url))
        c.collect(url)
    except Exception as e:
        logging.error('Error processing sample: {}: {}'.format(url.encode('utf-8'), e))


def main():
    logging.info('---------------------------------------')
    logging.info('Report for timestamp: {}'.format(datetime.now()))
    logging.info('---------------------------------------')
    pool = Pool(8)
    urls = []

    try:
        payload = {'q': 'task.source:phishtank OR task.source:openphish OR task.source:certstream-suspicious', 'size': 1000}
        r = requests.get(url='https://urlscan.io/api/v1/search/', params=payload, allow_redirects=True, timeout=(5, 12))
        data = r.json()
    except requests.exceptions.ConnectTimeout as e:
        logging.error("Error while connecting to urlscan.io: {}".format(e))
    except Exception as e:
        logging.error("Urlscan connection error: {}".format(e))

    for item in data.get('results', []):
        u = item.get('page', {}).get('url')
        if u:
            process_sample(u)
            urls.append(u)

    #pool.map(process_sample, urls)
    #pool.close()
    #pool.join()


if __name__ == '__main__':
    main()
