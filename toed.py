#!/usr/bin/env python

import re, os, sys, argparse, time, hmac, hashlib, base64
import logging as log
import traceback, json, requests
import urllib
import collections
from pprint import pprint


## REF error codes:
# Error 222 if you give it a bad path
# Error 220 if you give it a bad path e.g. no opening /
# Error 202 if you give it a bad path
# Error 107 if you give it no path
# Error 101 if you give a dud hmac hash
# Error 341 if you give a dud spaceOid


# REST API Gateway
API_GATEWAY = 'https://restapi.oxygencloud.com'

# LocalDirectory
# Use beta if available, assuming beta is the one we care about
LOCALOX = os.path.expanduser('~') + "\Oxygen Enterprise\\"
if os.path.isdir(os.path.expanduser('~') + "\Oxygen Enterprise Beta\\"):
    LOCALOX = os.path.expanduser('~') + "\Oxygen Enterprise Beta\\"

class Oxrest:
    'Oxygen Rest API Class'

    def __init__(self):

        # We're reusing this connection quite a bit
        self.sess = requests.Session()

        # A timestamp needs to be in the header and in hashed signature
        self.curtime = str(int(time.time()))
        self.sess.headers.update({'X-Timestamp': self.curtime })

        # Gets user/api credentials, additionally sets API key in session header
        self.get_user_creds()
        self.get_api_creds()

        # Ensure we've cleared session ID
        self.sessid = None
        # X-Session starts empty, update it after our first request
        self.sess.headers.update({'X-Session'  : ''})
        self.get_session_id()

        # A list of spaces
        self.spaces = self.get_spaces()
    
    def get_user_creds(self):
        """Grabs user credentials from the .user file"""
        d = {}
        try:
            with open('.user') as f:
                 for line in f:
                     k,v = line.split(':')
                     d[k] = v.strip()
            log.debug('Got user Credentials')
            self.logind = d
        except:
            log.error('Could not get user credentials from .user file')
    
    def get_api_creds(self):
        """Grabs api credentials from the .api file"""
        d = {}
        try:
            with open('.api') as f:
                 for line in f:
                     k,v = line.split(':')
                     d[k] = v.strip().encode('utf-8')
            log.debug('Got API Credentials')
            self.api = d
            self.sess.headers.update({'X-App-Key'  : d['KEY'] })
        except:
            log.error('Could not get API credentials from .api file')
    
    def hmac_header(self, api, payload, actiontype='POST'):
        """Generate a HMAC header dict"""
        try:
            flatdict = ' '.join(["%s %s" % (k, v) for k, v in sorted(payload.items())])
        except:
            # Probably no payload
            flatdict = ''

        try:
            unhashed = ' '.join([actiontype, api, flatdict, self.curtime, self.sessid])
        except:
            # Probably don't have session ID yet
            unhashed = ' '.join([actiontype, api, flatdict, self.curtime])

        log.debug('Unhashed Signature: %s', unhashed)

        hashed = hmac.new(self.api['SECRET'], unhashed.encode("utf-8"), hashlib.sha1)
        signature = base64.b64encode(hashed.digest())

        return { 'X-Signature': signature,
                 'X-Timestamp': self.curtime
               }

    def get_session_id(self):
        """Initiates a session with the REST API"""

        log.debug( '-------------------------')
        log.debug( '       LOGGING IN        ')
        log.debug( '-------------------------')
        
        header = self.hmac_header('/rest/account/login', self.logind)
        
        log.debug('Header: %s', header)
    
        try:
            response = self.sess.post(API_GATEWAY + '/rest/account/login', data=self.logind, headers=header)
        except requests.exceptions.SSLError:
            raise
        except:
            self.nosession()
            
        resjson = self.process_response(response)
    
        log.debug("Response itself is %s" , resjson)
        
        if (resjson):
            log.info("Response session is %s", resjson["session"])
        else:
            self.nosession()
    
        self.sess.headers.update({'X-Session'  : resjson["session"]})
        self.sessid = resjson["session"]

    def nosession(self):
        log.error("Could not connect and get session ID, cannot continue!")
        sys.exit(11)
    
    def spacels(self, spaceOid, path="/"):
        """Asks API for list of files from a given space"""
        """/rest/files/list?path=/FOLDERNAME&spaceOid=uv-abcde01010101010100101"""
        log.debug( '-------------------------')
        log.debug( ' Getting remote ls for: %s ', path)
        log.debug( '-------------------------')
    
        apiaction = '/rest/files/list'
        dir = dict(spaceOid = spaceOid, path = path)
        #urllib.parse.quote(path, safe='/,\ '))
        header = self.hmac_header(apiaction, dir)

        log.debug('Header: %s', header)
        log.debug('Payload: %s', dir)

        try:
            response = self.sess.post(API_GATEWAY + apiaction, data=dir, headers=header)
        except:
            self.nosession()

        resjson = self.process_response(response)
    
        if (resjson['data']):
            return resjson['data']
        else:
            log.error("No file listing returned, Aborting!")
            sys.exit(10)

    def get_spaces(self):
        """Asks API for list of spaces"""

        log.debug( '-------------------------')
        log.debug( '      GETTING SPACES     ')
        log.debug( '-------------------------')
    
        apiaction = '/rest/spaces/list_spaces'

        header = self.hmac_header(apiaction, None)
        log.debug('Header: %s', header)

        try:
            response = self.sess.post(API_GATEWAY + apiaction, headers=header)
        except requests.exceptions.ConnectionError:
            log.error("Couldn't go on, ouch, no connection")
            sys.exit(12)


        resjson = self.process_response(response)
    
        if (resjson['spaces']):
            return(resjson['spaces'])
        else:
            log.error("No spaces returned, user may not have spaces!")
            sys.exit(14)
    
    def process_response(self, response):
        """Deals with API response codes"""
    
        log.debug("Response URL is %s"    , response.url)
        log.debug("Response code is %s"   , response.status_code)
        log.debug(json.dumps(response.json(), sort_keys = False, indent = 4))
    
        if response.status_code == 200:
            if response:
                log.debug("Response looks good.")
                return response.json()
            # else dict()
    
        if response.status_code == 401:
            if response:
              response_json = response.json()
              log.error ('API error, unauthorized? error_code: %s', response_json['errorCode'])
            else:
              log.error ('401, couldn not get json response')
        else:
            log.error ('ERROR, unknown reason, error_code: %s', response.status_code)
            sys.exit(15)
    
    
    def filter_spaces(self, filterl):
        """Filter out the spaces based on the given list"""
        log.info('Filtering unopened spaces')
        log.info('Filter using: %s', filterl)

        self.spaces[:] = [d for d in self.spaces if d.get('name') not in filterl]
        log.debug("Spaces after filtering")
        log.debug(json.dumps(self.spaces, sort_keys = False, indent = 4))


class LocalOx:
    'Local Oxygen Enterprise Directory'

    def __init__(self):
        ( self.topdir_files, self.unopened_spaces, self.topdir_dirs, self.spaces ) = self.get_localspaces()

    def get_localspaces(self):
        """Checks current directory to see what spaces we already have"""

        log.debug( '-------------------------')
        log.debug( 'SEARCHING LOCAL INSTALL..')
        log.debug( '-------------------------')

        # You can't tell what the spaces are from the topdir by dirname alone
        # since there are also regular folders
        topdir = os.listdir(LOCALOX)
        
        log.debug("Top Dir looks like:")
        log.debug(topdir)

        topdir_files = []
        unopened_spaces = []
        topdir_dirs = []
        spaces = []

        cloudfx = re.compile('.*.cloudfx')
        unopened_space = re.compile('.*.space$')

        for file_entry in topdir:
            if os.path.isfile(file_entry):
                if unopened_space.match(file_entry):
                    log.debug("unopened space: %s", file_entry)
                    file_entry = re.sub('\.space$', '', file_entry)
                    unopened_spaces.append(file_entry)
                else:
                    log.debug("regular file: %s", file_entry)
                    topdir_files.append(file_entry)
            elif os.path.isdir(file_entry):
                if os.path.isfile(file_entry + "/.odrive"):
                    log.debug("space: %s", file_entry)
                    spaces.append(file_entry)
                else:
                    log.debug("regular directory: %s", file_entry)
                    topdir_dirs.append(file_entry)

        log.debug("Top dir files: %s", topdir_files)
        log.debug("Top dir Dirs: %s", topdir_dirs)
        log.debug("Unopened spaces: %s", unopened_spaces)
        log.info("Opened Spaces: %s", spaces)

        return (topdir_files, unopened_spaces, topdir_dirs, spaces)

def iterSpace(OxRest, LocalOx, curfolder):
    
    file_ignore = { '.odrive',
                    '.odrivemount',
                    '.oxygenreserved',
                    'Desktop.ini',
                    'desktop.ini',
                    'DS_Store' }

    all_missing_localfiles = dict()
    all_missing_remotefileparents = []
    all_filemismatch = []

    myspace = next((d for d in OxRest.spaces if d['name'] == curfolder), None)
    # Raise error if no space matches! TODO

    log.debug("--")
    log.debug("--iterSpace: %s", myspace)
    log.info("%s>", curfolder)

    for dirname, dirnames, local_filenames in os.walk(curfolder):
        #for file2ignore in file_ignore:
        #    if file2ignore in filenames:
        #        filenames.remove(file2ignore)
        #        # ICK, this loop then runs *file_ignore.length
        local_filenames = list(set(local_filenames) - file_ignore)
        log.debug('----------')
        log.debug("Processing %s", dirname)

        # On the remote end, the dirname needs to be sans space name
        rdirname = dirname.split(curfolder, 1).pop()

        # Flip Windows slashes
        rdirname = '/'.join(rdirname.split('\\'))
        if not rdirname.startswith('/'):
            rdirname = '/' + rdirname
        rdirname = '/'.join(rdirname.split('//'))

        remotels = OxRest.spacels(myspace['oid'], rdirname)

        #log.debug("Remote JSON: %s", remotels)
        remote_filenames = dict((d['name'], dict(d, index=i)) for (i, d) in enumerate(remotels.get('files')))
        remote_dirnames  = remotels.get('folders', None)

        log.debug("%s>Local Dirnames %s", dirname, dirnames)
        log.debug("%s>Remote Dirnames %s", dirname, remote_dirnames)
        log.debug("%s> #dir(s): Local %s , Remote %s", dirname, len(dirnames), len(remote_dirnames))
        log.debug("%s>Local filenames %s", dirname, sorted(local_filenames))
        log.debug("%s>Remote filenames %s", dirname, remote_filenames)
        log.debug("%s>Remote filenames (keys) %s", dirname, sorted(remote_filenames.keys()))
        log.debug("%s> #file(s): Local %s, Remote %s", dirname, len(local_filenames), len(remote_filenames))

        # Taking filenames (list of local files), comparing with remote_filenames (dict of remote files)
        missing_localfiles = [d.get('name') for d in remotels.get('files') if d.get('name') not in local_filenames and d.get('name') + '.cloudx' not in local_filenames]
        missing_localfiles = list(set(missing_localfiles) - file_ignore)

        ## But these can be cloudx files, let's edit those out
        #for (k, v) in enumerate(missing_remotefiles):
        #    log.info("missing remote file key: %s", k)
        #    if (v.endswith(".cloudx")):
        #        raise Exception

        if len(missing_localfiles):
            log.error("%s>local filenames missing %s", dirname, missing_localfiles)

        # Now other way around, looking for missing remote files
        missing_remotefiles = list(set(local_filenames) - set(remote_filenames.keys()) - file_ignore)
        # Remove cloudx extensions if they are present on remote
        #for (k, v) in enumerate(missing_remotefiles):
        #    if (v.endswith(".cloudx") and v[:-len(".cloudx")] not in remote_filenames.keys()):
        #        log.error("%s is a cloudx that does not exist on server", v[:-len(".cloudx")])
        #    delete
        missing_remotefiles[:] = [li for li in missing_remotefiles if (not li.endswith(".cloudx") or li[:-len(".cloudx")] not in remote_filenames.keys()) and not li.endswith(".cloudfx")] # and log.error("%s", li[:-len(".cloudx")])]

        ## TODO: DEAL WITH reconciling cloudfx and missing dirs

        if len(missing_remotefiles):
            log.error("%s>Missing Remote files: %s", dirname, missing_remotefiles)
            if dirname not in all_missing_remotefileparents:
                all_missing_remotefileparents.append(dirname)


        # Now stat and check filesize of ones that are there?
        # Maybe timestamps too
        common_files = list(set(local_filenames).intersection(remote_filenames.keys()))

        log.debug("%s>Common files: %s", dirname, sorted(common_files))

        for file in common_files:
            # Stat Local file
            flstat = os.stat(dirname + '/' + file)
            flsize = flstat.st_size
            flts = int(flstat.st_mtime)
            # Equiva Remote file stat
            frsize = remote_filenames[file]['size']
            frts = remote_filenames[file]['modified']
            log.debug("%s>File %s: Local size", dirname, flsize)
            log.debug("%s>File %s: Remote size", dirname, frsize)
            log.debug("%s>File %s: Local timestamp", dirname, flts)
            log.debug("%s>File %s: Remote timestamp", dirname, frts)
            if flsize != frsize:
                log.error("%s>File size of %s: Local %s and Remote %s differs", dirname, file, flsize, frsize)
                all_filemismatch.append(file)
            if flts != frts:
                log.error("%s>File timestamp of %s: Local %s and Remote %s differs", dirname, file, flts, frts)
                all_filemismatch.append(file)


        #DEBUG:{'folders': [{'seq': 1, 'name': '__adirname__', 'type': 'folder'}], 'files': [{'size': __integersize__, 'name': '__filename.ext__', 'seq': __integersequencenumber__, 'contentId': '12345678-90ab-cde1-2345-6789abcde012', 'modified': 1425428689}]}

    return all_missing_remotefileparents, all_missing_localfiles, all_filemismatch

def fix_missing_remotefiles(localox, missing_remotefileparents):
    """Given a list of dirs, try to 'fix' it. Oxygen remote may be missing things """
    """and triggering Oxygen to restat the directory by putting in a new file or removing"""
    """a file usually does the trick."""

    log.error("Fixing remotes, since -f/--fix was specified")
    log.error("WARNING: Oxygen needs to be running to have changes synced up")
    log.debug("%s", missing_remotefileparents)


    for dirname in missing_remotefileparents:
        log.error("Trying to autofix %s", dirname)
        os.utime(dirname)
        if (os.path.isfile(dirname + '/.paulnguyenfix')):
            try:
                os.remove(dirname + '/.paulnguyenfix')
            except:
                log.error("Could not remove the .paulnguyenfix file")
        else:
            try:
                open(dirname + '/.paulnguyenfix', 'a').close()
            except:
                log.error("Could not create the .paulnguyenfix file")
            try:
                os.remove(dirname + '/.paulnguyenfix')
            except:
                log.error("Could not remove the .paulnguyenfix file")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help='Turn debugging on', action="store_true")
    parser.add_argument('-v', '--verbose', help='Turn Verbose output on', action="store_true")
    parser.add_argument('-f', '--fix', help='Try Auto-Fix where possible', action="store_true")
    args = parser.parse_args()

    if (args.debug):
        log.basicConfig(format='%(levelname)s:%(message)s', level=log.DEBUG)
        log.info("Debugging output is on")
    elif (args.verbose):
        log.basicConfig(format='%(levelname)s:%(message)s', level=log.INFO)
        log.info("Verbose is on")

    # Assumes we're still in this folder
    oxrest = Oxrest()

    # Change to Oxygen Enterprise folder for processing
    os.chdir(LOCALOX)

    localox = LocalOx()
    oxrest.filter_spaces(localox.unopened_spaces)

    for d in oxrest.spaces:
        log.info("Checking space %s", d.get("name"))
        mrf, mlf, mcf = iterSpace(oxrest, localox, d.get("name"))
        if (args.fix and len(mrf)):
            fix_missing_remotefiles(localox, mrf)


if __name__ == '__main__':
    
    main()

