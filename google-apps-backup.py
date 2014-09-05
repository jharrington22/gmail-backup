#!/usr/bin/python

import os
import time
import json
import base64
import urllib
import urllib2
import argparse
import xml.etree.ElementTree as etree

parser = argparse.ArgumentParser(description="Backup Google Apps Business/Education Gmail to mbox file")
parser.add_argument("-u", "--username", help="Google Apps username")
parser.add_argument("-p", "--password", help="Google Apps password or app specific password for two-factor enabled accounts")
parser.add_argument("-a", "--auth", action="store_true", help="Make authentication request and return authentication token")
parser.add_argument("-d", "--domain", help="Google Apps domain")
parser.add_argument("-t", "--token", help="Google Apps authorization token")
parser.add_argument("-e", "--email", help="Google Apps user email address")
parser.add_argument("-k", "--key", help="GPG Public key file")
parser.add_argument("-i", "--installKey", help="Install new Public GPG file (created with GPG tool)")
parser.add_argument("-s", "--status", action="store_true", help="Check status of request and download if complete (downloads to /tmp)")
parser.add_argument("-r", "--requestId", help="Request Id of mbox request")
parser.add_argument("-b", "--backup", action="store_true", help="Request download of mbox")

args = parser.parse_args()

epoch = str(time.time()).split('.')[0]

clientLoginUrl = "https://www.google.com/accounts/ClientLogin"
tokenRequestHeader = "application/x-www-form-urlencoded"

# TODO: Split these off into if's below as they will fail if argument isn't specified

publicKeyUrl = "https://apps-apis.google.com/a/feeds/compliance/audit/publickey/%s" % args.domain
publicKeyUploadHeader = "application/atom+xml"

mailboxExportUrl = "https://apps-apis.google.com/a/feeds/compliance/audit/mail/export/%s/%s" % (args.domain, args.email.split("@")[0])

mailboxExportStatusUrl = "https://apps-apis.google.com/a/feeds/compliance/audit/mail/export/%s/%s/" % (args.domain, args.email.split("@")[0])

# Get users home directory
homeDirectory = os.path.expanduser("~") + "/"
# Set default cache file location
cacheFileLocation = homeDirectory + '.google-apps-backup.json'


def formatPublicGpgUpload(publicGpgStringFile):
    """Read GPG public key from file and format Atom XML request for POST"""
    with open(publicGpgStringFile, "rb") as gpgFile:
        encodedGpgFile = base64.b64encode(gpgFile.read())
    data = """<atom:entry xmlns:atom='http://www.w3.org/2005/Atom' xmlns:apps='http://schemas.google.com/apps/2006'>
<apps:property name="publicKey" value="%s"/>
</atom:entry>""" % encodedGpgFile
    return data


def formatMailboxDownloadRequestXml():
    """Format XML to request mailbox download"""
    data = """<atom:entry xmlns:atom='http://www.w3.org/2005/Atom' xmlns:apps='http://schemas.google.com/apps/2006'>
<apps:property name='beginDate' value='2009-07-01 04:30'/>
<apps:property name='endDate' value='2009-08-30 20:00'/>
<apps:property name='includeDeleted' value='false'/>
<apps:property name='searchQuery' value='in:chat'/>
<apps:property name='packageContent' value='FULL_MESSAGE'/>
</atom:entry>"""
    data = """<atom:entry xmlns:atom='http://www.w3.org/2005/Atom' xmlns:apps='http://schemas.google.com/apps/2006'>
<apps:property name='includeDeleted' value='false'/>
<apps:property name='packageContent' value='FULL_MESSAGE'/>
</atom:entry>"""
    return data


def getAuthTokenParams(username, password):
    """Get authentication Token from Google"""
    params = urllib.urlencode({"accountType": "HOSTED", "Email": username, "Passwd": password, "service": "apps",
                               "source": "gmailbackup-0.1"})
    return params


def requestMailboxDownload(url, cacheFile):
    """Sets up request to download mailbox data"""
    success = 0
    postData = formatMailboxDownloadRequestXml()
    responseData = postToGoogle(publicKeyUploadHeader, postData, url, cacheFile["token"]["Auth"])
    if not responseData:
        tree = etree.parse(responseData)
        for elem in tree.iterfind('{http://schemas.google.com/apps/2006}property'):
            try:
                if elem.attrib["name"] == "requestId":
                    print "Request Id: %s" % elem.attrib["value"]
                    requestId = elem.attrib["value"]
                    success = True
            except KeyError:
                pass
            try:
                if elem.attrib["name"] == "userEmailAddress":
                    print "Requested Users Mailbox: %s" % elem.attrib["value"]
                    requestedMailbox = elem.attrib["value"]
                    success = True
            except KeyError:
                pass
            try:
                if elem.attrib["name"] == "adminEmailAddress":
                    print "Admin Email of Requester: %s" % elem.attrib["value"]
                    adminEmail = elem.attrib["value"]
                    success = True
            except KeyError:
                pass
            try:
                if elem.attrib["name"] == "status":
                    print "Status of request: %s" % elem.attrib["value"]
                    statusOfRequest = elem.attrib["value"]
                    success = True
            except KeyError:
                pass
            try:
                if elem.attrib["name"] == "requestDate":
                    print "Request Date: %s" % elem.attrib["value"]
                    requestDate = elem.attrib["value"]
                    success = True
            except KeyError:
                pass
            try:
                if elem.attrib["name"] == "packageContent":
                    print "Package Contents: %s" % elem.attrib["value"]
                    packageContents = elem.attrib["value"]
                    success = True
            except KeyError:
                pass
        if success == 1:
            # Write request response to cacheFile
            if "requests" not in cacheFile:
                cacheFile["requests"] = {}
            cacheFile["requests"][requestId] = {"requestedMailbox": requestedMailbox, "adminEmail": adminEmail, "status": statusOfRequest, "requestDate": requestDate, "packageContents": packageContents}
            with open(cacheFileLocation, 'w') as cacheFileFp:
                cacheFileFp.write(json.dumps(cacheFile))


def getMailboxExportStatus(url, cacheFile, email, epoch):
    """Print mailbox status and download mbox file if status is Complete"""
    update = False
    for request in cacheFile["requests"]:
        print("Checking status of request %s.." % request)
        if cacheFile["requests"][request]["status"] == "PENDING":
            status = getFromGoogle(request, url, cacheFile["token"]["Auth"])
            if not status:
                tree = etree.parse(status)
                for elem in tree.iterfind('{http://schemas.google.com/apps/2006}property'):
                    try:
                        if elem.attrib["name"] == "requestId":
                            print "Request Id: %s" % elem.attrib["value"]
                    except KeyError:
                        pass
                    try:
                        if elem.attrib["name"] == "requestDate":
                            print "Request Date: %s" % elem.attrib["value"]
                    except KeyError:
                        pass
                    try:
                        if elem.attrib["name"] == "completedDate":
                            print "Complete Date: %s" % elem.attrib["value"]
                    except KeyError:
                        pass
                    try:
                        if elem.attrib["name"] == "userEmailAddress":
                            print "Requested Users Mailbox: %s" % elem.attrib["value"]
                    except KeyError:
                        pass
                    try:
                        if elem.attrib["name"] == "status":
                            print "Status of request: %s" % elem.attrib["value"]
                    except KeyError:
                        pass
                    try:
                        if elem.attrib["name"] == "fileUrl0":
                            print "Downloading file 0 for mbox: %s" % elem.attrib["value"]
                            if downloadMboxFile(elem.attrib["value"], email, epoch, "0"):
                                cacheFile["requests"][request]["status"] = "COMPLETE"
                                update = True
                    except KeyError:
                        pass
                    try:
                        if elem.attrib["name"] == "fileUrl1":
                            print "Downloading file 1 for mbox: %s" % elem.attrib["value"]
                            if downloadMboxFile(elem.attrib["value"], email, epoch, "1"):
                                cacheFile["requests"][request]["status"] = "COMPLETE"
                                update = True
                    except KeyError:
                        pass
            else:
                print("Error retrieving status for request: %s" % request)
            status = None
            tree = None
        else:
            print("Already Complete")
    if update:
        with open(cacheFileLocation, 'w') as cacheFileFp:
            cacheFileFp.write(json.dumps(cacheFile))


def postToGoogle(contentType, data, url, authorization=None):
    """POST data Google"""
    req = urllib2.Request(url)
    req.add_header('Content-Type', contentType)
    if authorization is None:
        req.add_header('Authorization', "GoogleLogin auth=%s" % authorization)
    try:
        response = urllib2.urlopen(req, data)
        return response
    except Exception as e:
        print e
        print "Error posting data to Google"
        return False


def getFromGoogle(requestId, url, authorization=None):
    """GET data Google """
    url = url + requestId
    req = urllib2.Request(url)
    if authorization is None:
        req.add_header('Authorization', "GoogleLogin auth=%s" % authorization)
    try:
        response = urllib2.urlopen(req)
        return response
    except Exception as e:
        print e
        print "Error in GET request to Google"
        return False


def downloadMboxFile(url, email, epoch, num):
    """ Download mbox file from Google"""
    req = urllib2.urlopen(url)
    mboxTmpFile = "/tmp/mbox-%s-%s-%s" % (email.split('@')[0], epoch, num)
    CHUNK = 12 * 2048
    with open(mboxTmpFile, 'wb') as fp:
        while True:
            chunk = req.read(CHUNK)
            if not chunk:
                break
            fp.write(chunk)
    fp.close()
    print "Complete downloaded to %s" % mboxTmpFile
    return True

# TODO: Finish if's below, currently works if you run auth then install then request then status until mailbox is ready

# If token is specified set authToken
if args.token:
    authToken = args.token

# Build URL and request auth Token (Only valid for 24 hours)
# TODO: Check if cache file is older than 24 hours and generate a new token
# postToGoogle responds with three long alphanumeric codes SID,LSID and Auth
# SID = Session ID
# LSID = Is for APIs not using the Google Data protocol
# Auth = Authorization token the we'll send to the email audit service
# Store these in a cache file as they are valid for 24 hours
if os.path.exists(cacheFileLocation):
    with open(cacheFileLocation, 'r') as cacheFileFp:
        cacheFile = json.load(cacheFileFp)
        authToken = cacheFile["token"]["Auth"]
else:
    urlParams = getAuthTokenParams(args.username, args.password)
    authToken = postToGoogle(tokenRequestHeader, urlParams, clientLoginUrl)
    SID, LSID, Auth = authToken.read().rstrip().split("\n")
    SID = SID.split("=")[1]
    LSID = LSID.split("=")[1]
    Auth = Auth.split("=")[1]
    cacheFile = {"token": {"SID": SID, "LSID": LSID, "Auth": Auth}}
    authToken = cacheFile["token"]["Auth"]
    with open(cacheFileLocation, 'w') as cacheFileFp:
        cacheFileFp.write(json.dumps(cacheFile))

if args.installKey:
    # Insert new public GPG key to Google Apps
    # Adding a new key will overwrite any existing
    # postData = formatPublicGpgUpload(args.key)
    # publicKeyResponse = postToGoogle(publicKeyUploadHeader, postData, publicKeyUrl, args.token)
    # print publicKeyResponse
    pass

if args.backup:
    # From this request need to pickup;
    # <apps:property name='requestId' value='470444354'/>
    # This value then needs to be used in getMailboxExportStatus
    requestMailboxDownload(mailboxExportUrl, cacheFile)

if args.status:
    # Check mailbox status download if status is Complete
    getMailboxExportStatus(mailboxExportStatusUrl, cacheFile, args.email, epoch)


print "Hello James"
