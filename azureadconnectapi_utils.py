from hashlib import pbkdf2_hmac
import hashlib,binascii
import random
from commonutils import binarytoxml,xmltobinary
import requests

aadsync_server=        "adminwebservice.microsoftonline.com"
aadsync_client_version="8.0"
aadsync_client_build=  "1.5.29.0"

def create_aadhash(hashnt=None,iterations = 1000,password=None):
    # literal convert powershell to python script :
    # https://github.com/Gerenios/AADInternals/blob/b135545d50a5a473c942139182265850f9d256c2/AzureADConnectAPI_utils.ps1#L279

    if not hashnt:
        if not password:
            raise Exception('Please provide hashnt or password')
        hashnt = binascii.hexlify(hashlib.new('md4', password.encode('utf-16le')).digest()).decode('utf-8').upper()
    if len(hashnt) != 32:
        raise Exception('Invalid hash length!')

    hashbytes = bytearray(hashnt.encode('UTF-16LE'))

    listnb = []
    while not len(listnb) >= 10 :
        listnb.append(random.choice(list(range(0, 256))))

    salt = bytearray(listnb)
    #salt = bytearray([180 ,119 ,18 ,77 ,229 ,76 ,32 ,48 ,55 ,143])

    salthex = salt.hex()
    key = pbkdf2_hmac("sha256", hashbytes, salt, iterations, 32).hex()
    aadhash = "v1;PPH1_MD4,%s,%s,%s;" % (salthex,iterations,key)
    return aadhash


def create_syncenvelope(token,command,body,message_id,server="adminwebservice.microsoftonline.com",binary=True,isinstalledondc=False,richcoexistenceenabled=False,version=1):

    if version == 2:
        applicationclient= "6eb59a73-39b2-4c23-a70f-e2e3ce8965b1"
    else :
        applicationclient = "1651564e-7ce4-4d99-88be-0a65050d8dc3"

    envelope = rf'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/online/aws/change/2010/01/IProvisioningWebService/{command}</a:Action>
        <SyncToken s:role="urn:microsoft.online.administrativeservice" xmlns="urn:microsoft.online.administrativeservice" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
            <ApplicationId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">{applicationclient}</ApplicationId>
            <BearerToken xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">{token}</BearerToken>
            <ClientVersion xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">{aadsync_client_version}</ClientVersion>
            <DirSyncBuildNumber xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">{aadsync_client_build}</DirSyncBuildNumber>
            <FIMBuildNumber xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">{aadsync_client_build}</FIMBuildNumber>
            <IsInstalledOnDC xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">{isinstalledondc}</IsInstalledOnDC>
            <IssueDateTime xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">0001-01-01T00:00:00</IssueDateTime>
            <LanguageId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">en-US</LanguageId>
            <LiveToken xmlns="http://schemas.microsoft.com/online/aws/change/2010/01"/>
            <ProtocolVersion xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">2.0</ProtocolVersion>
            <RichCoexistenceEnabled xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">{richcoexistenceenabled}</RichCoexistenceEnabled>
            <TrackingId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">{message_id}</TrackingId>
        </SyncToken>
        <a:MessageID>urn:uuid:{message_id}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">https://{server}/provisioningservice.svc</a:To>
    </s:Header>
    <s:Body>
        {body}
    </s:Body>
</s:Envelope>'''

    if binary:
        return xmltobinary(envelope)
    else:
        return envelope


def call_adsyncapi(envelope,command,tenant_id,message_id,server="adminwebservice.microsoftonline.com"):
    headers = {
        "Host":server,
        'Content-type': 'application/soap+msbin1',
        "x-ms-aadmsods-clientversion": aadsync_client_version,
        "x-ms-aadmsods-dirsyncbuildnumber": aadsync_client_build,
        "User-Agent":"",
        "x-ms-aadmsods-fimbuildnumber":   aadsync_client_build,
        "Host":"adminwebservice.microsoftonline.com",
        "x-ms-aadmsods-tenantid" : tenant_id,
        "client-request-id": message_id,
        "x-ms-aadmsods-appid":"1651564e-7ce4-4d99-88be-0a65050d8dc3",
        "x-ms-aadmsods-apiaction": command
    }

    r = requests.post("https://%s/provisioningservice.svc" % server, headers=headers,data=envelope)

    return r.content