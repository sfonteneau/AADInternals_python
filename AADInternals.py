from azure.common.credentials import UserPassCredentials
from azure.graphrbac import GraphRbacManagementClient
from hashlib import pbkdf2_hmac
from passlib.hash import nthash
from wcf.xml2records import XMLParser
from wcf.records import dump_records
from wcf.records import Record, print_records
import io
import requests
import random
import uuid
import datetime

aadsync_server=        "adminwebservice.microsoftonline.com"
aadsync_client_version="8.0"
aadsync_client_build=  "1.5.29.0"

class AADInternals():

    def __init__(self, mail=None, password=None,proxies={}):
        self.proxies=proxies
        self.credentials = UserPassCredentials(mail, password, resource="https://graph.windows.net",proxies=proxies)
        self.tenant_id = self.credentials.token['tenant_id']
        self.token = self.credentials.token['access_token']
        self.graphrbac_client = GraphRbacManagementClient(self.credentials,self.credentials.token['tenant_id'])

    #https://github.com/Gerenios/AADInternals/blob/master/AzureADConnectAPI.ps1#L570
    def set_azureadobject(self,user_principal_name,sourceanchor):
        #https://github.com/Gerenios/AADInternals/blob/master/AzureADConnectAPI.ps1#L571
        tenant_id = self.tenant_id

        command = "ProvisionAzureADSyncObjects"
#                    <c:KeyValueOfstringanyType><c:Key>SourceAnchor</c:Key><c:Value i:type="d:string" xmlns:d="http://www.w3.org/2001/XMLSchema">%s</c:Value></c:KeyValueOfstringanyType>
#                    <c:KeyValueOfstringanyType><c:Key>displayName</c:Key><c:Value i:type="d:string" xmlns:d="http://www.w3.org/2001/XMLSchema">testsf41</c:Value></c:KeyValueOfstringanyType>
#                    <c:KeyValueOfstringanyType><c:Key>userPrincipalName</c:Key><c:Value i:type="d:string" xmlns:d="http://www.w3.org/2001/XMLSchema">%s</c:Value></c:KeyValueOfstringanyType>
        body =  r"""<ProvisionAzureADSyncObjects xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
    <syncRequest xmlns:b="http://schemas.microsoft.com/online/aws/change/2014/06" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <b:SyncObjects>
            <b:AzureADSyncObject>
                <b:PropertyValues xmlns:c="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
                    <c:KeyValueOfstringanyType><c:Key>SourceAnchor</c:Key><c:Value i:type="d:string" xmlns:d="http://www.w3.org/2001/XMLSchema">%s</c:Value></c:KeyValueOfstringanyType>
                    <c:KeyValueOfstringanyType><c:Key>userPrincipalName</c:Key><c:Value i:type="d:string" xmlns:d="http://www.w3.org/2001/XMLSchema">%s</c:Value></c:KeyValueOfstringanyType>
                </b:PropertyValues>
                <b:SyncObjectType>User</b:SyncObjectType>
                <b:SyncOperation>Set</b:SyncOperation>
            </b:AzureADSyncObject>
        </b:SyncObjects>
    </syncRequest>
</ProvisionAzureADSyncObjects>""" % (sourceanchor,user_principal_name)

        message_id = str(uuid.uuid4())
        command = "ProvisionAzureADSyncObjects"
        envelope  = self.create_syncenvelope(self.token,command,body,message_id,binary=True)
        response = self.call_adsyncapi(envelope,command,tenant_id,message_id)
        return self.binarytoxml(response)


    def search_user(self,upn_or_object_id):
        return self.graphrbac_client.users.get(upn_or_object_id,proxies=self.proxies)

    #https://github.com/Gerenios/AADInternals/blob/9cc2a3673248dbfaf0dccf960481e7830a395ea8/AzureADConnectAPI.ps1#L1087
    def set_userpassword(self,cloudanchor=None,sourceanchor=None,userprincipalname=None,password=None,hashnt=None,changedate=None,iterations=1000,):
        tenant_id = self.tenant_id
        credentialdata = self.create_aadhash(hashnt=hashnt,password=password,iterations=iterations)

        if userprincipalname and (not cloudanchor) and (not sourceanchor):
            cloudanchor = 'User_' + self.search_user(userprincipalname).object_id

        if not changedate :
            changedate = datetime.datetime.now()

        if cloudanchor :
            cloudanchordata = "<b:CloudAnchor>%s</b:CloudAnchor>" % cloudanchor
        else:
            cloudanchordata =  '<b:CloudAnchor i:nil="true"/>'

        if sourceanchor:
            sourceanchordata= '<b:SourceAnchor>%s</b:SourceAnchor>' % sourceanchor
        else:
            sourceanchordata= '<b:SourceAnchor i:nil="true"/>'

        body = r'''<ProvisionCredentials xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
                <request xmlns:b="http://schemas.datacontract.org/2004/07/Microsoft.Online.Coexistence.Schema" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
                    <b:RequestItems>
                        <b:SyncCredentialsChangeItem>
                            <b:ChangeDate>%s</b:ChangeDate>
                            %s
                            <b:CredentialData>%s</b:CredentialData>
                            <b:ForcePasswordChangeOnLogon>false</b:ForcePasswordChangeOnLogon>
                            %s
                            <b:WindowsLegacyCredentials i:nil="true"/>
                            <b:WindowsSupplementalCredentials i:nil="true"/>
                        </b:SyncCredentialsChangeItem>
                    </b:RequestItems>
                </request>
            </ProvisionCredentials>''' % ( '%sZ' % changedate.isoformat() ,cloudanchordata, credentialdata,sourceanchordata )

        message_id = str(uuid.uuid4())
        command = "ProvisionCredentials"
        envelope  = self.create_syncenvelope(self.token,command,body,message_id,binary=True)
        response = self.call_adsyncapi(envelope,command,tenant_id,message_id)
        respxml = self.binarytoxml(response)
        if not "<b:Result>0</b:Result>" in str(respxml):
            raise Exception(respxml)

        return respxml



    # https://github.com/Gerenios/AADInternals/blob/b135545d50a5a473c942139182265850f9d256c2/AzureADConnectAPI_utils.ps1#L279
    def create_aadhash(self,hashnt=None,iterations = 1000,password=None):
        if not hashnt:
            if not password:
                raise Exception('Please provide hashnt or password')
            hashnt = nthash.encrypt(password).upper()
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

    #https://github.com/Gerenios/AADInternals/blob/b135545d50a5a473c942139182265850f9d256c2/AzureADConnectAPI_utils.ps1#L77
    def create_syncenvelope(self,token,command,body,message_id,server="adminwebservice.microsoftonline.com",binary=True,isinstalledondc=False,richcoexistenceenabled=False,version=1):

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
            return self.xmltobinary(envelope)
        else:
            return envelope

    #https://github.com/Gerenios/AADInternals/blob/b135545d50a5a473c942139182265850f9d256c2/AzureADConnectAPI_utils.ps1#L166
    def call_adsyncapi(self,envelope,command,tenant_id,message_id,server="adminwebservice.microsoftonline.com"):
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

        r = requests.post("https://%s/provisioningservice.svc" % server, headers=headers,data=envelope,proxies=self.proxies)

        return r.content



    def binarytoxml(self,binaryxml):
        fp = io.BytesIO(binaryxml)
        records = Record.parse(fp)
        fp = io.StringIO()
        print_records(records,fp=fp)
        fp.seek(0)
        data = fp.read()
        return str(data)

    def xmltobinary(self,dataxml):
        r = XMLParser.parse(dataxml)
        data = dump_records(r)
        return data
