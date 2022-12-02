#-------------------------------------------------------------------------------
# Name:        module1
# Purpose:
#
# Author:      sfonteneau
#
# Created:     01/12/2022
# Copyright:   (c) sfonteneau 2022
#-------------------------------------------------------------------------------

#https://github.com/DeltaSystems/python-wcfbin.git
from wcf.xml2records import XMLParser
from wcf.records import dump_records
from wcf.records import Record, print_records

from aadhash import create_aadhash
import requests
import datetime
import io
import uuid


#FROM AADInternals POWERSHELL WITH Get-AADIntAccessTokenForAADGraph
token = r"""123456"""

guid = str(uuid.uuid4())

hashnt = "0366F5C43990657D4AF37BC470E0EF97"
cloudanchor = "User_a95265fd-ab31-4ffb-8140-77224583d999"
tenantid = "c07608fa-c211-410c-a884-08852225d444"

dataxml = r"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/online/aws/change/2010/01/IProvisioningWebService/ProvisionCredentials</a:Action>
        <SyncToken s:role="urn:microsoft.online.administrativeservice" xmlns="urn:microsoft.online.administrativeservice" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
	        <ApplicationId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">1651564e-7ce4-4d99-88be-0a65050d8dc3</ApplicationId>
	        <BearerToken xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">%s</BearerToken>
	        <ClientVersion xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">8.0</ClientVersion>
	        <DirSyncBuildNumber xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">1.5.29.0</DirSyncBuildNumber>
	        <FIMBuildNumber xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">1.5.29.0</FIMBuildNumber>
	        <IsInstalledOnDC xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">False</IsInstalledOnDC>
	        <IssueDateTime xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">0001-01-01T00:00:00</IssueDateTime>
	        <LanguageId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">en-US</LanguageId>
	        <LiveToken xmlns="http://schemas.microsoft.com/online/aws/change/2010/01"/>
	        <ProtocolVersion xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">2.0</ProtocolVersion>
	        <RichCoexistenceEnabled xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">False</RichCoexistenceEnabled>
	        <TrackingId xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">%s</TrackingId>
        </SyncToken>
        <a:MessageID>urn:uuid:%s</a:MessageID>
        <a:ReplyTo>
	        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">https://adminwebservice.microsoftonline.com/provisioningservice.svc</a:To>
    </s:Header>
    <s:Body>
        		<ProvisionCredentials xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
    <request xmlns:b="http://schemas.datacontract.org/2004/07/Microsoft.Online.Coexistence.Schema" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <b:RequestItems>
	        <b:SyncCredentialsChangeItem>
		        <b:ChangeDate>%sZ</b:ChangeDate>
		        <b:CloudAnchor>%s</b:CloudAnchor>
		        <b:CredentialData>%s</b:CredentialData>
		        <b:ForcePasswordChangeOnLogon>false</b:ForcePasswordChangeOnLogon>
		        <b:SourceAnchor i:nil="true"/>
		        <b:WindowsLegacyCredentials i:nil="true"/>
		        <b:WindowsSupplementalCredentials i:nil="true"/>
	        </b:SyncCredentialsChangeItem>
        </b:RequestItems>
    </request>
</ProvisionCredentials>
    </s:Body>
</s:Envelope>""" % (token,guid,guid,datetime.datetime.now().isoformat(),cloudanchor,create_aadhash(hashnt))


def main():

    r = XMLParser.parse(dataxml)
    data = dump_records(r)

    headers = {
            'Content-type': 'application/soap+msbin1',
            "x-ms-aadmsods-clientversion": "8.0",
            "x-ms-aadmsods-dirsyncbuildnumber": "1.5.29.0",
            "User-Agent":"",
            "x-ms-aadmsods-fimbuildnumber":   "1.5.29.0",
            "Host":"adminwebservice.microsoftonline.com",
            "x-ms-aadmsods-tenantid" : tenantid,
            "client-request-id": "b9e8fb31-c315-473f-96a8-b13c1faca186",
            "x-ms-aadmsods-appid":"1651564e-7ce4-4d99-88be-0a65050d8dc3",
            "x-ms-aadmsods-apiaction": "ProvisionCredentials"
    }
    
    r = requests.post("https://adminwebservice.microsoftonline.com/provisioningservice.svc", headers=headers,data=data)

    fp = io.BytesIO(r.content)
    records = Record.parse(fp)
    print_records(records)

if __name__ == '__main__':
    main()
