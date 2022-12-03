from azureadconnectapi_utils import create_aadhash,create_syncenvelope,call_adsyncapi
from commonutils import binarytoxml
import uuid
import datetime

def set_userpassword(accesstoken,tenant_id,cloudanchor=None,sourceanchor=None,userprincipalname=None,password=None,hashnt=None,changedate=None,iterations=1000,):

    credentialdata = create_aadhash(hashnt=hashnt,password=password,iterations=iterations)

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
    envelope  = create_syncenvelope(accesstoken,command,body,message_id,binary=True)
    response = call_adsyncapi(envelope,command,tenant_id,message_id)
    return binarytoxml(response)

