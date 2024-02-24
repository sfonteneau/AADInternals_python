from azure.common.credentials import UserPassCredentials
from azure.graphrbac import GraphRbacManagementClient
from hashlib import pbkdf2_hmac
from passlib.hash import nthash
from adal import AuthenticationContext
from msrestazure.azure_active_directory import AADTokenCredentials
from urllib import parse
import string
import json
import sys
import os

if "__file__" in locals():
    sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)),'python_wcfbin'))
    sys.path.append(os.path.dirname(os.path.realpath(__file__)))

from python_wcfbin.wcf.xml2records import XMLParser
from python_wcfbin.wcf.records import dump_records
from python_wcfbin.wcf.records import Record, print_records
import io
import requests
import random
import uuid
import datetime
import xmltodict

aadsync_server=        "adminwebservice.microsoftonline.com"
aadsync_client_version="8.0"
aadsync_client_build=  "2.2.8.0"

class AADInternals():

    def __init__(self, mail=None, password=None,proxies={},use_cache=True,save_to_cache=True,tenant_id=None,cache_file=os.path.join(os.path.dirname(os.path.realpath(__file__)),'last_token.json')):
        """
        Establish a connection with Microsoft and attempts to retrieve a token from Microsoft servers.
        Is initialization interactive if cache is not available : (M.F.A.)

        Args:
            mail (str): Deprecated , Login azure ad (Requires a right global admin), Can be left as None to use a browser connection (MFA, recommended)
            password (str): password associated with that of the e-mail if the e-mail is entered
            proxies (dict): Specify proxies if needed.
            use_cache (bool): Define if the cache_file is used (last token generated if exists)
            save_to_cache (bool): Define if the token give is backup in cache_file
            tenant_id (str): tenant id azure
            cache_file (str): Path to the cache_file (last token generated)

        Returns:
            None

        >>> az = AADInternals(tenant_id='00000000-0000-0000-0000-000000000000')

        """

        self.proxies=proxies
        token_response = None
        self.requests_session_call_adsyncapi = requests.Session()
        

        if use_cache:
            if os.path.isfile(cache_file) :
                with open(cache_file,'r') as f:
                    old_token=json.loads(f.read())

                if tenant_id :
                    if tenant_id != old_token['tenant_id']:
                        print('ERROR New tenant_id detect, please delete %s' % cache_file)             
                        sys.exit(1)

                context = AuthenticationContext("https://login.microsoftonline.com/" + old_token['tenant_id'],proxies=proxies)
                try:
                    token_response = context.acquire_token_with_refresh_token(
                        old_token['refresh_token'],
                        old_token['_client_id'],
                        old_token['resource']
                        )
                    token_response['tenant_id'] = old_token['tenant_id']
                    token_response['resource'] = old_token['resource']
                    token_response['_client_id'] = old_token['_client_id']
                    token_response['refresh_token'] = old_token['refresh_token']
                    token_response['access_token'] = token_response['accessToken']
                except:
                    pass

        if not token_response :
            if password :
                try:
                    self.credentials = UserPassCredentials(mail, password, resource="https://graph.windows.net",proxies=proxies)
                    token_response = self.credentials.token
                    tenant_id = token_response['tenant_id']
                except:
                    pass
        
        if not token_response :
            if not tenant_id:
                print('Error, Please provide tenant_id')
                sys.exit(1)
            TEMPLATE_AUTHZ_URL = ('https://login.windows.net/{}/oauth2/authorize?' + 'response_type=code&client_id={}&redirect_uri={}&' +'state={}&resource={}')
            auth_state = (''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits)for _ in range(48)))
            authorization_url = TEMPLATE_AUTHZ_URL.format(tenant_id,"04b07795-8ddb-461a-bbee-02f9e1bf7b46","http://localhost",auth_state,"2ff814a6-3304-4ab8-85cb-cd0e6f879c1d")
            print('visit this website and give the link back which goes to localhost:')
            print(authorization_url)  
            respurl = input('\n\nURL returned by Microsoft : \n')
            code=parse.parse_qs(parse.urlparse(respurl).query)['code'][0]
            state = parse.parse_qs(parse.urlparse(respurl).query)['state'][0]
            if state != auth_state:
                raise ValueError('state does not match')
            context = AuthenticationContext("https://login.microsoftonline.com/" + tenant_id,proxies=proxies)
            token_response = context.acquire_token_with_authorization_code(code,"http://localhost",'https://graph.windows.net',"04b07795-8ddb-461a-bbee-02f9e1bf7b46")
            token_response['tenant_id'] = tenant_id
            token_response['access_token'] = token_response['accessToken']
            token_response['_client_id'] = token_response['_clientId']
            token_response['refresh_token'] = token_response['refreshToken']

        
        if save_to_cache:
            with open(cache_file,'w') as f:
                f.write(json.dumps(token_response))

        self.tenant_id = token_response['tenant_id']
        self.token = token_response['access_token']
        self.graphrbac_client = GraphRbacManagementClient(AADTokenCredentials(token_response),self.tenant_id)

    #https://github.com/Gerenios/AADInternals/blob/1561dc64568aa7c1a411e85d75ae2309c51d0633/GraphAPI_utils.ps1#L7
    def call_graphapi(self,Command,ApiVersion="1.61-internal",Method="Get",Body=None,Headers={},QueryString=None):
        Headers['Authorization'] = "Bearer %s" % self.token
        Headers['Content-type'] = 'application/json; charset=utf-8'

        r = getattr(requests, Method.lower())

        data = r(rf"https://graph.windows.net/{self.tenant_id}/{Command}?api-version={ApiVersion}{QueryString if QueryString else ''}", headers=Headers,data=Body,proxies=self.proxies)
        return json.loads(data.content)

    #https://github.com/Gerenios/AADInternals/blob/1561dc64568aa7c1a411e85d75ae2309c51d0633/GraphAPI.ps1#L73
    def get_devices(self,include_immutable_id=True):
        """
        Extracts tenant devices

        Args:
            include_immutable_id (bool): defined if the immutable_id will be included (takes longer)

        Returns:
            list of dicts: [{"odata.type": "Microsoft.DirectoryServices.Device","objectType": "Device", ... }, ...]

        """

        r = self.call_graphapi('devices')['value']

        result = []
        if include_immutable_id:
            dict_cloudanchor_sourceanchor = self.get_dict_cloudanchor_sourceanchor()
        else:
            dict_cloudanchor_sourceanchor = {}

        for data in r :
            if str('Device_' + data['objectId']) in dict_cloudanchor_sourceanchor:
                data['immutable_id'] = dict_cloudanchor_sourceanchor[str('Device_' + data['objectId'])]
            else:
                if include_immutable_id :
                    data['immutable_id'] = None
            result.append(data)
        return result

    #https://github.com/Gerenios/AADInternals/blob/9cc2a3673248dbfaf0dccf960481e7830a395ea8/AzureADConnectAPI.ps1#L8
    def get_syncconfiguration(self):
        """
        Gets tenant's synchronization configuration using Provisioning and Azure AD Sync API.
        If the user doesn't have admin rights, only a subset of information is returned.

        Returns:
            dicts: {'AllowedFeatures': 'None', 'AnchorAttribute': None, 'ApplicationVersion': None , ...}

        """
        body = '''<GetCompanyConfiguration xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
            <includeLicenseInformation>false</includeLicenseInformation>
        </GetCompanyConfiguration>'''
        message_id = str(uuid.uuid4())
        command = "GetCompanyConfiguration"
        envelope  = self.create_syncenvelope(self.token,command,body,message_id,binary=True)
        response = self.call_adsyncapi(envelope,command,self.tenant_id,message_id)
        data = self.xml_to_result(self.binarytoxml(response),command)
        dict_data = {"AllowedFeatures" :                        data["AllowedFeatures"],
                "AnchorAttribute" :                             data["DirSyncConfiguration"].get("AnchorAttribute",""),
                "ApplicationVersion" :                          data["DirSyncConfiguration"].get("ApplicationVersion",""),
                "ClientVersion" :                               data["DirSyncConfiguration"].get("ClientVersion",""),
                "DirSyncClientMachine" :                        data["DirSyncConfiguration"].get("CurrentExport",{}).get("DirSyncClientMachineName",""),
                "DirSyncFeatures" :                             int(data["DirSyncFeatures"]),
                "DisplayName" :                                 data["DisplayName"],
                "IsDirSyncing" :                                data["IsDirSyncing"],
                "IsPasswordSyncing" :                           data["IsPasswordSyncing"],
                "IsTrackingChanges" :                           data["DirSyncConfiguration"].get("IsTrackingChanges",""),
                "MaxLinksSupportedAcrossBatchInProvision" :     data["MaxLinksSupportedAcrossBatchInProvision2"],
                "PreventAccidentalDeletion" :                   data["DirSyncConfiguration"].get("PreventAccidentalDeletion",{}).get("DeletionPrevention",''),
                "SynchronizationInterval" :                     data["SynchronizationInterval"],
                "TenantId" :                                    data["TenantId"],
                "TotalConnectorSpaceObjects" :                  data["DirSyncConfiguration"].get("CurrentExport",{}).get("TotalConnectorSpaceObjects",''),
                "TresholdCount" :                               data["DirSyncConfiguration"].get("PreventAccidentalDeletion",{}).get("ThresholdCount",''),
                "TresholdPercentage" :                          data["DirSyncConfiguration"].get("PreventAccidentalDeletion",{}).get("ThresholdPercentage",''),
                "UnifiedGroupContainer" :                       data["DirSyncConfiguration"].get("Writeback",{}).get("UnifiedGroupContainer",{}).get('@i:nil',''),
                "UserContainer" :                               data["DirSyncConfiguration"].get("Writeback",{}).get("UserContainer",{}).get('@i:nil',''),
            }
        return dict_data

    #https://github.com/Gerenios/AADInternals/blob/9cc2a3673248dbfaf0dccf960481e7830a395ea8/AzureADConnectAPI.ps1#L515
    def update_syncfeatures(self,feature=None):
        body = '''<SetCompanyDirsyncFeatures xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
            <dirsyncFeatures>%s</dirsyncFeatures>
        </SetCompanyDirsyncFeatures>''' % feature
        message_id = str(uuid.uuid4())
        command = "SetCompanyDirsyncFeatures"
        envelope  = self.create_syncenvelope(self.token,command,body,message_id,binary=True)
        response = self.call_adsyncapi(envelope,command,self.tenant_id,message_id)
        return self.binarytoxml(response)

    #https://github.com/Gerenios/AADInternals/blob/fd6474e840f457c32a297cadbad051cabe2a019b/ProvisioningAPI.ps1#L4582
    def get_companyinformation(self):
        body = '''<b:ReturnValue i:nil="true"/>''' 
        command = "GetCompanyInformation"
        envelope  = self.create_envelope(self.token,command,body)
        response = self.call_provisioningapi(envelope)
        return  self.xml_to_result(response,command)['b:ReturnValue']
       

    #https://github.com/Gerenios/AADInternals/blob/fd6474e840f457c32a297cadbad051cabe2a019b/ProvisioningAPI.ps1#L2870
    def get_users(self,pagesize=500,sortdirection="Ascending",sortfield="None",searchstring=""):
        body = rf'''<b:UserSearchDefinition xmlns:c="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration">
			    <c:PageSize>{pagesize}</c:PageSize>
                <c:SearchString>{searchstring}</c:SearchString>
			    <c:SortDirection>{sortdirection}</c:SortDirection>
			    <c:SortField>{sortfield}</c:SortField>
			    <c:AccountSku i:nil="true"/>
			    <c:AdministrativeUnitObjectId i:nil="true"/>
			    <c:BlackberryUsersOnly i:nil="true"/>
			    <c:City i:nil="true"/>
			    <c:Country i:nil="true"/>
			    <c:Department i:nil="true"/>
			    <c:DomainName i:nil="true"/>
			    <c:EnabledFilter i:nil="true"/>
			    <c:HasErrorsOnly i:nil="true"/>
			    <c:IncludedProperties i:nil="true"/>
			    <c:IndirectLicenseFilter i:nil="true"/>
			    <c:LicenseReconciliationNeededOnly i:nil="true"/>
			    <c:ReturnDeletedUsers i:nil="true"/>
			    <c:State i:nil="true"/>
			    <c:Synchronized i:nil="true"/>
			    <c:Title i:nil="true"/>
			    <c:UnlicensedUsersOnly i:nil="true"/>
			    <c:UsageLocation i:nil="true"/>
		    </b:UserSearchDefinition>''' 
        command = "ListUsers"
        envelope  = self.create_envelope(self.token,command,body)
        response = self.call_provisioningapi(envelope)
        return  self.xml_to_result(response,command)['b:ReturnValue']

    #https://github.com/Gerenios/AADInternals/blob/fd6474e840f457c32a297cadbad051cabe2a019b/ProvisioningAPI.ps1#L3988
    def get_userbyobjectid(self,objectid,returndeletedusers=False):
        body = rf'''<b:ObjectId>{objectid}</b:ObjectId>
		    <b:ReturnDeletedUsers>{str(returndeletedusers).lower()}</b:ReturnDeletedUsers>'''
        command = "GetUser"
        envelope  = self.create_envelope(self.token,command,body)
        response = self.call_provisioningapi(envelope)
        return  self.xml_to_result(response,command)['b:ReturnValue']

    #https://github.com/Gerenios/AADInternals/blob/fd6474e840f457c32a297cadbad051cabe2a019b/ProvisioningAPI.ps1#L6119
    def get_group(self,objectid):
        body = rf'''<b:ObjectId>{objectid}</b:ObjectId>'''
        command = "GetGroup"
        envelope  = self.create_envelope(self.token,command,body)
        response = self.call_provisioningapi(envelope)
        return  self.xml_to_result(response,command)['b:ReturnValue']



    #https://github.com/Gerenios/AADInternals/blob/fd6474e840f457c32a297cadbad051cabe2a019b/ProvisioningAPI.ps1#L715
    def get_groups(self,pagesize=500,sortdirection="Ascending",sortfield="None"):
        body = rf'''<b:GroupSearchDefinition xmlns:c="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration">
                <c:PageSize>{pagesize}</c:PageSize>
                <c:SearchString i:nil="true"/>
                <c:SortDirection>{sortdirection}</c:SortDirection>
                <c:SortField>{sortfield}</c:SortField>
                <c:AccountSku i:nil="true"/>
                <c:GroupType i:nil="true"/>
                <c:HasErrorsOnly i:nil="true"/>
                <c:HasLicenseErrorsOnly i:nil="true"/>
                <c:IncludedProperties i:nil="true"/>
                <c:IsAgentRole i:nil="true"/>
                <c:UserObjectId i:nil="true"/>
                <c:UserPrincipalName i:nil="true"/>
            </b:GroupSearchDefinition>''' 
        command = "ListGroups"
        envelope  = self.create_envelope(self.token,command,body)
        response = self.call_provisioningapi(envelope)
        return  self.xml_to_result(response,command)['b:ReturnValue']

    #https://github.com/Gerenios/AADInternals/blob/fd6474e840f457c32a297cadbad051cabe2a019b/ProvisioningAPI.ps1#L4332
    def get_groupsmembers(self,objectid,pagesize=500,sortdirection="Ascending",sortfield="None"):
        body = rf'''<b:GroupMemberSearchDefinition xmlns:c="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration">
			    <c:PageSize>{pagesize}</c:PageSize>
			    <c:SearchString i:nil="true"/>
			    <c:SortDirection>{sortdirection}</c:SortDirection>
			    <c:SortField>{sortfield}</c:SortField>
			    <c:GroupObjectId>{objectid}</c:GroupObjectId>
			    <c:IncludedProperties i:nil="true"/>
			    <c:MemberObjectTypes i:nil="true"/>
		    </b:GroupMemberSearchDefinition>'''
        command = "ListGroupMembers"
        envelope  = self.create_envelope(self.token,command,body)
        response = self.call_provisioningapi(envelope)
        return  self.xml_to_result(response,command)['b:ReturnValue']



    #https://github.com/Gerenios/AADInternals/blob/fd6474e840f457c32a297cadbad051cabe2a019b/ProvisioningAPI.ps1#L3404
    def set_adsyncenabled(self,enabledirsync=True):
        """
        Enables or disables directory synchronization using provisioning API.
        Enabling / disabling the synchrnoization usually takes less than 10 seconds. Check the status using Get-AADIntCompanyInformation.
        """
        body = '''<b:EnableDirSync>%s</b:EnableDirSync>''' % str(bool(enabledirsync)).lower()
        message_id = str(uuid.uuid4())
        command = "SetCompanyDirSyncEnabled"
        envelope  = self.create_envelope(self.token,command,body)
        response = self.call_provisioningapi(envelope)
        return self.xml_to_result(response,command)


    #https://github.com/Gerenios/AADInternals/blob/fd6474e840f457c32a297cadbad051cabe2a019b/ProvisioningAPI.ps1#L5561
    def set_userlicenses(self,objectid):
        body = rf'''<b:AddLicenses i:nil="true"/>
            <b:ObjectId>{objectid}</b:ObjectId>
            <b:RemoveLicenses i:nil="true"/>
            <b:LicenseOptions i:nil="true"/>'''
        command = "SetUserLicenses"
        envelope  = self.create_envelope(self.token,command,body)
        response = self.call_provisioningapi(envelope)
        return response

    #https://github.com/Gerenios/AADInternals/blob/9cc2a3673248dbfaf0dccf960481e7830a395ea8/AzureADConnectAPI.ps1#L784
    def remove_azureadoject(self,sourceanchor=None,objecttype=None):
        """Removes Azure AD object using Azure AD Sync API"""
        body = '''<ProvisionAzureADSyncObjects xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
			<syncRequest xmlns:b="http://schemas.microsoft.com/online/aws/change/2014/06" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
				<b:SyncObjects>
					<b:AzureADSyncObject>
						<b:PropertyValues xmlns:c="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
                            <c:KeyValueOfstringanyType><c:Key>SourceAnchor</c:Key><c:Value i:type="d:string" xmlns:d="http://www.w3.org/2001/XMLSchema">%s</c:Value></c:KeyValueOfstringanyType>
                        </b:PropertyValues>
						<b:SyncObjectType>%s</b:SyncObjectType>
						<b:SyncOperation>Delete</b:SyncOperation>
					</b:AzureADSyncObject>
				</b:SyncObjects>
			</syncRequest>
		</ProvisionAzureADSyncObjects>''' % (sourceanchor,objecttype)
        message_id = str(uuid.uuid4())
        command = "ProvisionAzureADSyncObjects"
        envelope  = self.create_syncenvelope(self.token,command,body,message_id,binary=True)
        response = self.call_adsyncapi(envelope,command,self.tenant_id,message_id)
        return self.binarytoxml(response)



    #https://github.com/Gerenios/AADInternals/blob/9cc2a3673248dbfaf0dccf960481e7830a395ea8/AzureADConnectAPI.ps1#L1585
    def get_kerberosdomainsyncconfig(self):
        body = '''<GetKerberosDomainSyncConfig xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
        </GetKerberosDomainSyncConfig>'''
        message_id = str(uuid.uuid4())
        command = "GetKerberosDomainSyncConfig"
        envelope  = self.create_syncenvelope(self.token,command,body,message_id,binary=True)
        response = self.call_adsyncapi(envelope,command,self.tenant_id,message_id)
        return self.binarytoxml(response)

    #https://github.com/Gerenios/AADInternals/blob/9cc2a3673248dbfaf0dccf960481e7830a395ea8/AzureADConnectAPI.ps1#L1665
    def get_kerberosdomain(self,domainname):
        body = '''<GetKerberosDomain xmlns="http://schemas.microsoft.com/online/aws/change/2010/01" i:nil="true" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
            <dnsDomainName>%s</dnsDomainName>
        </GetKerberosDomain>''' % domainname
        message_id = str(uuid.uuid4())
        command = "GetKerberosDomain"
        envelope  = self.create_syncenvelope(self.token,command,body,message_id,binary=True)
        response = self.call_adsyncapi(envelope,command,self.tenant_id,message_id)
        return self.binarytoxml(response)


    #https://github.com/Gerenios/AADInternals/blob/9cc2a3673248dbfaf0dccf960481e7830a395ea8/AzureADConnectAPI.ps1#L1743
    def get_windowscredentialssyncconfig(self):
        body = '''<GetMonitoringTenantCertificate xmlns="http://schemas.microsoft.com/online/aws/change/2010/01"></GetMonitoringTenantCertificate>'''
        message_id = str(uuid.uuid4())
        command = "GetMonitoringTenantCertificate"
        envelope  = self.create_syncenvelope(self.token,command,body,message_id,binary=True)
        response = self.call_adsyncapi(envelope,command,self.tenant_id,message_id)
        return self.binarytoxml(response)


    #https://github.com/Gerenios/AADInternals/blob/9cc2a3673248dbfaf0dccf960481e7830a395ea8/AzureADConnectAPI.ps1#L1881
    def get_syncdeviceconfiguration(self):
        body = '''<GetDeviceConfiguration xmlns="http://schemas.microsoft.com/online/aws/change/2010/01"></GetDeviceConfiguration>'''
        message_id = str(uuid.uuid4())
        command = "GetDeviceConfiguration"
        envelope  = self.create_syncenvelope(self.token,command,body,message_id,binary=True)
        response = self.call_adsyncapi(envelope,command,self.tenant_id,message_id)
        return self.binarytoxml(response)


    #https://github.com/Gerenios/AADInternals/blob/9cc2a3673248dbfaf0dccf960481e7830a395ea8/AzureADConnectAPI.ps1#L1972
    def get_synccapabilities(self):
        body = '''<Capabilities xmlns="http://schemas.microsoft.com/online/aws/change/2010/01" />'''
        message_id = str(uuid.uuid4())
        command = "Capabilities"
        envelope  = self.create_syncenvelope(self.token,command,body,message_id,binary=True)
        response = self.call_adsyncapi(envelope,command,self.tenant_id,message_id)
        return self.binarytoxml(response)

    #https://github.com/Gerenios/AADInternals/blob/9cc2a3673248dbfaf0dccf960481e7830a395ea8/AzureADConnectAPI.ps1#L872
    def finalize_export(self,count=0):
        body = '''<FinalizeExport xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
			<totalExported>%s</totalExported>
			<successfulExportCount>%s</successfulExportCount>
		</FinalizeExport>''' % (count,count)
        message_id = str(uuid.uuid4())
        command = "FinalizeExport"
        envelope  = self.create_syncenvelope(self.token,command,body,message_id,binary=True)
        response = self.call_adsyncapi(envelope,command,self.tenant_id,message_id)
        return self.binarytoxml(response)


    def set_sync_features(self,enable_features=[], disable_features=[]):
        feature_values = {
            "PasswordHashSync": 1,
            "PasswordWriteBack": 2,
            "DirectoryExtensions": 4,
            "DuplicateUPNResiliency": 8,
            "EnableSoftMatchOnUpn": 16,
            "DuplicateProxyAddressResiliency": 32,
            "EnforceCloudPasswordPolicyForPasswordSyncedUsers": 512,
            "UnifiedGroupWriteback": 1024,
            "UserWriteback": 2048,
            "DeviceWriteback": 4096,
            "SynchronizeUpnForManagedUsers": 8192,
            "EnableUserForcePasswordChangeOnLogon": 16384,
            "PassThroughAuthentication": 131072,
            "BlockSoftMatch": 524288,
            "BlockCloudObjectTakeoverThroughHardMatch": 1048576
        }

        access_token = self.token



        current_features = self.get_syncconfiguration()['DirSyncFeatures']

        for feature in enable_features:
            current_features = current_features | feature_values[feature]

        for feature in disable_features:
            current_features = current_features & (0x7FFFFFFF ^ feature_values[feature])


        return self.update_syncfeatures(current_features)


    #https://github.com/Gerenios/AADInternals/blob/9cc2a3673248dbfaf0dccf960481e7830a395ea8/AzureADConnectAPI.ps1#L570
    def set_azureadobject(self,
                SourceAnchor=None,
                userPrincipalName=None,
                usertype='User',
                operation_type="Set",
                accountEnabled=True,
                surname=None,
                onPremisesSamAccountName=None,
                onPremisesDistinguishedName=None,
                onPremiseSecurityIdentifier=None,
                netBiosName=None,
                lastPasswordChangeTimestamp=None,
                givenName=None,
                dnsDomainName=None,
                displayName=None,
                countryCode=None,
                commonName=None,
                cloudMastered=None,
                usageLocation=None,
                proxyAddresses=None,
                thumbnailPhoto=None,
                groupMembers=None,
                deviceId=None,
                deviceOSType=None,
                deviceTrustType=None,
                userCertificate=None,
                physicalDeliveryOfficeName=None,
                employeeId=None,
                deviceOSVersion=None,
                country=None,
                city=None,
                streetAddress=None,
                state=None,
                department=None,
                telephoneNumber=None,
                company=None,
                employeeType=None,
                facsimileTelephoneNumber=None,
                mail=None,
                mobile=None,
                title=None,
                SecurityEnabled=None,
                **kwargs
                ):
        """
        Creates or updates Azure AD object using Azure AD Sync API. Can also set cloud-only user's sourceAnchor (ImmutableId) and onPremisesSAMAccountName. SourceAnchor can only be set once!
        """
        tenant_id = self.tenant_id

        datakwargs = []
        for k in kwargs:
            datakwargs.append(self.Add_PropertyValue(k,Value=kwargs[k]))

        datakwargs = '\n'.join(datakwargs)


        command = "ProvisionAzureADSyncObjects"
        body =  rf"""<ProvisionAzureADSyncObjects xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
    <syncRequest xmlns:b="http://schemas.microsoft.com/online/aws/change/2014/06" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
        <b:SyncObjects>
            <b:AzureADSyncObject>
                <b:PropertyValues xmlns:c="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
                    {self.Add_PropertyValue("SourceAnchor",Value=SourceAnchor)}
                    {self.Add_PropertyValue("accountEnabled",Value=accountEnabled,Type="bool")}
                    {self.Add_PropertyValue("userPrincipalName",Value=userPrincipalName)}
                    {self.Add_PropertyValue("commonName",Value=commonName)}
                    {self.Add_PropertyValue("deviceOSVersion",Value=deviceOSVersion)}
                    {self.Add_PropertyValue("countryCode",Value=countryCode,Type="long")}
                    {self.Add_PropertyValue("displayName",Value=displayName)}
                    {self.Add_PropertyValue("dnsDomainName",Value=dnsDomainName)}
                    {self.Add_PropertyValue("givenName",Value=givenName)}
                    {self.Add_PropertyValue("lastPasswordChangeTimestamp",Value=lastPasswordChangeTimestamp)}
                    {self.Add_PropertyValue("netBiosName",Value=netBiosName)}
                    {self.Add_PropertyValue("onPremiseSecurityIdentifier",Value=onPremiseSecurityIdentifier,Type='base64')}
                    {self.Add_PropertyValue("onPremisesDistinguishedName",Value=onPremisesDistinguishedName)}
                    {self.Add_PropertyValue("onPremisesSamAccountName",Value=onPremisesSamAccountName)}
                    {self.Add_PropertyValue("surname",Value=surname)}
                    {self.Add_PropertyValue("cloudMastered",Value=cloudMastered,Type="bool")}
                    {self.Add_PropertyValue("usageLocation",Value=usageLocation)}
                    {self.Add_PropertyValue("ThumbnailPhoto",Value=thumbnailPhoto)}
                    {self.Add_PropertyValue("proxyAddresses",Value=proxyAddresses,Type="ArrayOfstring")}
                    {self.Add_PropertyValue("member",Value=groupMembers,Type="ArrayOfstring")}
                    {self.Add_PropertyValue("deviceId",Value=deviceId,Type="base64")}
                    {self.Add_PropertyValue("deviceTrustType",Value=deviceTrustType)}
                    {self.Add_PropertyValue("deviceOSType",Value=deviceOSType)}
                    {self.Add_PropertyValue("userCertificate",Value=userCertificate,Type='ArrayOfbase64')}
                    {self.Add_PropertyValue("physicalDeliveryOfficeName",Value=physicalDeliveryOfficeName)}
                    {self.Add_PropertyValue("department",Value=department)}
                    {self.Add_PropertyValue("employeeId",Value=employeeId)}
                    {self.Add_PropertyValue("streetAddress",Value=streetAddress)}
                    {self.Add_PropertyValue("city",Value=city)}
                    {self.Add_PropertyValue("state",Value=state)}
                    {self.Add_PropertyValue("country",Value=country)}
                    {self.Add_PropertyValue("telephoneNumber",Value=telephoneNumber)}
                    {self.Add_PropertyValue("company",Value=company)}
                    {self.Add_PropertyValue("employeeType",Value=employeeType)}
                    {self.Add_PropertyValue("facsimileTelephoneNumber",Value=facsimileTelephoneNumber)}
                    {self.Add_PropertyValue("mail",Value=mail)}
                    {self.Add_PropertyValue("mobile",Value=mobile)}
                    {self.Add_PropertyValue("title",Value=title)}
                    {self.Add_PropertyValue("SecurityEnabled",Value=SecurityEnabled,Type="bool")}
                    {datakwargs}
                </b:PropertyValues>
                <b:SyncObjectType>{usertype}</b:SyncObjectType>
                <b:SyncOperation>{operation_type}</b:SyncOperation>
            </b:AzureADSyncObject>
        </b:SyncObjects>
    </syncRequest>
</ProvisionAzureADSyncObjects>"""

        message_id = str(uuid.uuid4())
        command = "ProvisionAzureADSyncObjects"
        envelope  = self.create_syncenvelope(self.token,command,body,message_id,binary=True)
        rawresponse = self.call_adsyncapi(envelope,command,tenant_id,message_id)
        newresponse = self.xml_to_result(self.binarytoxml(rawresponse),command)['b:SyncObjectResults']['b:AzureADSyncObjectResult']
        if newresponse['b:ResultCode'] == 'Failure' or newresponse['b:ResultErrorDescription'] != {'@i:nil': 'true'}:
            raise Exception (newresponse['b:ResultErrorDescription'])
        return newresponse

    def xml_to_result(self,response,command):
        dataxml = xmltodict.parse(response)
        try:
            return dataxml["s:Envelope"]["s:Body"]["%sResponse" % command]['%sResult' % command]
        except KeyError:
            if 's:Fault' in dataxml.get("s:Envelope",{}).get("s:Body",{}):
                raise Exception(dataxml["s:Envelope"]["s:Body"]['s:Fault']['s:Reason']['s:Text']['#text'])
            else:
                raise Exception(dataxml)


    #Official api for search
    def search_user(self,upn_or_object_id):
        return self.graphrbac_client.users.get(upn_or_object_id,proxies=self.proxies)

    def list_users(self,):
        result = []
        for entry in list(self.graphrbac_client.users.list(proxies=self.proxies)) :
            result.append(entry.as_dict())
        return result

    def get_dict_cloudanchor_sourceanchor(self):
        dict_cloudanchor_sourceanchor = {}
        for entry in self.get_syncobjects(False):
            cloudanchor = None
            sourceanchor = None
            if type(entry) == str:
                continue
            for v in entry['b:PropertyValues']['c:KeyValueOfstringanyType']:
                if v['c:Key'] == "CloudAnchor":
                    cloudanchor = v["c:Value"].get('#text')
                if v['c:Key'] == "SourceAnchor":
                    sourceanchor = v["c:Value"].get('#text')

            if (not cloudanchor) or (not sourceanchor):
                continue
            dict_cloudanchor_sourceanchor[cloudanchor] = sourceanchor

        return dict_cloudanchor_sourceanchor

    def list_groups(self,include_immutable_id=True):
        result = []
        if include_immutable_id:
            dict_cloudanchor_sourceanchor = self.get_dict_cloudanchor_sourceanchor()
        else:
            dict_cloudanchor_sourceanchor = {}
        for entry in list(self.graphrbac_client.groups.list(proxies=self.proxies)) :
            data = entry.as_dict()
            if str('Group_' + data['object_id']) in dict_cloudanchor_sourceanchor:
                data['immutable_id'] = dict_cloudanchor_sourceanchor[str('Group_' + data['object_id'])]
            else:
                if include_immutable_id :
                    data['immutable_id'] = None
            result.append(data)
        return result

    #https://github.com/Gerenios/AADInternals/blob/9cc2a3673248dbfaf0dccf960481e7830a395ea8/AzureADConnectAPI.ps1#L927
    def get_syncobjects(self,fullsync=True,version=2):
        if version==2:
            txtvers="2"
        else:
            txtvers=""
        body = '''<ReadBackAzureADSyncObjects%s xmlns="http://schemas.microsoft.com/online/aws/change/2010/01">
            <includeLicenseInformation>true</includeLicenseInformation>
            <inputCookie i:nil="true" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"></inputCookie>
            <isFullSync>%s</isFullSync>
        </ReadBackAzureADSyncObjects%s>''' % (txtvers,fullsync,txtvers)
        message_id = str(uuid.uuid4())
        command = "ReadBackAzureADSyncObjects%s" % txtvers
        envelope  = self.create_syncenvelope(self.token,command,body,message_id,binary=True)
        response = self.call_adsyncapi(envelope,command,self.tenant_id,message_id)
        dataxml = self.xml_to_result(self.binarytoxml(response),command)
        if dataxml.get('b:ResultObjects',{}) == None:
            dataxml['b:ResultObjects'] = {}
        return  dataxml.get('b:ResultObjects',{}).get('b:AzureADSyncObject',[])

    #https://github.com/Gerenios/AADInternals/blob/9cc2a3673248dbfaf0dccf960481e7830a395ea8/AzureADConnectAPI.ps1#L1087
    def set_userpassword(self,cloudanchor=None,sourceanchor=None,userprincipalname=None,password=None,hashnt=None,changedate=None,iterations=1000,):
        """
        Sets the password of the given user using Azure AD Sync API. If the Result is 0, the change was successful.
        Requires that Directory Synchronization is enabled for the tenant!
        """
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
        formatresponse = self.xml_to_result(self.binarytoxml(response),command)['b:Results']['b:SyncCredentialsChangeResult']
        if formatresponse['b:Result'] != '0':
            raise Exception(formatresponse.get('b:ExtendedErrorInformation',formatresponse))
        return formatresponse



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

    #https://github.com/Gerenios/AADInternals/blob/fd6474e840f457c32a297cadbad051cabe2a019b/ProvisioningAPI_utils.ps1#L64
    def create_envelope(self,token,command,requestelements):
        message_id = str(uuid.uuid4())
        envelope = rf'''
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
	        <s:Header>
		        <a:Action s:mustUnderstand="1">http://provisioning.microsoftonline.com/IProvisioningWebService/{command}</a:Action>
		        <a:MessageID>urn:uuid:{message_id}</a:MessageID>
		        <a:ReplyTo>
			        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		        </a:ReplyTo>
		        <UserIdentityHeader xmlns="http://provisioning.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
			        <BearerToken xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">Bearer {self.token}</BearerToken>
			        <LiveToken i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService"/>
		        </UserIdentityHeader>
		        <ClientVersionHeader xmlns="http://provisioning.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
			        <ClientId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">50afce61-c917-435b-8c6d-60aa5a8b8aa7</ClientId>
			        <Version xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">1.2.183.17</Version>
		        </ClientVersionHeader>
		        <ContractVersionHeader xmlns="http://becwebservice.microsoftonline.com/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
			        <BecVersion xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService">Version47</BecVersion>
		        </ContractVersionHeader>
		        <a:To s:mustUnderstand="1">https://provisioningapi.microsoftonline.com/provisioningwebservice.svc</a:To>
	        </s:Header>
	        <s:Body>
                <{command} xmlns="http://provisioning.microsoftonline.com/">
			        <request xmlns:b="http://schemas.datacontract.org/2004/07/Microsoft.Online.Administration.WebService" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
                        <b:BecVersion>Version16</b:BecVersion>
                        <b:TenantId>{self.tenant_id}</b:TenantId>
                        <b:VerifiedDomain i:nil="true"/>
		                {requestelements}
                    </request>
                </{command}>
	        </s:Body>
        </s:Envelope>
        '''
        return envelope


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

    #https://github.com/Gerenios/AADInternals/blob/fd6474e840f457c32a297cadbad051cabe2a019b/ProvisioningAPI_utils.ps1#L127
    def call_provisioningapi(self,envelope):
        headers = {
            'Content-type': 'application/soap+xml'
        }
        r = requests.post("https://provisioningapi.microsoftonline.com/provisioningwebservice.svc", headers=headers,data=envelope,proxies=self.proxies)
        return r.content

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
        r = self.requests_session_call_adsyncapi.post("https://%s/provisioningservice.svc" % server, headers=headers,data=envelope,proxies=self.proxies)

        return r.content


    #https://github.com/Gerenios/AADInternals/blob/b135545d50a5a473c942139182265850f9d256c2/AzureADConnectAPI_utils.ps1#L228
    #generate by chatgpt
    def Add_PropertyValue(self,Key: str, Value, Type: str = "string"):
        if Value is not None:
            PropBlock = "<c:KeyValueOfstringanyType><c:Key>" + Key + "</c:Key>"
            if Type == "long":
                PropBlock += "<c:Value i:type='d:long' xmlns:d='http://www.w3.org/2001/XMLSchema'>" + str(Value) + "</c:Value>"
            elif Type == "bool":
                PropBlock += "<c:Value i:type='d:boolean' xmlns:d='http://www.w3.org/2001/XMLSchema'>" + str(Value).lower() + "</c:Value>"
            elif Type == "base64":
                PropBlock += "<c:Value i:type='d:base64Binary' xmlns:d='http://www.w3.org/2001/XMLSchema'>" + Value + "</c:Value>"
            elif Type == "ArrayOfstring":
                PropBlock += "<c:Value i:type='c:ArrayOfstring'>"
                for stringValue in Value:
                    PropBlock += "<c:string>" + stringValue + "</c:string>"
                PropBlock += "</c:Value>"
            elif Type == "ArrayOfbase64":
                PropBlock += "<c:Value i:type='c:ArrayOfbase64Binary'>"
                for stringValue in Value:
                    PropBlock += "<c:base64Binary>" + stringValue + "</c:base64Binary>"
                PropBlock += "</c:Value>"
            else:
                if Value:
                    PropBlock +=   "<c:Value i:type='d:string' xmlns:d='http://www.w3.org/2001/XMLSchema'>" + Value + "</c:Value>"
                else:
                    PropBlock += """<c:Value i:nil="true" xmlns:d='http://www.w3.org/2001/XMLSchema'></c:Value>"""
            PropBlock += "</c:KeyValueOfstringanyType>"
            return PropBlock
        else:
            return ""


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
