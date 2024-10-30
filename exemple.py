from AADInternals import AADInternals

#az = AADInternals(tenant_id='00000000-0000-0000-0000-000000000000')
az = AADInternals(domain='mydomain.com')

#enable sync password feature
print(az.set_sync_features(enable_features=['PasswordHashSync']))

#create account
#az.set_azureadobject('sourceanchortest',"test@mydomain.com",netBiosName='MYDOMAIN',givenName='givenName',dnsDomainName='dnsDomainName',displayName="displayName",surname='surname',commonName='commonName')

#Send password (if error is "2")  please wait ...
#print(az.set_userpassword(hashnt="8846F7EAEE8FB117AD06BDD830B7586C",sourceanchor='sourceanchortest'))

#create group with member
#print(az.set_azureadobject("testgroup",usertype='Group',SecurityEnabled=True,displayName='testgroup',groupMembers=["sourceanchortest"]))

