from AADInternals import AADInternals
az = AADInternals(mail="admin@mydomain.com",password="password")

#create account
az.set_azureadobject('sourceanchortest',"test@mydomain.com",netBiosName='MYDOMAIN',givenName='givenName',dnsDomainName='dnsDomainName',displayName="displayName",surname='surname',commonName='commonName')

#Send password (if error is "2")  please wait ...
print(az.set_userpassword(hashnt="8846F7EAEE8FB117AD06BDD830B7586C",sourceanchor='sourceanchortest'))

#create group with member
print(az.set_azureadobject("testgroup",usertype='Group',SecurityEnabled=True,displayName='testgroup',groupMembers=["sourceanchortest"]))

