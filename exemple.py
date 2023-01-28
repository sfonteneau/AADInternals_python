from AADInternals import AADInternals
az = AADInternals(mail="admin@mydomain.com",password="password")

#create account
az.set_azureadobject("test@mydomain.com",'sourceanchor',netBiosName='MYDOMAIN',givenName='givenName',dnsDomainName='dnsDomainName',displayName="displayName",surname='surname',commonName='commonName')

#hashnt
print(az.set_userpassword(hashnt="8846F7EAEE8FB117AD06BDD830B7586C",userprincipalname='test@mydomain.com'))

