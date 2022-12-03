from AADInternals import AADInternals

#FROM AADInternals POWERSHELL WITH Get-AADIntAccessTokenForAADGraph
token = '123'
tenant_id= 'c07608fa-c211-410c-a884-08852225d400'
az = AADInternals(tenant_id=tenant_id,token=token)

#print(az.set_userpassword(hashnt="0366F5C43990657D4AF37BC470E0EF97",cloudanchor='User_a95265fd-ab31-4ffb-8140-77224583da98'))
print(az.set_userpassword(hashnt="0366F5C43990657D4AF37BC470E0EF97",cloudanchor='User_a95265fd-ab31-4ffb-8140-77224583da98'))
