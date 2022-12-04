from AADInternals import AADInternals
az = AADInternals(mail="admin@mydomain.com",password="password")

#password
print(az.set_userpassword(password="password",userprincipalname='test@mydomain.com'))

#hashnt
print(az.set_userpassword(hashnt="8846F7EAEE8FB117AD06BDD830B7586C",userprincipalname='test@mydomain.com'))

