from AADInternals import AADInternals
az = AADInternals(mail="admin@mydomain.com",password="password")
print(az.set_userpassword(password="password",userprincipalname='test@mydomain.com'))
