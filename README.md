# AADInternals python

Reimplementation of part of the AAdinternals (https://github.com/Gerenios/AADInternals) project.

This project focuses on synchronizing users, groups, and password hashes with Microsoft Entra ID.

This project uses undocumented Microsoft APIs. Microsoft may change or remove them at any time.


# Install Notes

```
git clone https://github.com/tranquilit/AADInternals_python
cd AADInternals_python
git submodule update --progress --init -- "python_wcfbin"
```

Install dependencies
-----------------------------

```
apt-get install python3-passlib python3-xmltodict python3-requests python3-msal -y
```


If you are not using Debian, or if these packages are not available:

```
pip3 install -r requirements.txt
```

# Use the CLI

Example:

```
python3 main.py -help
python3 main.py --domain mydomain.com set_azureadobject  -help
python3 main.py --domain mydomain.com set_azureadobject --SourceAnchor=test00 --userPrincipalName=test00@mydomain.com
python3 main.py --domain mydomain.com set_userpassword --sourceanchor=test00 --password password
python3 main.py --domain mydomain.com get_syncconfiguration
```



