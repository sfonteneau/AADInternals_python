from azureadconnectapi import set_userpassword

class AADInternals():

    def __init__(self, tenant_id=None, token=None):

        self.tenant_id = tenant_id
        self.token = token

    def set_userpassword(self,*arg, **args):
        set_userpassword(*arg, **args,accesstoken=self.token,tenant_id=self.tenant_id)