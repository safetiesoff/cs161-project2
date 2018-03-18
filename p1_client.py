"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
from binascii import hexlify

def path_join(*strings):                                  
    """Joins a list of strings putting a "/" between each.
                                                          
    :param strings: a list of strings to join             
    :returns: a string                                    
    """                                                   
    return '/'.join(strings)                              

class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)

    def resolve_loc(self, fname, num_times=500):                              
        """
        some jankier key generation scheme from given elgamal key
        """
        res = 'some_set_start'
        for i in range(num_times):
            res = self.crypto.cryptographic_hash(res + fname + self.username + str(self.elg_priv_key.x), hash_name='SHA256')
        return res

    def encode(self, loc, value):
        aes_key = self.resolve_loc('aesaesaes' + loc,num_times=100)[:64]
        nonce = self.crypto.get_random_bytes(8)
        counter = self.crypto.new_counter(64, prefix = nonce)
        mac_key = self.resolve_loc('macmacmac' + loc,num_times=105)[:64]
        print(len(aes_key))
        aes_val = self.crypto.symmetric_encrypt(value, aes_key, cipher_name='AES', mode_name='CTR', counter=counter) 
        mac_val = self.crypto.message_authentication_code(nonce + aes_val, mac_key, hash_name='SHA256')
        return  mac_val+nonce+aes_val

    def decode_verify(self, loc, value):
        mac_key = self.resolve_loc('macmacmac' + loc,num_times=105)[:64]
        mac_val = self.crypto.message_authentication_code(value[64:], mac_key, hash_name='SHA256')                      
        flag = (mac_val == value[:64])
        if not flag:
            raise IntegrityError
 
        aes_key = self.resolve_loc('aesaesaes' + loc,num_times=100)[:64]
        nonce = value[64:64+16] 
        counter = self.crypto.new_counter(64, prefix = nonce)
        message = self.crypto.symmetric_decrypt(value[16+64:], aes_key, cipher_name='AES', mode_name='CTR', counter=counter) 
        return message

    """
    def resolve_location():
        while still pointer:
            decode_verify
        
    """

    def upload(self, name, value):
        # Replace with your implementation
        loc = self.resolve_loc(name)
        data = self.encode(loc, value)
        self.storage_server.put(loc, data)

    def download(self, name):
        # Replace with your implementation
        loc = self.resolve_loc(name)
                                                          
        resp = self.storage_server.get(loc)             
        if resp is None:                                  
            return None 
        data = self.decode_verify(loc, resp)
                         
        return data 

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
