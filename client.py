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

LOC_LEN = 256
ENC_KEY_LEN = 64
MAC_KEY_LEN = 64
MAC_LEN = 64
NONCE_LEN = 16
COUNTER_LEN = 64

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

    def generate_personal_key(self, start, num_iters, fname):
        """
        Some jankier key generation scheme from given elgamal key using repeated hashes.
        """
        res = start
        for i in range(num_iters):
            res = self.crypto.cryptographic_hash(res + fname + self.username + str(self.elg_priv_key.x), hash_name='SHA256')
        return res

    def get_pointer_loc(self, fname):
        """
        Gets the location of a pointer block for this user
        """
        start = "pointerlocstart"
        return self.generate_personal_key(start, 50, fname)[:LOC_LEN]

    def get_pointer_mac(self, fname):
        start = "pointermacstart"
        return self.generate_personal_key(start, 51, fname)[:MAC_KEY_LEN]
    
    def get_pointer_key(self, fname):
        start = "pointerkeystart"
        return self.generate_personal_key(start, 52, fname)[:ENC_KEY_LEN]

    def read_verify_ptr(self, location, mac_key, decode_key):
        """
        goes to location, reads and verifies the pointer there
        returns the location of the associated headerfile, and the username of the file owner
        """
        raw = self.storage_server.get(location) 
        if raw is None:                                  
            return None, None 

        mac_val = self.crypto.message_authentication_code(raw[MAC_LEN:], mac_key, hash_name='SHA256')
        flag = (mac_val == raw[:MAC_LEN])
        if not flag:
            raise IntegrityError("pointer mac invalid")

        nonce = raw[MAC_LEN:MAC_LEN+NONCE_LEN]
        counter = self.crypto.new_counter(COUNTER_LEN, prefix = nonce)
        message = self.crypto.symmetric_decrypt(raw[MAC_LEN+NONCE_LEN:], decode_key, cipher_name='AES', mode_name='CTR', counter=counter) 
        if not message[:3] == 'PTR':
            raise IntegrityError("Value at this location is not actually pointer.")

        return message[3:LOC_LEN+3], message[LOC_LEN+3:] # location, username of owner of file who controls this header block

    def create_pointer(self, fname, pval, uname):
        loc = self.get_pointer_loc(fname)
        value = "PTR"+pval+uname

        aes_key = self.get_pointer_key(fname)
        mac_key = self.get_pointer_mac(fname)
        nonce = self.crypto.get_random_bytes(NONCE_LEN//2)
        counter = self.crypto.new_counter(COUNTER_LEN, prefix = nonce)
        aes_val = self.crypto.symmetric_encrypt(value, aes_key, cipher_name='AES', mode_name='CTR', counter=counter) 
        mac_val = self.crypto.message_authentication_code(nonce + aes_val, mac_key, hash_name='SHA256')
        self.storage_server.put(loc, mac_val+nonce+aes_val)


    def read_verify_header(self, location, mac_key, decode_key, include_metadata=False):
        """
        goes to location, reads and verifies the header file there
        returns the location, decryption key, and mac key required to read/write the actual file if not chained
        else returns the location, username of the owner who controls next header, None

        if include_metadata, contains list of people shared with
        """

        raw = self.storage_server.get(location)             
        if raw is None:                                  
            raise IntegrityError("header does not exist")

        mac_val = self.crypto.message_authentication_code(raw[MAC_LEN:], mac_key, hash_name='SHA256')
        flag = (mac_val == raw[:MAC_LEN])
        if not flag:
            raise IntegrityError("header mac invalid")

        nonce = raw[MAC_LEN:MAC_LEN+NONCE_LEN] 
        counter = self.crypto.new_counter(COUNTER_LEN, prefix = nonce)

        message = self.crypto.symmetric_decrypt(raw[MAC_LEN+NONCE_LEN:], decode_key, cipher_name='AES', mode_name='CTR', counter=counter)

        if not message[:3] == 'HDR' and not message[:3] == 'MET' :
            raise IntegrityError("Value at this location is not actually header. " + str(message[:3]))

        if include_metadata:
            if not message[:3] == 'MET':
                return message[3:LOC_LEN+3], None, None, None
            else:
                if not message[LOC_LEN+3:LOC_LEN+4] == '0':
                    raise IntegrityError("Metatdata block is chained!" + message[LOC_LEN+3:LOC_LEN+4])
                return message[3:LOC_LEN+3], message[LOC_LEN+4:LOC_LEN+ENC_KEY_LEN+4], message[LOC_LEN+ENC_KEY_LEN+4:LOC_LEN+ENC_KEY_LEN+MAC_KEY_LEN+4], message[LOC_LEN+ENC_KEY_LEN+MAC_KEY_LEN+4:]
        else:
            if message[LOC_LEN+3:LOC_LEN+4] == '1': # chained
                return message[3:LOC_LEN+3], message[LOC_LEN+4:], None
            else:
                return message[3:LOC_LEN+3], message[LOC_LEN+4:LOC_LEN+ENC_KEY_LEN+4], message[LOC_LEN+ENC_KEY_LEN+4:LOC_LEN+ENC_KEY_LEN+MAC_KEY_LEN+4]
    
    def write_metadata(self, location, value):
        aes_key = str(self.pks.get_encryption_key(self.username).y)[:ENC_KEY_LEN]
        mac_key = str(self.pks.get_encryption_key(self.username).y)[:ENC_KEY_LEN]

        raw = self.storage_server.get(location)             
        if raw is None:                                  
            raise IntegrityError("header does not exist")

        mac_val = self.crypto.message_authentication_code(raw[MAC_LEN:], mac_key, hash_name='SHA256')
        flag = (mac_val == raw[:MAC_LEN])
        if not flag:
            raise IntegrityError("header mac invalid")

        nonce = raw[MAC_LEN:MAC_LEN+NONCE_LEN] 
        counter = self.crypto.new_counter(COUNTER_LEN, prefix = nonce)

        message = self.crypto.symmetric_decrypt(raw[MAC_LEN+NONCE_LEN:], aes_key, cipher_name='AES', mode_name='CTR', counter=counter)
        if not message[:3] == 'MET':
            raise IntegrityError("trying to edit metadata of invalid type")

        value = message[:LOC_LEN+ENC_KEY_LEN+MAC_KEY_LEN+4] + value

        aes_key = str(self.pks.get_encryption_key(self.username).y)[:ENC_KEY_LEN]
        mac_key = str(self.pks.get_encryption_key(self.username).y)[:ENC_KEY_LEN]

        nonce = self.crypto.get_random_bytes(NONCE_LEN//2)
        counter = self.crypto.new_counter(COUNTER_LEN, prefix = nonce)
        aes_val = self.crypto.symmetric_encrypt(value, aes_key, cipher_name='AES', mode_name='CTR', counter=counter) 
        mac_val = self.crypto.message_authentication_code(nonce + aes_val, mac_key, hash_name='SHA256')
 
        self.storage_server.put(location, mac_val+nonce+aes_val)

    def create_header(self, file_loc, arg1, arg2, chain=False, metadata=False):
        header_location = self.crypto.get_random_bytes(LOC_LEN)[:LOC_LEN] #idk
        if chain:
            if metadata:
                raise IntegrityError("can't create chinaed metadata block!")
            #TODO for sharing
            value = 'HDR' + file_loc + "1" + arg1 + arg2
        else:
            if metadata:
                value = 'MET' + file_loc + "0" + arg1 + arg2
            else:
                value = 'HDR' + file_loc + "0" + arg1 + arg2

        aes_key = str(self.pks.get_encryption_key(self.username).y)[:ENC_KEY_LEN]
        mac_key = str(self.pks.get_encryption_key(self.username).y)[:ENC_KEY_LEN]

        nonce = self.crypto.get_random_bytes(NONCE_LEN//2)
        counter = self.crypto.new_counter(COUNTER_LEN, prefix = nonce)
        aes_val = self.crypto.symmetric_encrypt(value, aes_key, cipher_name='AES', mode_name='CTR', counter=counter) 
        mac_val = self.crypto.message_authentication_code(nonce + aes_val, mac_key, hash_name='SHA256')
 
        self.storage_server.put(header_location, mac_val+nonce+aes_val)
        return header_location

    def edit_header(self, loc, file_loc, arg1, arg2, mac_key, decode_key):
        raw = self.storage_server.get(loc)             
        if raw is None:                                  
            raise IntegrityError("header does not exist")

        mac_val = self.crypto.message_authentication_code(raw[MAC_LEN:], mac_key, hash_name='SHA256')
        flag = (mac_val == raw[:MAC_LEN])
        if not flag:
            raise IntegrityError("header mac invalid")

        nonce = raw[MAC_LEN:MAC_LEN+NONCE_LEN] 
        counter = self.crypto.new_counter(COUNTER_LEN, prefix = nonce)

        message = self.crypto.symmetric_decrypt(raw[MAC_LEN+NONCE_LEN:], decode_key, cipher_name='AES', mode_name='CTR', counter=counter)

        if not message[:3] == 'HDR' and not message[:3] == 'MET' :
            raise IntegrityError("Value at this location is not actually header.")

        if not message[LOC_LEN+3:LOC_LEN+4] == '0':
            raise IntegrityError("edit header block is chained!" + message[LOC_LEN+3:LOC_LEN+4])

        value = message[:3]+ file_loc + "0" + arg1 + arg2 + message[LOC_LEN+ENC_KEY_LEN+MAC_KEY_LEN+4:]

        aes_key = str(self.pks.get_encryption_key(self.username).y)[:ENC_KEY_LEN]
        mac_key = str(self.pks.get_encryption_key(self.username).y)[:ENC_KEY_LEN]

        nonce = self.crypto.get_random_bytes(NONCE_LEN//2)
        counter = self.crypto.new_counter(COUNTER_LEN, prefix = nonce)
        aes_val = self.crypto.symmetric_encrypt(value, aes_key, cipher_name='AES', mode_name='CTR', counter=counter) 
        mac_val = self.crypto.message_authentication_code(nonce + aes_val, mac_key, hash_name='SHA256')
 
        self.storage_server.put(loc, mac_val+nonce+aes_val)

    def read_file(self, location, mac_key, decode_key):
        raw = self.storage_server.get(location)             
        if raw is None:                                  
            raise IntegrityError("data does not exist")

        mac_val = self.crypto.message_authentication_code(raw[MAC_LEN:], mac_key, hash_name='SHA256')
        flag = (mac_val == raw[:MAC_LEN])
        if not flag:
            raise IntegrityError("header mac invalid")

        nonce = raw[MAC_LEN:MAC_LEN+NONCE_LEN] 
        counter = self.crypto.new_counter(COUNTER_LEN, prefix = nonce)

        message = self.crypto.symmetric_decrypt(raw[MAC_LEN+NONCE_LEN:], decode_key, cipher_name='AES', mode_name='CTR', counter=counter)
        if not message[:3] == 'DAT':
            raise IntegrityError("read file called on non datafile")
        return message[3:]

    def write_file(self, loc, data, mac_key, key):
        """
        Writes data to a file location
        """
        nonce = self.crypto.get_random_bytes(NONCE_LEN//2)
        counter = self.crypto.new_counter(COUNTER_LEN, prefix = nonce)
        aes_val = self.crypto.symmetric_encrypt("DAT" + data, key, cipher_name='AES', mode_name='CTR', counter=counter) 
        mac_val = self.crypto.message_authentication_code(nonce + aes_val, mac_key, hash_name='SHA256')
        write_val = mac_val+nonce+aes_val        
        self.storage_server.put(loc, write_val) 

    def upload(self, fname, value):
        header_location, file_owner_uname = self.read_verify_ptr(self.get_pointer_loc(fname), self.get_pointer_mac(fname), self.get_pointer_key(fname))
        if header_location is None:
            file_location = self.crypto.get_random_bytes(LOC_LEN)[:LOC_LEN]
            file_key = self.crypto.get_random_bytes(ENC_KEY_LEN)[:ENC_KEY_LEN]
            file_mac_key = self.crypto.get_random_bytes(MAC_KEY_LEN)[:MAC_KEY_LEN]
            header_location = self.create_header(file_location, file_key, file_mac_key, chain=False, metadata=True)
            self.write_metadata(header_location, self.username + "," + header_location)
            self.create_pointer(fname, header_location, self.username)

        else:
            loop_flag = True
            while loop_flag:
                enc_key = str(self.pks.get_encryption_key(file_owner_uname).y)[:ENC_KEY_LEN]
                mac_key = str(self.pks.get_encryption_key(file_owner_uname).y)[:ENC_KEY_LEN]
                header_location, file_owner_uname, tag = self.read_verify_header(header_location,enc_key, mac_key)
                if not tag is None:
                    file_location, file_key, file_mac_key = header_location, file_owner_uname, tag
                    loop_flag = False

        self.write_file(file_location, value, file_mac_key, file_key)

    def download(self, fname):
        header_location, file_owner_uname = self.read_verify_ptr(self.get_pointer_loc(fname), self.get_pointer_mac(fname), self.get_pointer_key(fname))
        if header_location is None:
            return None

        loop_flag = True
        while loop_flag:
            enc_key = str(self.pks.get_encryption_key(file_owner_uname).y)[:ENC_KEY_LEN]
            mac_key = str(self.pks.get_encryption_key(file_owner_uname).y)[:ENC_KEY_LEN]
            header_location, file_owner_uname, tag = self.read_verify_header(header_location,enc_key, mac_key)
            if not tag is None:
                file_location, file_key, file_mac_key = header_location, file_owner_uname, tag
                loop_flag = False
        return self.read_file(file_location, file_mac_key, file_key)

    def share(self, user, fname):
        header_location, file_owner_uname = self.read_verify_ptr(self.get_pointer_loc(fname), self.get_pointer_mac(fname), self.get_pointer_key(fname))
        if header_location is None:
            return ""

        enc_key = str(self.pks.get_encryption_key(file_owner_uname).y)[:ENC_KEY_LEN]
        mac_key = str(self.pks.get_encryption_key(file_owner_uname).y)[:ENC_KEY_LEN]
        file_location, file_key, file_mac_key, metadata  = self.read_verify_header(header_location,enc_key, mac_key, include_metadata=True)

        if not metadata is None:
            new_header_location = self.create_header(file_location, file_key, file_mac_key, chain=False, metadata=False)
            self.write_metadata(header_location, metadata+"," + user + "," + new_header_location)
        else:
            new_header_location = self.create_header(header_location, file_owner_uname, "", chain=True, metadata=False)

        c1 = self.crypto.asymmetric_encrypt(new_header_location, self.pks.get_encryption_key(user))
        s1 = self.crypto.asymmetric_sign(c1, self.rsa_priv_key)

        return c1+s1

    def receive_share(self, from_username, newname, message):
        if message == "":
            return
            
        c1, s1 = message[:1044], message[1044:]

        if not self.crypto.asymmetric_verify(c1, s1, self.pks.get_signature_key(from_username)):
            raise IntegrityError("communication tampered with") 

        location = self.crypto.asymmetric_decrypt(c1, self.elg_priv_key)

        self.create_pointer(newname, location, from_username)

    def revoke(self, user, fname):
        header_location, file_owner_uname = self.read_verify_ptr(self.get_pointer_loc(fname), self.get_pointer_mac(fname), self.get_pointer_key(fname))
        enc_key = str(self.pks.get_encryption_key(file_owner_uname).y)[:ENC_KEY_LEN]
        mac_key = str(self.pks.get_encryption_key(file_owner_uname).y)[:ENC_KEY_LEN]
        file_location, file_key, file_mac_key, metadata  = self.read_verify_header(header_location,enc_key, mac_key, include_metadata=True)
        if metadata is None:
            raise IntegrityError("trying to share file that isn't yours")

        list_users = metadata.split(",")
        index = list_users.index(user)
        del list_users[index]
        del list_users[index]

        metadata = ",".join(list_users)
        self.write_metadata(header_location, metadata)
        
        file_contents = self.read_file(file_location, file_mac_key, file_key)

        file_location = self.crypto.get_random_bytes(LOC_LEN)[:LOC_LEN]
        file_key = self.crypto.get_random_bytes(ENC_KEY_LEN)[:ENC_KEY_LEN]
        file_mac_key = self.crypto.get_random_bytes(MAC_KEY_LEN)[:MAC_KEY_LEN]

        self.write_file(file_location, file_contents, file_mac_key, file_key)

        for i in range(len(list_users)):
            if i%2 == 1:
                loc = list_users[i]
                self.edit_header(loc, file_location, file_key, file_mac_key, enc_key, mac_key)

