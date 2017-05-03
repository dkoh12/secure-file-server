
from base_client import BaseClient, IntegrityError
from crypto import CryptoError
import util
from math import log, ceil
from collections import deque

BLOCKSIZE = 256 #512 #1024

def getNumBlocks(value):
    length = len(value)

    numblocks = length // BLOCKSIZE
    if numblocks * BLOCKSIZE < length:
        numblocks += 1

    return numblocks

# get binary blocks
def binaryBlocks(numblocks, value):
    binaryblock = 2 ** ceil(log(numblocks, 2))
    blocksize = ceil(len(value) / binaryblock)
    return binaryblock, blocksize


def path_join(*strings):
    return '/'.join(strings)

class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        self.dirkey = None
        self.directory = {}

    def generate_keys(self):
        # symmetric encrypt key
        sym_ke = self.crypto.get_random_bytes(16)
        # MAC key
        sym_ka = self.crypto.get_random_bytes(16)
        # sym name encrypt key
        sym_kn = self.crypto.get_random_bytes(16)
        keys = (sym_ke, sym_ka, sym_kn)

        return keys

    def dir_keys(self):
        # sym encrypt key
        sym_ke = self.crypto.get_random_bytes(16)
        # sym mac key
        sym_ka = self.crypto.get_random_bytes(16)

        return (sym_ke, sym_ka)

    def get_directory_keys(self):
        dir_ID = path_join("information", self.username)

        resp = self.storage_server.get(dir_ID)

        if resp is None:
            keys = self.dir_keys()
            key_info = self.safe_encrypt(keys)
            self.storage_server.put(dir_ID, util.to_json_string(key_info))
        else:
            keys = self.safe_decrypt(resp)

        return keys

    def encrypt_filepath(self, file_id, session_key, newkeys, name):
        sym_ke, sym_ka = session_key
        sym_Ke, sym_Ka, sym_Kn = newkeys
        F = self.crypto.message_authentication_code(name, sym_Kn, "SHA256")
        path = path_join(self.username, F)
        file_info = {"keys": newkeys, "path": path}

        self.encrypt_directory(file_id, file_info, sym_ke, sym_ka)

    def safe_encrypt(self, keys):
        pub_key = self.private_key.publickey()
        key_str = util.to_json_string(keys)

        encrypted_keys = self.crypto.asymmetric_encrypt(key_str, pub_key)
        signed_keys = self.crypto.asymmetric_sign(encrypted_keys, self.private_key)

        return {"encrypted_keys": encrypted_keys, "signed_keys": signed_keys}
        
    def safe_decrypt(self, resp):
        pub_key = self.private_key.publickey()

        try:
            key_info = util.from_json_string(resp)
            encrypted_keys = key_info["encrypted_keys"]
            signed_keys = key_info["signed_keys"]
        except:
            raise IntegrityError()

        if not self.crypto.asymmetric_verify(encrypted_keys, signed_keys, pub_key):
            raise IntegrityError()

        decrypted_keys = self.crypto.asymmetric_decrypt(encrypted_keys, self.private_key)
        return util.from_json_string(decrypted_keys)
    
    def encrypt_directory(self, client_ID, directory, sym_ke, sym_ka):
        directory = util.to_json_string(directory)

        IV = self.crypto.get_random_bytes(16)
        encrypted_dir = self.crypto.symmetric_encrypt(directory, sym_ke, 'AES', 'CBC', IV)
        signed_dir = self.crypto.message_authentication_code(encrypted_dir, sym_ka, 'SHA256')

        directory_info = {"IV": IV, "encrypted_keys": encrypted_dir, "signed_keys": signed_dir}
        self.storage_server.put(client_ID, util.to_json_string(directory_info))

    def decrypt_directory(self, resp, sym_ke, sym_ka):
        try:
            directory_info = util.from_json_string(resp)
            IV = directory_info['IV']
            encrypted_keys = directory_info["encrypted_keys"]
            signed_keys = directory_info["signed_keys"]
        except:
            raise IntegrityError()

        signed_dir = self.crypto.message_authentication_code(encrypted_keys, sym_ka, 'SHA256')
        if signed_dir != signed_keys:
            raise IntegrityError()

        directory = self.crypto.symmetric_decrypt(encrypted_keys, sym_ke, 'AES', 'CBC', IV) 
        directory = util.from_json_string(directory)

        return directory




    def getRoot(self, ID, sym_ka):
        meta = self.storage_server.get(path_join(ID, str(0)))

        if meta is None:
            return None
        try:
            meta = util.from_json_string(meta)
            numblocks = meta['numblocks']
            mac = meta['mac']

            meta_mac = self.crypto.message_authentication_code(str(numblocks), sym_ka, 'SHA') #SHA

            if meta_mac != mac:
                raise IntegrityError()
        except:
            raise IntegrityError()

        return numblocks


    def metaInRoot(self, ID, numblocks, sym_ka):
        mac = self.crypto.message_authentication_code(str(numblocks), sym_ka, 'SHA') #SHA
        meta_info = {"numblocks": numblocks, "mac": mac}
        self.storage_server.put(path_join(ID, str(0)), util.to_json_string(meta_info))


    # ENCRYPT THE DATA NODE
    def hashData(self, ID, message, sym_ke, sym_ka):
        IV = self.crypto.get_random_bytes(16)
        encrypted_message = self.crypto.symmetric_encrypt(message, sym_ke, 'AES', 'CBC', IV)
        mac = self.crypto.message_authentication_code(encrypted_message + ID, sym_ka, 'SHA256')
        message_info = {"IV": IV, "encrypted": encrypted_message, "mac": mac}
        self.storage_server.put(ID, util.to_json_string(message_info))


    # stores only the data blocks as leaves as well as corresponding hashes
    def hashDataBlocks(self, ID, numblocks, blocksize, value, sym_ke, sym_ka):
        d = {}
        start_index = 2**ceil(log(numblocks, 2)) # 1024

        self.metaInRoot(ID, numblocks, sym_ka)

        for i in range(numblocks):
            # store data
            message = value[i*blocksize : (i+1) * blocksize]
            path = path_join(ID, 'data', str(i))
            self.hashData(path, message, sym_ke, sym_ka)

            # hash leaves
            cipher = self.crypto.cryptographic_hash(message, 'SHA') #SHA
            path = path_join(ID, str(i+start_index))
            mac = self.crypto.message_authentication_code(cipher, sym_ka, 'SHA') #SHA
            cipher_info = {"hash": cipher, "mac":mac}
            self.storage_server.put(path, util.to_json_string(cipher_info))

            d[i+start_index] = cipher

        return d


    # stores the internal nodes of merkel tree as hashes 
    def hashTree(self, ID, d, sym_ke, sym_ka):
        tree = {}

        if len(d.keys()) == 1:
            return d

        for i in d.keys():
            if i % 2 == 0:
                # even binary tree
                if i+1 in d:
                    cipher = self.crypto.cryptographic_hash(d[i] + d[i+1], 'SHA') #SHA
                # odd binary tree
                else:
                    cipher = self.crypto.cryptographic_hash(d[i], 'SHA') #SHA

                path = path_join(ID, str(i//2))
                mac = self.crypto.message_authentication_code(cipher, sym_ka, 'SHA') #SHA
                cipher_info = {"hash": cipher, "mac": mac}
                self.storage_server.put(path, util.to_json_string(cipher_info))

                tree[i//2] = cipher

        return self.hashTree(ID, tree, sym_ke, sym_ka)


    # called by localTree
    def bunch(self, total, hh):
        level = {}

        if len(hh.keys()) == 1:
            return total

        for i in hh.keys():
            if i % 2 == 0:
                if i+1 in hh:
                    cipher = self.crypto.cryptographic_hash(hh[i] + hh[i+1], 'SHA') #SHA
                else:
                    cipher = self.crypto.cryptographic_hash(hh[i], 'SHA') #SHA

                level[i//2] = cipher
                total[i//2] = cipher

        return self.bunch(total, level)


    # get local tree hashes
    def getlocalTree(self, numblocks, blocksize, value):
        val = {}
        hh = {}
        start_index = 2**ceil(log(numblocks, 2))

        for i in range(numblocks):
            # message
            message = value[i*blocksize : (i+1) * blocksize]
            val[i] = message

            # cipher
            cipher = self.crypto.cryptographic_hash(message, 'SHA') #SHA
            hh[i+start_index] = cipher

        bunch = self.bunch(hh.copy(), hh)

        return val, bunch, start_index


    # retrieves stored hash
    def checkTreeNode(self, path, sym_Ka):
        resp = self.storage_server.get(path)

        if resp is None:
            return None
        try:
            resp = util.from_json_string(resp)
        except:
            raise IntegrityError()

        stored_hash = resp['hash']
        mac = resp['mac']

        newmac = self.crypto.message_authentication_code(stored_hash, sym_Ka, 'SHA') #SHA

        if mac != newmac:
            raise IntegrityError()

        return stored_hash


    def upload(self, name, value):
        newFile = False
        ID = ""

        # cache
        if self.dirkey is None:
            directory_keys = self.get_directory_keys()
            sym_ke, sym_ka = directory_keys
            self.dirkey = directory_keys
        else:
            sym_ke, sym_ka = self.dirkey


        # cache
        if name in self.directory:
            if len(self.directory[name]["file_id"]) == 32:
                #owner
                keys = self.directory[name]["keys"][0]
            else:
                #sharee
                session_key = self.directory[name]["keys"]
                file_id = self.directory[name]["file_id"]

                sym_fe, sym_fa = session_key

                shared_file = self.storage_server.get(file_id)
                if shared_file is None:
                    return None

                shared_info = self.decrypt_directory(shared_file, sym_fe, sym_fa)

                keys = shared_info["keys"]
                ID = shared_info["path"]
        # actual
        else:
            # CLIENT DIRECTORY
            client_ID = path_join(self.username, "directory")
            resp = self.storage_server.get(client_ID)

            if resp is None:
                newFile = True
                keys = self.generate_keys()
                session_key = self.dir_keys()
                directory = {name: {"keys": (keys, session_key), "shared": [], "file_id": self.crypto.get_random_bytes(16)}}
                self.encrypt_directory(client_ID, directory, sym_ke, sym_ka)

                # can cache directory here
                self.directory[name] = {"keys": (keys, session_key), "shared": [], "file_id": self.crypto.get_random_bytes(16)}
            else:
                directory = self.decrypt_directory(resp, sym_ke, sym_ka)

                if name in directory:
                    if len(directory[name]["file_id"]) == 32:
                        #owner
                        keys = directory[name]["keys"][0]
                    else:
                        #sharee
                        session_key = directory[name]["keys"]
                        file_id = directory[name]["file_id"]

                        sym_fe, sym_fa = session_key

                        shared_file = self.storage_server.get(file_id)
                        if shared_file is None:
                            return None

                        shared_info = self.decrypt_directory(shared_file, sym_fe, sym_fa)

                        keys = shared_info["keys"]
                        ID = shared_info["path"]
                # map exists but this filename isn't. Create new file. Default = owner
                else:
                    newFile = True
                    keys = self.generate_keys()
                    session_key = self.dir_keys()
                    directory[name] = {"keys": (keys, session_key), "shared": [], "file_id": self.crypto.get_random_bytes(16)}
                    self.encrypt_directory(client_ID, directory, sym_ke, sym_ka)

                    # can cache directory here
                    self.directory[name] = {"keys": (keys, session_key), "shared": [], "file_id": self.crypto.get_random_bytes(16)}


        sym_Ke, sym_Ka, sym_Kn = keys

        # If owner
        if ID == "":
            F = self.crypto.message_authentication_code(name, sym_Kn, 'SHA256')
            ID = path_join(self.username, F)


        numblocks = getNumBlocks(value)

        if numblocks < 1:
            print("Must have at least 1 block of data")
            return None

        # if numblock == 1 just store the whole damn thing. no tree
        elif numblocks == 1:
            self.metaInRoot(ID, numblocks, sym_Ka)

            # DATA NODE
            path = path_join(ID, 'data', str(0))

            IV = self.crypto.get_random_bytes(16)
            encrypted_file = self.crypto.symmetric_encrypt(value, sym_Ke, 'AES','CBC', IV)
            mac = self.crypto.message_authentication_code(encrypted_file + path, sym_Ka, 'SHA256') 
            data_info = {"IV": IV, "encrypted": encrypted_file, "mac": mac}

            self.storage_server.put(path, util.to_json_string(data_info))
        else:
            blocksize = BLOCKSIZE

            if log(numblocks, 2) != int(log(numblocks, 2)):
                numblocks, blocksize = binaryBlocks(numblocks, value)

            # upload tree into server only if newfile or file size changes
            if newFile or (self.getRoot(ID, sym_Ka) != numblocks):
                datadic = self.hashDataBlocks(ID, numblocks, blocksize, value, sym_Ke, sym_Ka)
                root = self.hashTree(ID, datadic, sym_Ke, sym_Ka)
            else:
                val, bunch, start_index = self.getlocalTree(numblocks, blocksize, value)

                mmin = min(val.keys()) + start_index
                mmax = max(val.keys()) + start_index

                # root
                checkentries = deque([1])
                leaves = []
                my_hash = {}

                while len(checkentries) != 0:
                    p = checkentries.popleft()

                    path = path_join(ID, str(p))
                    stored_hash = self.checkTreeNode(path, sym_Ka)

                    my_hash[p] = stored_hash

                    if stored_hash != bunch[p]:
                        if mmin <= 2*p <= mmax:
                            leaves.append(2*p)
                        else:
                            checkentries.append(2*p)

                        if mmin <= 2*p + 1 <= mmax:
                            leaves.append(2*p+1)
                        else:
                            checkentries.append(2*p + 1)

                for i in leaves:
                    path = path_join(ID, str(i))
                    stored_hash = self.checkTreeNode(path, sym_Ka)

                    if stored_hash != bunch[i]:
                        path = path_join(ID, 'data', str(i-start_index))

                        compare = self.storage_server.get(path)

                        if compare is None:
                            return None

                        compare = util.from_json_string(compare)
                        civ = compare["IV"]
                        cen = compare["encrypted"]
                        cmac = compare["mac"]

                        newmac = self.crypto.message_authentication_code(cen + path, sym_Ka, 'SHA256')

                        if newmac != cmac:
                            raise IntegrityError()

                        msg = self.crypto.symmetric_decrypt(cen, sym_Ke, 'AES', 'CBC', civ)

                        # updates DATA NODE
                        self.hashData(path, val[i-start_index], sym_Ke, sym_Ka)

                        # update HASH of DATA NODE
                        path = path_join(ID, str(i))
                        mac = self.crypto.message_authentication_code(bunch[i], sym_Ka, 'SHA') #SHA
                        cipher_info = {"hash": bunch[i], "mac":mac}
                        self.storage_server.put(path, util.to_json_string(cipher_info))

                        # GET SISTER LEAF HASH
                        if i % 2 == 0:
                            sister = path_join(ID, str(i+1))
                            stored_hash = self.checkTreeNode(sister, sym_Ka)
                            cipher = self.crypto.cryptographic_hash(bunch[i] + stored_hash, 'SHA')
                        else:
                            sister = path_join(ID, str(i-1))
                            storage_server = self.checkTreeNode(sister, sym_Ka)
                            cipher = self.crypto.cryptographic_hash(stored_hash + bunch[i], 'SHA')

                        path = path_join(ID, str(i//2))
                        mac = self.crypto.message_authentication_code(cipher, sym_Ka, 'SHA') #SHA
                        cipher_info = {"hash": cipher, "mac": mac}
                        self.storage_server.put(path, util.to_json_string(cipher_info))

                        i = i // 2

                        # update rest of HASHES of tree
                        while i > 1:
                            if i %2 == 0:
                                # get right node
                                sister = path_join(ID, str(i+1))
                                stored_hash = my_hash[i+1]
                                cipher = self.crypto.cryptographic_hash(bunch[i] + stored_hash, 'SHA') #SHA
                            else:
                                # get left node
                                sister = path_join(ID, str(i-1))
                                stored_hash = my_hash[i-1]
                                cipher = self.crypto.cryptographic_hash(stored_hash + bunch[i], 'SHA') #SHA

                            path = path_join(ID, str(i//2))
                            mac = self.crypto.message_authentication_code(cipher, sym_Ka, 'SHA') #SHA
                            cipher_info = {"hash": cipher, "mac": mac}
                            self.storage_server.put(path, util.to_json_string(cipher_info))

                            i = i//2


    def download(self, name):
        # GET DIRECTORY KEYS
        directory_keys = self.get_directory_keys()
        sym_ke, sym_ka = directory_keys

        # GET DIRECTORY
        client_ID = path_join(self.username, "directory")
        resp = self.storage_server.get(client_ID)
        if resp is None:
            return None

        directory = self.decrypt_directory(resp, sym_ke, sym_ka)

        if name not in directory:
            return None

        file = directory[name]
        #owner 
        if len(file["file_id"]) == 32:
            keys = file["keys"][0]
            sym_Ke, sym_Ka, sym_Kn = keys
            F = self.crypto.message_authentication_code(name, sym_Kn, "SHA256")
            ID = path_join(self.username, F)
        #sharee
        else:
            file_id = file["file_id"]
            session_key = file["keys"]
            sym_fe, sym_fa = session_key

            shared_file = self.storage_server.get(file_id)
            if shared_file is None:
                return None

            shared_info = self.decrypt_directory(shared_file, sym_fe, sym_fa)

            keys = shared_info["keys"]
            ID = shared_info["path"]

        sym_Ke, sym_Ka, sym_Kn = keys


        numblocks = self.getRoot(ID, sym_Ka)
        if numblocks is None:
            return None

        value = ""
        for i in range(numblocks):

            path = path_join(ID, 'data', str(i))

            block = self.storage_server.get(path)
            if block is None:
                return None
            try:
                block = util.from_json_string(block)

                iv = block['IV']
                encrypted = block["encrypted"]
                mac = block['mac']

                newmac = self.crypto.message_authentication_code(encrypted + path, sym_Ka, 'SHA256')
                if newmac != mac:
                    raise IntegrityError()

                decrypt = self.crypto.symmetric_decrypt(encrypted, sym_Ke, 'AES', 'CBC', iv)

                value += decrypt

            except:
                raise IntegrityError()

        return value



    # m = a.share("b", n1)
    # every user must be able to see any updates made to this file immediately
    def share(self, user, name):
        # GET DIRECTORY KEYS
        directory_keys = self.get_directory_keys()
        sym_ke, sym_ka = directory_keys

        # GET DIRECTORY
        client_ID = path_join(self.username, "directory")
        resp = self.storage_server.get(client_ID)
        if resp is None:
            return None

        directory = self.decrypt_directory(resp, sym_ke, sym_ka)

        if name not in directory:
            return None

        file = directory[name]
        # directory[name] = {"keys": (keys, session_key), "shared": [], "file_id": self.crypto.get_random_bytes(16)}}
        # owner sharing w/ child
        if len(file["file_id"]) == 32:
            keys = file["keys"][0]
            session_key = file["keys"][1]
            file_id = path_join(user, self.username, file["file_id"])
            self.encrypt_filepath(file_id, session_key, keys, name)

        # directory[name] = {"keys": session_key, "shared": [], "file_id": B/A/random 16 bytes}
        # child sharing w/ grandchild
        else:
            file_id = file["file_id"]
            session_key = file["keys"]
        
        directory[name]["shared"].append(user)

        self.encrypt_directory(client_ID, directory, sym_ke, sym_ka)

        # cache directory
        self.directory[name]["shared"].append(user)
        

        # ENCRYPT MESSAGE TO SEND
        recipient_pub_key = self.pks.get_public_key(user)

        share_info = {"session_key": session_key, "file_id": file_id}
        share_info = util.to_json_string(share_info)

        crypted = self.crypto.asymmetric_encrypt(share_info, recipient_pub_key)
        sign = self.crypto.asymmetric_sign(crypted, self.private_key)


        output = (crypted, sign)
        output = util.to_json_string(output)

        return output


    # b.receive_share("a", n2, m)
    # b must be able to read / modify / reshare this file
    def receive_share(self, from_username, newname, message):
        sender_pub_key = self.pks.get_public_key(from_username)


        try:
            output = util.from_json_string(message)
            crypted, sign = output
        except:
            raise IntegrityError()
        

        # DECRYPT RECEIVED MESSAGE
        if self.crypto.asymmetric_verify(crypted, sign, sender_pub_key):
            msg = self.crypto.asymmetric_decrypt(crypted, self.private_key)
            msg = util.from_json_string(msg)

            session_key = msg['session_key']
            file_id = msg['file_id']
        else:
            raise IntegrityError()

        # GET DIRECTORY KEYS
        directory_keys = self.get_directory_keys()
        sym_ke, sym_ka = directory_keys

        # GET DIRECTORY
        client_ID = path_join(self.username, "directory")
        resp = self.storage_server.get(client_ID)
        if resp is None:
            directory = {newname: {"keys": session_key, "shared": [], "file_id": file_id}}
        else:
            directory = self.decrypt_directory(resp, sym_ke, sym_ka)
            directory[newname] =  {"keys": session_key, "shared": [], "file_id": file_id}

        # can cache directory here
        self.directory[newname] = {"keys": session_key, "shared": [], "file_id": file_id}

        self.encrypt_directory(client_ID, directory, sym_ke, sym_ka)


    def revoke(self, user, name):
        # GET DIRECTORY KEYS
        directory_keys = self.get_directory_keys()
        sym_ke, sym_ka = directory_keys

        # GET DIRECTORY
        client_ID = path_join(self.username, "directory")
        resp = self.storage_server.get(client_ID)
        if resp is None:
            return None

        directory = self.decrypt_directory(resp, sym_ke, sym_ka)

        if name not in directory:
            return None

        file = directory[name]
        # only Owner can revoke
        if len(file["file_id"]) == 32:
            newkeys = self.generate_keys()
            session_key = file["keys"][1]

            if user not in file["shared"]:
                return None
            file["shared"].remove(user)

            # store new keys in path
            for people in file["shared"]:
                file_id = path_join(people, self.username, file["file_id"])
                self.encrypt_filepath(file_id, session_key, newkeys, name)

            directory[name] = {"keys": (newkeys, session_key), "shared": file["shared"], "file_id": file["file_id"]}
            self.encrypt_directory(client_ID, directory, sym_ke, sym_ka)

            # can cache directory here
            self.directory[name] = {"keys": (newkeys, session_key), "shared": file["shared"], "file_id": file["file_id"]}

        else:
            raise IntegrityError()

