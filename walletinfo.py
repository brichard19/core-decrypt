import sys, os.path, bsddb.db, struct, binascii

def hex_padding(s, length):
    if len(s) % length != 0:
        r = (length) - (len(s) % length)
        s = "0" * r + s

    return s


def read_encrypted_key(wallet_filename):

	with open(wallet_filename, "rb") as wallet_file:
		wallet_file.seek(12)
		if wallet_file.read(8) != b"\x62\x31\x05\x00\x09\x00\x00\x00":  # BDB magic, Btree v9
			print(prog+": ERROR: file is not a Bitcoin Core wallet")
			sys.exit(1)


		db_env = bsddb.db.DBEnv()
		db_env.open(os.path.dirname(wallet_filename), bsddb.db.DB_CREATE | bsddb.db.DB_INIT_MPOOL)
		db = bsddb.db.DB(db_env)

		db.open(wallet_filename, b"main", bsddb.db.DB_BTREE, bsddb.db.DB_RDONLY)
		mkey = db.get(b"\x04mkey\x01\x00\x00\x00")
		db.close()
		db_env.close()

		if not mkey:
			raise ValueError("Encrypted master key not found in the Bitcoin Core wallet file")


		encrypted_master_key, salt, method, iter_count = struct.unpack_from("< 49p 9p I I", mkey)
		
		if method != 0:
			print(prog+": warning: unexpected Bitcoin Core key derivation method ", str(method))

	  
		iv = binascii.hexlify(encrypted_master_key[16:32])
		ct = binascii.hexlify(encrypted_master_key[-16:])
		iterations = hex_padding('{:x}'.format(iter_count), 8)

		s = iv + ct + binascii.hexlify(salt) + iterations
		
		return s

######### main

prog = os.path.basename(sys.argv[0])

if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
    print("usage: walletinfo.py WALLET_FILE")
    sys.exit(2)


wallet_filename = os.path.abspath(sys.argv[1])
encrypted_key = read_encrypted_key(wallet_filename)
print(encrypted_key)

    
