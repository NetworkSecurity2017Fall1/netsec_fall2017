def getPrivateKeyForAddr(addr):
    # Enter the location of the Private key as per the location of the system
    with open(root + "/sign/user1_private")as fp:
        private_key_user = fp.read()
    return private_key_user
