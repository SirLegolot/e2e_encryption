from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class RSAKey:
    def __init__(self):
        self._private_key = None
        self._public_key = None

    def generate_private_key(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537, # For various reasons, this is a good value
            key_size=2048, # 2048 or 4096 are good values
            backend=default_backend()
        )
        self._private_key = private_key

    def generate_public_key(self):
        if self._private_key is None:
            raise Exception("There is no private key currently! Please \
                generate a key or read one from a file")
        else:
            public_key = self._private_key.public_key()
            self._public_key = public_key

    def get_public_key(self):
        return self._public_key

    def write_private_key_to_file(self, path="private_key.pem"):
        if self._private_key is None:
            raise Exception("There is no private key currently! Please \
                generate a key or read one from a file")
        else:
            pem = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                # Other formats include OpenSSH and OpenSSL, but those are 
                # used for other applications
                format=serialization.PrivateFormat.PKCS8, 
                # When writing to a file, we don't want to encyrpt the key 
                # itself. This is for demonstration purposes. We can 
                encryption_algorithm=serialization.NoEncryption() 
            )
            with open(path, 'wb') as f:
                f.write(pem)

    def write_public_key_to_file(self, path="public_key.pem"):
        if self._public_key is None:
            raise Exception("There is no public key currently! Please \
                generate a key or read one from a file")
        else:
            pem = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(path, 'wb') as f:
                f.write(pem)

    def read_private_key_from_file(self, path="private_key.pem"):
        with open(path, "rb") as f:
            self._private_key = serialization.load_pem_private_key(
                f.read(),
                # We don't use a password here, but we can for extra security
                # For demonstration purposes, we won't.
                password=None, 
                backend=default_backend()
            )

    def read_public_key_from_file(self, path="public_key.pem"):
        with open(path, "rb") as f:
            self._public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    def encrypt_message(self, message: bytes, public_key=None):
        if public_key is None:
            public_key = self._public_key
        
        encrypted_msg = public_key.encrypt(
            message, 
            # This padding is used so that attackers cannot predictably 
            # determine info about the package if the packet size is the same.
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_msg

    def decrypt_message(self, encrypted_msg : bytes):
        # We are always decrypting with our private key, we are not supposed
        # to know anyone else's private key!
        if self._private_key is None:
            raise Exception("There is no private key currently! Please \
                generate a key or read one from a file")
        message = self._private_key.decrypt(
            encrypted_msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return message

def setup_master_outstation_keys():
    server_key = RSAKey()
    client_key = RSAKey()

    server_key.generate_private_key()
    server_key.generate_public_key()
    server_key.write_private_key_to_file("server_private_key.pem")
    server_key.write_public_key_to_file("server_public_key.pem")

    client_key.generate_private_key()
    client_key.generate_public_key()
    client_key.write_private_key_to_file("client_private_key.pem")
    client_key.write_public_key_to_file("client_public_key.pem")

def test():
    # Simple program to confirm encryption mechanism works.
    server_key = RSAKey()
    client_key = RSAKey()

    server_key.generate_private_key()
    server_key.generate_public_key()
    server_public_key = server_key.get_public_key()

    client_key.generate_private_key()
    client_key.generate_public_key()
    client_public_key = client_key.get_public_key()

    ### Test server sending a message to a client
    print("Test server sending a message to a client")
    server_message = b"Command: turn of switch AE456"
    encrypted_msg = server_key.encrypt_message(server_message, client_public_key)
    print(type(encrypted_msg)) # Should be bytes

    # This is where communication protocol would be sent to send the message to
    # the client. I.e. sockets for demonstration purposes.

    decrypted_message = client_key.decrypt_message(encrypted_msg)
    print(f"Client got this message: {decrypted_message}")
    if (decrypted_message == server_message):
        print("Success!")
    else:
        assert(False)

    print()

    ### Test client sending message to server
    print("Test client sending a message to a server")
    client_message = b"Report: Successfully closed switch AE456"
    encrypted_msg = client_key.encrypt_message(client_message, server_public_key)

    # This is where communication protocol would be sent to send the message to
    # the server. I.e. sockets for demonstration purposes.

    decrypted_message = server_key.decrypt_message(encrypted_msg)
    print(f"Server got this message: {decrypted_message}")
    if (decrypted_message == client_message):
        print("Success!")
    else:
        assert(False)
        
if __name__ == "__main__":
    test()
    # setup_master_outstation_keys()
    



