from asymmetric_key import RSAKey
import socket
import uuid
import pickle
import time

HOST = '127.0.0.1'
PORT = 65432



class Client:
    def __init__(self) -> None:
        self.id = str(uuid.uuid4())
        self.rsa_key = RSAKey()
        self.init_password = "PepperFlakes"

        self.rsa_key.read_private_key_from_file("client_private_key.pem")
        self.rsa_key.read_public_key_from_file("server_public_key.pem")

        self.valid_servers = set()

    def process_message(self, encrypted_msg: bytes):
        # Decrypt the message
        msg_bytes = self.rsa_key.decrypt_message(encrypted_msg)
        msg = pickle.loads(msg_bytes)

        # Check if the message is a valid enrollment message
        if msg["msg_type"].startswith("ENROLLMENT"):
            return self.process_enrollment(msg)
        elif msg["msg_type"].startswith("MESSAGE"):
            if msg["id"] not in self.valid_servers:
                raise Exception("Invalid server id, not in list of accepted clients.")
            else:
                return self.process_normal_msg(msg)
        else:
            raise Exception("Invalid message Received")

    def process_enrollment(self, msg: dict):
        # Check the enrollment message has the correct initial password
        if msg["init_password"] == "PepperFlakes":
            self.valid_servers.add(msg["id"])
            print("Server {} has been added to the list of accepted servers.".format(msg["id"]))

            return
        
        else:
            raise Exception("Invalid init_password received. Not accepting as valid server")

    def send_message(self):
        # For the purposes of this demonstration, I hard-coded the message

        msg = {
            "msg_type": "MESSAGE",
            "id": self.id,
            "message": "Sucessfully turned off switch 745"
        }

        # Encrypt the message
        encrypted_msg = self.rsa_key.encrypt_message(pickle.dumps(msg))

        return encrypted_msg

    def process_normal_msg(self, msg: dict):
        message = msg["message"]
        print("Message received: {}".format(message))
        return

    def get_enrollment_msg(self):
        # Create the enrollment message
        client_msg = {
            "msg_type": "ENROLLMENT",
            "id": self.id,
            "init_password": self.init_password,
        }
        encrypted_client_msg = self.rsa_key.encrypt_message(pickle.dumps(client_msg))

        return encrypted_client_msg

    def run(self):
        # This demonstrates a simple example of how a client can register with 
        # a server. In a real situation, a client run function would be 
        # wrapped in a loop continously sending and receiving messages to the 
        # server.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.connect((HOST, PORT))
        print("Client has successfully connected!")

        encrypted_client_msg = self.get_enrollment_msg()
        s.sendall(encrypted_client_msg)

        encrypted_server_msg = s.recv(4096)
        self.process_message(encrypted_server_msg)

        time.sleep(1)

        server_msg = s.recv(4096)
        self.process_message(server_msg)

        client_msg = client.send_message()
        s.sendall(client_msg)

        time.sleep(1)

        s.close()

if __name__ == "__main__":
    client = Client()
    client.run()