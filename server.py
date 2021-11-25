from asymmetric_key import RSAKey
import socket
import uuid
import pickle
import time

HOST = '127.0.0.1'
PORT = 65432

class Server:
    def __init__(self) -> None:
        self.id = str(uuid.uuid4())
        self.rsa_key = RSAKey()

        # For the purposes of this demonstration, I will store the keys
        # in a file so that they are easy to load. Ideally, the server
        # and client would store their keys securely.
        self.rsa_key.read_private_key_from_file("server_private_key.pem")
        self.rsa_key.read_public_key_from_file("client_public_key.pem")

        self.valid_clients = set()

    def process_message(self, encrypted_msg: bytes):
        # Decrypt the message
        msg_bytes = self.rsa_key.decrypt_message(encrypted_msg)
        msg = pickle.loads(msg_bytes)

        # Check if the message is a valid enrollment message
        if msg["msg_type"].startswith("ENROLLMENT"):
            return self.process_enrollment(msg)
        elif msg["msg_type"].startswith("MESSAGE"):
            if msg["id"] not in self.valid_clients:
                raise Exception("Invalid client id, not in list of accepted clients.")
            else:
                return self.process_normal_msg(msg)
        else:
            raise Exception("Invalid message Received")

    def process_enrollment(self, msg: dict):
        # Check the enrollment message has the correct initial password
        if msg["init_password"] == "PepperFlakes":
            self.valid_clients.add(msg["id"])
            print("Client {} has been added to the list of accepted clients.".format(msg["id"]))

            response_msg = {
                "msg_type": "ENROLLMENT",
                "id": self.id,
                "init_password": "PepperFlakes",
            }

            # Encrypt the response message
            encrypted_response_msg = self.rsa_key.encrypt_message(pickle.dumps(response_msg))
            return encrypted_response_msg

        else:
            raise Exception("Invalid init_password received. Not accepting as valid client")
    
    def send_message(self):
        # For the purposes of this demonstration, I hard-coded the message

        msg = {
            "msg_type": "MESSAGE",
            "id": self.id,
            "message": "Turn off switch 745"
        }

        # Encrypt the message
        encrypted_msg = self.rsa_key.encrypt_message(pickle.dumps(msg))

        return encrypted_msg

    def process_normal_msg(self, msg: dict):
        message = msg["message"]
        print("Message received: {}".format(message))
        return

    def run(self):
        # This is a simple example of a server. It will listen for a connection
        # from a client, and then send a message back to the client. In a 
        # more real world scenario, the server code would be wrapped in a loop
        # continuing to listen for connections and process messages.

        # Basic setup
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((HOST, PORT))

        # Wait on a connection
        s.listen(1)
        print("Waiting for a connection...")
        conn, addr = s.accept()
        print("Connection from: "+str(addr))


        encrypted_client_msg = conn.recv(1024)
        encrypted_server_msg = self.process_message(encrypted_client_msg)
        conn.sendall(encrypted_server_msg)

        time.sleep(1)

        server_msg = server.send_message()
        conn.sendall(server_msg)

        client_msg = conn.recv(1024)
        self.process_message(client_msg)

        time.sleep(1)

        s.close()

if __name__ == "__main__":
    server = Server()
    server.run()