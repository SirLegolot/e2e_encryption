from server import Server
from client import Client


if __name__ == "__main__":
    server = Server()
    client = Client()


    # Enrollment messages
    encrypted_client_msg = client.get_enrollment_msg()

    # print("Client sending this message:")
    # print(client_msg)

    encrypted_server_msg = server.process_message(encrypted_client_msg)

    client.process_message(encrypted_server_msg)


    # Communication messages
    server_msg = server.send_message()

    # We should send via tcp

    client.process_message(server_msg)

    client_msg = client.send_message()

    # We should send via tcp

    server.process_message(client_msg)


