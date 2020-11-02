import socket
import argparse


class Colors:
    green = '\033[0;32m'
    end = '\033[m'


def receive_file(local_host, local_port, filename):
    try:
        print(
            "[%s*%s] go to file-transfer/client-file-download.py\n" % (
                Colors.green, Colors.end))
        sock = socket.socket()
        sock.bind((str(local_host), int(local_port)))
        sock.listen(1)
        connection, a = sock.accept()
        # the local_file will be the new name to receive the file under
        file_to_download = open(filename, "wb")
        print(f"\r[{Colors.green}*{Colors.end}] Receiving...", end="")
        while True:
            data = connection.recv(1024)
            if data == b"DONE":
                print("[%s*%s] Done Receiving" % (Colors.green, Colors.end))
                print("[%s*%s] you Can Exit Now" % (Colors.green, Colors.end))
                break
            file_to_download.write(data)
        file_to_download.close()
        connection.shutdown(2)
        connection.close()
        sock.close()
    except (socket.error, KeyboardInterrupt, ConnectionError) as error:
        print(error)
        quit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", help="filename to save to", metavar="", type=str)
    parser.add_argument("-l", help="local host", metavar="", type=str)
    parser.add_argument("-p", help="local port", metavar="", type=int)
    argument = parser.parse_args()
    receive_file(local_host=argument.l, filename=argument.f, local_port=argument.p)
