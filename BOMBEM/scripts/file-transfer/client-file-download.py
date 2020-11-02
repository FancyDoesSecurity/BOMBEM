import socket
import argparse


class Colors:
    green = '\033[0;32m'
    end = '\033[m'


def upload(remote_host, remote_port, file):
    try:
        sock = socket.socket()
        sock.connect((remote_host, int(remote_port)))
        filetosend = open(file, "rb")
        data = filetosend.read(1024)
        print("[%s*%s] Sending File Over To: %s" % (Colors.green, Colors.end, remote_host))
        while data:
            sock.send(data)
            data = filetosend.read(1024)
        filetosend.close()
        sock.send(b"DONE")
        print("[%s*%s] Done Sending" % (Colors.green, Colors.end))
        print(sock.recv(1024))
        sock.shutdown(2)
        sock.close()

        exit()
    except (socket.error, KeyboardInterrupt, ConnectionError) as error:
        print(error)
        quit()


parser = argparse.ArgumentParser()
parser.add_argument("-f", help="file you want to upload", metavar="file.txt", type=str, required=True)
parser.add_argument("-l", help="computer ip (target to upload to)", metavar="", type=str, required=True)
parser.add_argument("-p", help="remote port", metavar="9999", type=str, required=True)

argument = parser.parse_args()

if __name__ == "__main__":
    upload(remote_host=argument.l, file=argument.f, remote_port=argument.p)
