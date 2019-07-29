import socket
import sys
import os


_CONVERSATION = [
    # Receive:
    #   Command: connect
    #   Viewer ID: -1 (not set)
    #   Version: 2.4
    #
    # Send:
    #   Command: connect
    #   Viewer ID: 19 (0x13)
    #   Version: 2.10
    (
        '00000000000000140000000100000000ffffffffffffffff000000020000000400000001',
        '0000000000000013000000020000000a00000000',
    ),
    # Receive:
    #   Command: list sessions
    #
    # Send:
    #   Command: list sessions
    #   Session count: 2
    (
        '00000000000000000000000200000000',
        '000000020000000000000002000f424000000000000000056172636865657070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000073616c7574000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000f42400000000000000005617263686565707000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006175746f2d32303139303732392d31303030303200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    ),
]


class _UnexpectedMessage(RuntimeError):
    pass


def _print_err(msg):
    print(msg, file=sys.stderr)


def _recv_expect(conn, expect_hex):
    expect_bytes = bytes.fromhex(expect_hex)
    buf = bytes()

    while True:
        if len(buf) == len(expect_bytes):
            break

        buf += conn.recv(len(expect_bytes) - len(buf))

    if buf != expect_bytes:
        _print_err('Unexpected message from client:')
        _print_err('  Expected: {}'.format(expect_bytes))
        _print_err('  Got:      {}'.format(buf))
        raise _UnexpectedMessage


def _talk_once(conn, in_hex, out_hex):
    _recv_expect(conn, in_hex)
    conn.sendall(bytes.fromhex(out_hex))


def _talk_many(conn, in_out_hex):
    for in_hex, out_hex in in_out_hex:
        _talk_once(conn, in_hex, out_hex)


def _main(tmp_port_filename, port_filename):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # port 0: OS assigns an unused port
    serv_addr = ('localhost', 0)
    sock.bind(serv_addr)

    # write server port to temporary file
    serv_port = sock.getsockname()[1]

    with open(tmp_port_filename, 'w') as f:
        print(serv_port, end='', file=f)

    # rename temporary file to real file
    os.rename(tmp_port_filename, port_filename)
    print('# Wrote port to file `{}`'.format(port_filename))

    # listen to client and talk
    print('# Listening on port {}'.format(serv_port))
    sock.listen()
    conn, client_addr = sock.accept()
    print('# Accepted client: {}:{}'.format(client_addr[0], client_addr[1]))
    _talk_many(conn, _CONVERSATION)
    conn.close()
    print('# Closed connection.')


if __name__ == '__main__':
    try:
        _main(sys.argv[1], sys.argv[2])
    except _UnexpectedMessage:
        _print_err('Finished with an error.')
        sys.exit(1)
