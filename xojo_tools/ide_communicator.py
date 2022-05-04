#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, unicode_literals

import argparse
import cmd
import json
import os
import os.path
import socket
import tempfile
import time
import sys


debug = False
debug_out = sys.stderr


def _log(*msg):
    if not debug:
        return
    debug_out.write(
        '[DEBUG] [{}] {}\n'.format(time.asctime(), ' '.join(map(str, msg))))
    debug_out.flush()


class _IDECommunicatorBase(object):

    def __init__(self, sock, close=True):
        self._sock = sock
        self._close = close

    def __del__(self):
        if self._close:
            self.close()

    def close(self):
        sock = self._sock
        if sock is not None:
            sock.close()
            _log('# CLOSE:', sock)
            self._sock = None

    def _write(self, data):
        if self._sock is None:
            raise RuntimeError('write failed: connection already closed')
        _log('# SEND:', data)
        self._sock.send(data)

    @classmethod
    def open(cls, path=None, wait=True, timeout=10):
        if wait:
            path = cls._wait_ipc_path(path, timeout)
            if path is None:
                raise RuntimeError('socket could not be found within timeout')
        if path is None:
            path = cls._find_ipc_path()
            if path is None:
                raise RuntimeError('socket could not be found')
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(path)
        return cls(sock)

    @classmethod
    def _wait_ipc_path(cls, path, timeout):
        for i in range(timeout):
            if path is None:
                path = cls._find_ipc_path()
                if path is not None:
                    return path
            else:
                if os.path.exists(path):
                    return path
            time.sleep(1)
        return None

    @classmethod
    def _find_ipc_path(cls):
        cands = []
        cands += [os.environ.get('XOJO_IPCPATH', None)]
        cands += [
            os.path.join(base, 'XojoIDE') for base in
                ['/tmp', '/var/tmp', tempfile.gettempdir(),
                 os.path.expanduser('~')]]
        paths = [p for p in cands if p is not None and os.path.exists(p)]
        if len(paths) != 0:
            return paths[0]
        return None


class IDECommunicatorV1(_IDECommunicatorBase):
    """IDE Communicator (protocol version 1)."""

    def send_script(self, script):
        self._write(script.encode('utf-8') + b'\n')


class IDECommunicatorV2(_IDECommunicatorBase):
    """IDE Communicator (protocol version 2)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _log('Switching to protocol version 2')
        try:
            self._write_json({'protocol': 2})
        except:
            self.close()
            raise

    def send_script(self, script, tag=None):
        if tag is None:
            tag = 'cmd_{}_{}'.format(os.getpid(), time.time())
        self._write_json({'tag': tag, 'script': script})
        return tag

    def receive(self):
        return self._read_json()

    def _write_json(self, data):
        self._write(json.dumps(data).encode('utf-8') + b'\x00')

    def _read_json(self):
        buf = []
        while True:
            try:
                # TODO: use nonblocking socket
                b = self._sock.recv(1)
                if (b == b'\x00'):
                    break
            except Exception as e:
                raise RuntimeError(
                    'failed to receive message ({}: {})'.format(
                        type(e).__name__, e))
            buf.append(b)
        data = b''.join(buf)
        _log('# RECV:', data)
        return json.loads(data)


class _CommunicatorCLI(object):

    out = sys.stdout
    err = sys.stderr

    def get_parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            '-c', '--command', default=[], action='append',
            help='Specify IDE script to run '
                 '(can be specified multiple times)')
        parser.add_argument(
            '-r', '--receive', default=0, action='count',
            help='Receive message from IDE '
                 '(can be specified multiple times to '
                 'receive multiple messages; protocol V2 only)')
        parser.add_argument(
            '-w', '--wait', default=False, action='store_true',
            help='wait until IPC socket is ready')
        parser.add_argument(
            '--ipc', default=None, type=str,
            help='path to IPC socket (default: auto-detect)')
        parser.add_argument(
            '--protocol', default=2, choices=[1, 2],
            help='protocol version (default: %(default)s)')
        parser.add_argument(
            '--timeout', default=30, type=int,
            help='timeout in seconds (default: %(default)s)')
        parser.add_argument(
            '--debug', default=False, action='store_true',
            help='enable debug logging')
        parser.add_argument(
            'ide_script', nargs='?', type=str,
            help='IDE script file')
        return parser

    def _send_script(self, comm, script):
        _log('Command: {}'.format(script))
        tag = comm.send_script(script)
        if tag is not None:
            # V2+
            _log('Tag: {}'.format(tag))

    def _receive(self, comm, count):
        assert not isinstance(comm, IDECommunicatorV1)
        for i in range(count):
            _log('Receiving message {} of {}'.format(i+1, count))
            self.out.write(
                    '{}\n'.format(json.dumps(comm.receive(), indent=4)))

    def main(self, argv):
        opts = self.get_parser().parse_args(argv[1:])

        invalid_param = False
        if opts.protocol == 1 and 0 < opts.receive:
            self.err.write('Error: recieve unsupported in protocol V1\n')
            invalid_param = True
        if opts.timeout <= 0:
            self.err.write('Error: invalid timeout\n')
            invalid_param = True
        if invalid_param:
            return 1

        if opts.debug:
            global debug
            debug = True

        if opts.protocol == 1:
            comm = IDECommunicatorV1.open(opts.ipc, wait=opts.wait, timeout=opts.timeout)
        elif opts.protocol == 2:
            comm = IDECommunicatorV2.open(opts.ipc, wait=opts.wait, timeout=opts.timeout)
        else:
            assert False

        try:
            for cmd in opts.command:
                self._send_script(comm, cmd)
            if opts.ide_script:
                _log('Reading IDE script:', opts.ide_script)
                with open(opts.ide_script) as f:
                    self._send_script(comm, f.read())
            if 0 < opts.receive:
                self._receive(comm, opts.receive)
        except Exception as e:
            self.err.write('Error: {}\n'.format(e))
            if opts.debug:
                raise
            return 2
        finally:
            comm.close()

        return 0


def _main():
    sys.exit(_CommunicatorCLI().main(sys.argv))


if __name__ == '__main__':
    _main()
