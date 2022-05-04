#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, unicode_literals

import argparse
import sys


_eol = '" + EndOfLine + "'


def _quote(text):
    return '"' + (
        text
            .replace('"', '""')
            .replace('\r\n', _eol)
            .replace('\r', _eol)
            .replace('\n', _eol)
    ) + '"'


class _QuoteCLI(object):

    def get_parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            '-f', '--file', default=None, type=str,
            help='Quote string read from the file (default: stdin)')
        parser.add_argument(
            '-t', '--text', default=None, type=str,
            help='Quote string specified in the command line')
        parser.add_argument(
            '-s', '--strip', default=False, action='store_true',
            help='Remove trailing EOLs')
        return parser

    def main(self, argv):
        parser = self.get_parser()
        opts = parser.parse_args(argv[1:])
        if opts.file is not None and opts.text is not None:
            parser.error('file and text cannot be specified at once')
            return 1
        if opts.file is None and opts.text is None:
            opts.file = '-'

        text = opts.text
        if text is None:
            f = sys.stdin if opts.file == '-' else open(opts.file)
            text = f.read()
        if opts.strip:
            text = text.rstrip('\r\n')
        sys.stdout.write('{}'.format(_quote(text)))

        return 0


def _main():
    sys.exit(_QuoteCLI().main(sys.argv))


if __name__ == '__main__':
    _main()
