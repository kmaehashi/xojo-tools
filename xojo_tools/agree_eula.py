#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, unicode_literals

import sys


_dot_xojo_xojo = '''
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>License Mod Time</key>
        <real>9999999999</real>
        <key>System Specs Offered</key>
        <true/>
        <key>Show Getting Started</key>
        <false/>
</dict>
</plist>
'''


def main():
    cfg = None
    if sys.platform.startswith('linux'):
        cfg = os.path.expanduser('~/.Xojo.Xojo')
    elif sys.platform.startswith('darwin'):
        cfg = os.path.expanduser(
            '~/Library/Preferences/com.xojo.xojo.plist')
    else:
        # TODO: sys.platform.startswith('win32')
        print('Error: Unsupported platform: {}\n'.format(sys.platform))
        return 2

    if os.path.exists(cfg):
        # TODO: support merging with existing config
        print('Configuration already exists: {}'.format(cfg))
        return 0

    print('Automatically accepting EULA: '.format(cfg))
    with open(cfg, 'w') as f:
        f.write(_dot_xojo_xojo)
    return 0


def _main():
    sys.exit(main())


if __name__ == '__main__':
    _main()
