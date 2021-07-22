#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import pefile
import argparse

if __name__ in '__main__':
    try:
        parser = argparse.ArgumentParser( description = 'Extracts the shellcode from a PE' );
        parser.add_argument( '-f', required = True, help = 'Path to the PE.',  type = str );
        parser.add_argument( '-o', required = True, help = 'Path to the bin.', type = argparse.FileType("wb+") );
        option = parser.parse_args();

        PeExe = pefile.PE( option.f );
        PeSec = PeExe.sections[0].get_data();

        if PeSec.find( b'ENDOFCODE' ) != None:
            ScRaw = PeSec[ : PeSec.find( b'ENDOFCODE' ) ];
            option.o.write( ScRaw );
        else:
            print( "[!] error: No ending tag." );
    except Exception as e:
        print( "[!] error: {}".format(e) );
