#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
import argparse
import typing
import scapy.all


MAXLENGTH = 160


def sendmsg(ip: str, msg: str) -> None:
    if len(msg) > MAXLENGTH:
        raise ValueError(f'Message to long max {MAXLENGTH} characters')

    packages = list()
    for char in msg:
        # To confuse the Russians, the secret is the length
        # of the payload, not the content.
        payload = scapy.all.RandString(ord(char)).decode()
        icmp = scapy.all.IP(dst=ip)/scapy.all.ICMP()/payload
        packages.append(icmp)
    scapy.all.send(packages)


def extractmessage(dst:str, filename: str) -> str:
    msg = ''
    packages = scapy.all.rdpcap(filename)
    for package in packages:
        # extract character from payload length
        if package[scapy.all.IP].dst == dst:
            payload = package[scapy.all.Raw]
            msg += chr(len(payload))
    return msg


def cmdparse(args: typing.Optional[typing.List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='simple script to hide a message in the length of an icmp packet')
    parser.add_argument('--ip', 
            help='the IP address of the recipient of the message')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--send', action='store_true',
                       help=f'Send a hidden message with max {MAXLENGTH} characters')
    group.add_argument('--extract', type=str,
                       help='Extract a message from pcap File')
    parser.add_argument('-m', '--message',
                        help=f'the short message to be sent ({MAXLENGTH} characters maximum)')
    return parser.parse_args(args)


def main():
    args = cmdparse()
    if args.send:
        try:
            if not args.message:
                message = input('Message to send: ')
            else:
                message = args.message
            sendmsg(args.ip, message)
        except ValueError:
            print('Message is too long')
        except PermissionError:
            print('Not allow to send RAW Packages (maybe you should try as root)')
    elif args.extract:
        try:
            print(extractmessage(args.ip, args.extract))
        except scapy.error.Scapy_Exception:
            print(f'the format of file {args.extract} is not supported')


if __name__ == "__main__":
    main()
