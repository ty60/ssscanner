import sys
import argparse

import numpy as np
import matplotlib.pyplot as plt

from collections import deque, Counter

from scapy.all import *


def check_five_tuple(ap, bp):
    try:
        asrc = ap['IP'].src
        adst = ap['IP'].dst
        asport = ap['TCP'].sport
        adport = ap['TCP'].dport
        aproto = ap['IP'].proto

        bsrc = bp['IP'].src
        bdst = bp['IP'].dst
        bsport = bp['TCP'].sport
        bdport = bp['TCP'].dport
        bproto = bp['IP'].proto
    except (IndexError, KeyError, AttributeError):
        return False
    return (
            asrc == bsrc and
            asport == bsport and
            adst == bdst and
            adport == bdport and
            aproto == bproto
            )


def gen_scan_pkts(pcapfile, windowsize):
    window = deque(maxlen=windowsize)

    with PcapReader(pcapfile) as pkts:
        # fill window
        for p in pkts:
            if p.haslayer(TCP):
                window.append(p)
            if len(window) == windowsize:
                break

        for p in pkts:
            if not p.haslayer(TCP):
                continue

            syn_p = window.popleft()
            window.append(p)

            flags = syn_p['TCP'].flags
            dport = syn_p['TCP'].dport
            # is syn_p really a SYN packet?
            if not ('S' == flags):
                continue

            is_scan = True
            for p in window:
                # is syn_p is a usual SYN packet to establish TCP conn?
                # it will be, if there is a TCP packet which carries a payload
                # within the same conversation.
                is_same_conv = check_five_tuple(syn_p, p)
                is_usual_p = is_same_conv and len(p['TCP'].payload) > 0
                if is_usual_p:
                    is_scan = False
                    break

            if is_scan:
                yield syn_p


def draw_bar(bars, output, xlabel, ylabel, log=False):
    sorted_bars = sorted(bars, key=lambda t: t[1], reverse=True)
    bar_name = np.array([t[0] for t in sorted_bars]) # name
    y = np.array([t[1] for t in sorted_bars]) # value

    bar_posision = np.arange(len(bar_name))

    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.bar(bar_posision, y, tick_label=bar_name)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    if log:
        ax.yscale("log")

    plt.savefig(output)


NUM_TOP = 10
def bar_chart(counter, outputpath):
    if not outputpath.endswith('.png'):
        raise Exception('PNG only')
    draw_bar(counter.most_common(NUM_TOP), outputpath,
             'Port Number', 'Number of Scan')


WINDOWSIZE = 256
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pcapfile', type=str)
    parser.add_argument('-w', '--windowsize', type=int, default=WINDOWSIZE)
    parser.add_argument('-q', '--quiet', action='store_true', help='No output description')
    parser.add_argument('--bar', type=str, default='', help='Path to output bar chart')

    args = parser.parse_args()

    if not args.bar:
        if not args.quiet:
            print('source ip:port, dest ip:port')

        for syn_p in gen_scan_pkts(args.pcapfile, args.windowsize):
            print('{}:{}, {}:{}'.format(
                syn_p['IP'].src, syn_p['TCP'].sport,
                syn_p['IP'].dst, syn_p['TCP'].dport))
        port_c = Counter()
        for syn_p in gen_scan_pkts(args.pcapfile, args.windowsize):
            port_c[syn_p.dport] += 1
        bar_chart(port_c, args.bar)


if __name__ == '__main__':
    main()
