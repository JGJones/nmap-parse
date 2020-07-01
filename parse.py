#!/usr/bin/env python

import argparse
import xlsxwriter
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

def command_args():
    ''' get args (ie nmap xml file and display help text) '''
    parser = argparse.ArgumentParser(
        description='Take an nmap XML file as input to produce a tab-delimited CSV or XLSX output')
    parser.add_argument('filename', metavar='input_file', help='Nmap XML file to parse')
    # parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument('-o', dest='output', nargs='?', metavar='filename',
                        help='Name of file to output to. If not used, defaults to report.csv',
                        const='report', default='report')
    parser.add_argument('-x', dest='xlsx', nargs='?', metavar='', help='Output to XLSX format instead',
                        const='report', default=False)
    parser.add_argument('-v', dest='verbose', help='Verbose output', default=False, action='store_true')
    return parser.parse_args()

def get_results(report):
    # Using a nested dictionary for all results
    # using this format: results[ip] = {'hostname':hostname, 'results':listOfTuples}
    result = {}

    # libnmap.object.hosts - returns an array of scanned hosts
    for host in report.hosts:
        ip = host.address

        if host.is_up():

            # Get the first hostname found (even if multiple hostnames), if none then N/A
            result[ip] = {'hostname': 'N/A'}

            if len(host.hostnames[0]) != 0:
                result[ip]['hostname'] = host.hostnames[0]

            # Initialise empty list
            result[ip]['scanopen'] = []
            result[ip]['scanclosed'] = []
            # each host could have multiple open ports so it's an array
            # so fetch array of scanned services for that host using
            # report.host.services
            for i in host.services:
                # get port, service type and banner if any for all open ports

                if i.open():
                    # hostscan.append((i.port, i.service, i.banner, ip))
                    result[ip]['scanopen'].append((i.port, i.service, i.banner))
                elif not i.open():
                    result[ip]['scanclosed'].append((i.port, 'closed'))

    # print(result) # test if all works

    return result

def print_basic(nmapxml, results, output, verbose):
    '''
    Console output of data in a tab-delimited format
    Also going to make use of string format module like here:
    https://www.geeksforgeeks.org/python-format-function/
    '''
    output = output + ".csv"
    with open(output, 'w') as f: #using with means not needing to remember to close the file at end.
        towrite = str(nmapxml.hosts_up) + ' live hosts\n'
        towrite += str(nmapxml.hosts_total) + ' hosts scanned\n'
        towrite += 'Scan type used: ' + str(nmapxml.scan_type) + '\n'
        towrite += 'nmap version used:' + str(nmapxml.version) + '\n'
        towrite += 'command used: '  + nmapxml.commandline + '\n'

        for ip in results.keys():
            # print('[*] {1} - {0}'.format(ip, hostname))
            towrite += 'HOST: ' + ip + '-' + results[ip]['hostname'] +'\n'
            towrite += 'IP\t\tPORT\tSERVICE\tVERSION\n'
            listofscan = list(results[ip]['scanopen'])
            for i in listofscan:
                towrite += str(ip) + '\t' + str(i[0]) + '\t' + str(i[1]) + '\t' + str(i[2]) + '\n'
            listofscan = list(results[ip]['scanclosed'])
            for i in listofscan:
                towrite += str(ip) + '\t' + str(i[0]) + '\t' + str(i[1]) + '\n'

        if verbose:
            print(towrite)

def print_xlsx(results, output):
    # Do some output
    # Create XLSX file and add a worksheet
    output = str(output) + '.xlsx'
    with xlsxwriter.Workbook(output) as workbook:
        worksheet = workbook.add_worksheet()
        # Add formatting
        bold = workbook.add_format({'bold': True})

        worksheet.write('A1', 'IP Address', bold)
        worksheet.write('B1', 'Port', bold)
        worksheet.write('C1', 'Service', bold)
        worksheet.write('D1', 'Version', bold)

        for ip in results.keys():
            #worksheet.write += 'HOST: ' + ip + '-' + results[ip]['hostname'] + '\n'
            listofscan = list(results[ip]['scanopen'])
            x = 1
            for i in listofscan:
                x = x + 1
                worksheet.write(('A'+str(x)), str(ip))
                worksheet.write(('B'+str(x)), str(i[0]))
                worksheet.write(('C'+str(x)), str(i[1]))
                worksheet.write(('D'+str(x)), str(i[2]))

            listofscan = list(results[ip]['scanclosed'])
            x = 1
            for i in listofscan:
                x = x + 1
                worksheet.write(('A' + str(x)), str(ip))
                worksheet.write(('B' + str(x)), str(i[0]))
                worksheet.write(('C' + str(x)), str(i[1]))


def main():
    ''' get the args '''
    args = command_args()
    ''' Load the nmap XML file '''
    nmapxml = NmapParser.parse_fromfile(args.filename)
    #output = args.output
    ''' do the parsing stuff here '''

    results = get_results(nmapxml)
    print_basic(nmapxml, results, args.output, args.verbose)
    if args.xlsx:  # if -x is being used, then this shows
        print_xlsx(results, args.xlsx)


main()
