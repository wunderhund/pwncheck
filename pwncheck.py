#!/usr/local/bin/python3

from urllib.parse import quote_plus, urljoin
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import json
import argparse
import sys
import csv
from re import findall


def get_page(args, page):
    """HTTP Request function with error handling"""
    for attempt in range(3):
        try:
            response = urlopen(page)
            return response
        except HTTPError as error:
            if args.debug:
                print("HTTP Request %d failed: %d %s" %
                      (attempt+1, error.code, error.reason))
        except URLError as error:
            if args.debug:
                print("URL failed: %s" % (error.reason))
        except Exception:
            if args.debug:
                print("Unknown other failure")


def pwned_requests(args, valid_emails):
    """Make requests to haveibeenpwned API"""
    breach_dict = {}
    for email in valid_emails:

        # Build haveibeenpwned request
        req = Request(urljoin('https://haveibeenpwned.com/api/v2/breachedaccount/',
                              quote_plus(email.strip())))
        req.add_header('User-Agent', 'Pwnage-Checker')

        # Submit request
        response = get_page(args, req)

        # If breaches are found, format response as json output
        if response:
            breach_dict[email.strip()] = []
            for breach in json.load(response):

                # Adding the email into the dict for CSV output
                breach.update({'E-mail Address': email})
                breach_dict[email.strip()].append(breach)

        else:
            print("No breaches found for %s" % email.strip())

    return breach_dict


def write_csv(args, breach_dict):
    """Write API output to CSV file"""
    with open(args.outfile, 'w', newline='') as csvfile:

        # Write CSV file header
        fieldnames = ['E-mail Address']
        for breaches in breach_dict.values():
            for breach in breaches:
                for field in breach:
                    fieldnames.append(field)
        writer = csv.DictWriter(csvfile, fieldnames=sorted(set(fieldnames), key=fieldnames.index))
        writer.writeheader()

        # Populate Data into CSV file
        for breaches in breach_dict.values():
            writer.writerows(breaches)


def validate_email(args, email_list):
    """Filter input for valid e-mail addresses"""
    valid_emails = findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", str(email_list))
    if args.debug:
        print("valid emails: ", valid_emails)
    return valid_emails


def print_findings(args, breach_dict):
    """ Print findings to stdout"""
    if args.verbose and breach_dict:
        print(json.dumps(breach_dict, sort_keys=True, indent=4))
    elif not breach_dict:
        print("No breaches found.")
    else:
        for email, breaches in breach_dict.items():
            print(email)
            for breach in breaches:
                print('    ', breach['Name'], breach['BreachDate'])


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('email', nargs='?', help='E-mail address for single query')
    parser.add_argument('-v', '--verbose', help='Verbose output (JSON)', action="store_true")
    parser.add_argument('-i', '--infile', help="Input file with e-mail addresses")
    parser.add_argument('-o', '--outfile', help='CSV output file')
    parser.add_argument('-d', '--debug', help='Print debug messages', action='store_true')
    args = parser.parse_args()

    if not args.email and not args.infile:
        print("Must include a single e-mail address or an input file \
                containing e-mail addresses, one per line, as arguments!")
        parser.print_help()
        sys.exit()

    email_list = set()

    if args.infile:
        with open(args.infile) as file:
            for email in file:
                email_list.add(email.strip())

    if args.email:
        email_list.add(args.email.strip())

    valid_emails = set(validate_email(args, email_list))

    breach_dict = pwned_requests(args, valid_emails)

    print_findings(args, breach_dict)

    if args.outfile and breach_dict:
        write_csv(args, breach_dict)


if __name__ == "__main__":
    main()
