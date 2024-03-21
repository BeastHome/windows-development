#!/usr/bin/env python
# Python program to mimic doing multiple dig commands in bash and providing the information parsed in an easy to read format.

# Written by David M Harris on 16 March 2024
# Last modified 20 March 2024
# dave@harris-services.com

# Import the normal system calls, as well as the dnspython, tldextract and python-whois modules.
import sys
import dns.name # pip install dnspython
import dns.resolver
import dns.reversename
from rich import print as rprint # pip install rich
import tldextract # pip install tldextract
import whois # pip install python-whois

# Take the domain as an argument or prompt for it.
try:
    entered_domain_name = sys.argv[1]
except IndexError:
    entered_domain_name = input ("Enter the domain to check: ")

# Extracts the domain name from a subdomain
clean_domain_name = tldextract.extract(entered_domain_name).fqdn
domain_name = tldextract.extract(entered_domain_name).registered_domain

#print(clean_domain_name, domain_name)
#sys.exit()
# Function to get A recrords from other records.
def get_a_records(a_answers):
        for rdata in a_answers:
            print(rdata.address)

# Sets the resolver to one that works with DNSSEC.
resolver = dns.resolver.Resolver()
resolver.nameservers = ['4.2.2.1']

# Function that does all of the work.
def get_dns_records(domain_name):
    # Print the header.
    rprint (f"DNS for [green1]{domain_name}[/].\n")

    # Print the A record(s) for the domain.
    a_answers = resolver.resolve(domain_name, 'A')
    rprint ("[cyan]A record(s):[/]")
    get_a_records(a_answers)
    print()

    # Print the SOA record for the domain.
    soa_answers = resolver.resolve(domain_name, 'SOA')
    print ("SOA:")
    for rdata in soa_answers:
        print(f' serial: {rdata.serial} | tech: {rdata.rname} | mname: {rdata.mname}')
        print(f' refresh: {rdata.refresh} | retry: {rdata.retry} | expire: {rdata.expire} | minimum: {rdata.minimum}')
    print()

    # Print the nameservers for the domain with the related A record(s).
    ns_answers = resolver.resolve(domain_name, 'NS')
    print("Nameservers:")
    for server in ns_answers:
        print(server.target)
        a_answers = resolver.resolve(server.target, 'A')
        get_a_records(a_answers)
        print()

    # Print the MX records for the domain with the related A record(s).
    mx_answers = resolver.resolve(domain_name, 'MX',)
    print ("MX:")
    for rdata in mx_answers:
        print('Host', rdata.exchange, 'has preference', rdata.preference)
        try:
            a_answers = resolver.resolve(rdata.exchange, 'A')
            for mx_rdata in a_answers:
                reverse_addr = dns.reversename.from_address(mx_rdata.address)
                print(mx_rdata.address, 'PTR:', resolver.resolve(reverse_addr, "PTR")[0])
            print()
        except Exception:
            print()

    # Print the TXT record(s) for the domain.
    txt_answers = resolver.resolve(domain_name, 'TXT')
    print ("TXT:")
    for rdata in txt_answers:
        for txt_string in rdata.strings:
            txt_value = str(txt_string)
            trimmed_txt_value = txt_value[1:]
            print (trimmed_txt_value)
    sys.exit()

# Checking whois to see if the domain is registeed, printing a message if not, or running the function if it is registered.
try:
    get_info = (whois.whois(domain_name))
#getinfo2 = pythonwhois.whois(domain_name)
#print (getinfo2)
#sys.exit()
# Checks to see if the domain is based on a valid extension.
    if not get_info.domain:
        rprint('[red]Invalid domain.  Please check the spelling of the domain!!![/]')
        sys.exit()
    if not get_info.creation_date:
            rprint(f'[orange3]Domain[/] [green1]{clean_domain_name}[/] [orange3]is not registeed[/].')
            sys.exit()
    # Then checks to see if the entry is the parent domain.
    if domain_name == clean_domain_name:
        get_dns_records(domain_name)
        sys.exit()
    # Finally it checks to see if it is a subdomain and prints the A record(s) for the subdomain.
    if domain_name != clean_domain_name:
        rprint (f'The entry [green1]{clean_domain_name}[/] is a subdomain of [green1]{domain_name}[/] and has the A [white]record(s):')
        # These next three lines print the A record(s) and then a blank line.
        a_answers = resolver.resolve(clean_domain_name, 'A')
        get_a_records(a_answers)
        print()
        get_dns_records(domain_name)
    # Exits cleanly if none of the above are caught.
    else:
        sys.exit()
except (whois.parser.PywhoisError) as e:
    print(f"Error: {e}")