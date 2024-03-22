#!/usr/bin/env python
# Python program to mimic doing multiple dig commands in bash and providing the information parsed in an easy to read format.

# Written by David M Harris on 16 March 2024
# Last modified 21 March 2024
# dave@harris-services.com

# Import the normal system calls, as well as the dnspython, rich, tldextract and python-whois modules.
import sys
import dns.name # pip install dnspython
import dns.resolver
import dns.reversename
from rich import print as rprint # pip install rich
import tldextract # pip install tldextract
import whois # pip install python-whois
import socket

# Take the domain as an argument or prompt for it.
try:
    entered_domain_name = sys.argv[1]
except IndexError:
    entered_domain_name = input ("Enter the domain to check: ")

# Extracts the domain name from a subdomain
clean_domain_name = tldextract.extract(entered_domain_name).fqdn
domain_name = tldextract.extract(entered_domain_name).registered_domain

# Sets the resolver to one that works with DNSSEC.
resolver = dns.resolver.Resolver()
resolver.nameservers = ['4.2.2.1']

# Function to get A recrords from other records.
def get_a_records(a_answers):
        for rdata in a_answers:
            print(f'A record for the subdomain: {rdata.address}')

# Function that retreives SOA and NS information.
def resolve_dns(record_label, domain_name, record_type):
    print()
    print(record_label)
    return resolver.resolve(domain_name, record_type)

# Function that does all of the work.
def get_dns_records(domain_name):
    # Print the header.
    rprint (f"DNS for [green1]{domain_name}[/].\n")

    # Print the A record(s) for the domain.
    rprint ("[cyan]A record(s):[/]")
    a_answers = resolver.resolve(domain_name, 'A')
    get_a_records(a_answers)

# Print the SOA record for the domain.
    soa_answers = resolve_dns("SOA:", domain_name, 'SOA')
    for rdata in soa_answers:
        print(f' serial: {rdata.serial} | tech: {rdata.rname} | mname: {rdata.mname}')
        print(f' refresh: {rdata.refresh} | retry: {rdata.retry} | expire: {rdata.expire} | minimum: {rdata.minimum}')

# Print the nameservers for the domain with the related A record(s).
    ns_answers = resolve_dns("Nameservers:", domain_name, 'NS')
    for server in ns_answers:
        print(server.target)
        a_answers = resolver.resolve(server.target, 'A')
        get_a_records(a_answers)
        print()

    # Print the MX records for the domain with the related A record(s).
    print ("MX:")
    try:
        mx_answers = resolver.resolve(domain_name, 'MX',)
        try:
            for rdata in mx_answers:
                print('Host', rdata.exchange, 'has preference', rdata.preference)
                try:
                    a_answers = resolver.resolve(rdata.exchange, 'A')
                    for mx_rdata in a_answers:
                        print(mx_rdata.address, 'PTR:', resolver.resolve((dns.reversename.from_address(mx_rdata.address)), "PTR")[0])
                    print()
                except Exception:
                    print()
        except Exception:
            print()
    except Exception:
        print('There are no MX records defined.\n')

    # Print the TXT record(s) for the domain.
    print ("TXT:")
    try:
        txt_answers = resolver.resolve(domain_name, 'TXT')
        for rdata in txt_answers:
            for txt_string in rdata.strings:
                print(str(txt_string, 'utf-8'))
        sys.exit()
    except Exception:
        print('There are no TXT records defined.\n')
        sys.exit()

# Performing the base whois check to be used later.

try:
    dns_exists = resolver.resolve(domain_name, 'SOA')
    print (dns_exists.canonical_name)
    dns_failed = domain_name
except Exception:
    dns_failed = 'True'
    print(Exception, dns_failed)

try:
    get_info = (whois.whois(domain_name))
#getinfo2 = pythonwhois.whois(domain_name)
#print (getinfo2)
#sys.exit()

# Checks to see if the domain is based on a valid extension.
    if not get_info.domain:
        rprint('[red]Invalid domain.  Please check the spelling of the domain!!![/]')
        sys.exit()

    if dns_failed != domain_name:
        try:
            rprint(f'[orange3]Domain[/] [green1]{clean_domain_name}[/] [orange3]is not registeed.[/]')
            sys.exit()
        except Exception:
            sys.exit()

    if not get_info.creation_date:
        rprint(f'Body: [orange3]Domain[/] [green1]{clean_domain_name}[/] [orange3]cannot be checked by the whois module.[/]')
        # If the domain is not able to be checked via whois correctly the user is prompted to see if they want to get the DNS anyway.
        continue_to_dns = input('Do you want to to get DNS for the domain anyhow? (Y or N): ')
        if continue_to_dns in ('y', 'Y', 'Yes', 'YES', 'yes'):
            get_dns_records(domain_name)
        else:
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
    #print(f"Error: {e}")
    rprint(f'[orange3]Exception: Domain[/] [green1]{clean_domain_name}[/] [orange3]is not registeed.[/]')