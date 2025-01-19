#!/usr/bin/python
# Python program to mimic doing multiple dig commands in bash and providing the information parsed in an easy to read format.

# Written by David M Harris on 16 March 2024
# Last modified 17 Jan 2025
# dave@harris-services.com

## !!! Build the project with pyinstaller pydig.spec to avoid losing the whois data setup !!!

# Import the normal system calls, as well as the dnspython, rich, tldextract and python-whois modules.
import sys
import dns.name # pip install dnspython
import dns.resolver
import dns.reversename
from rich import print as rprint # pip install rich
import tldextract # pip install tldextract
import whois # pip install python-whois as well as pip install python-dateutil if you receive an error related to that module.

# Take the domain as an argument or prompt for it.
try:
    entered_domain_name = sys.argv[1]
except IndexError:
    rprint('Enter the domain to check: ', end='')
    entered_domain_name = input()

# Extracts the domain name from a subdomain
clean_domain_name = tldextract.extract(entered_domain_name).fqdn
domain_name = tldextract.extract(entered_domain_name).registered_domain

# Sets the resolver to one that works with DNSSEC.
resolver = dns.resolver.Resolver()
resolver.nameservers = ['4.2.2.1']

# Function to get A recrords from other records.
def get_a_records(a_answers):
        for rdata in a_answers:
            rprint(rdata.address)

# Function that retreives SOA and NS information.
def resolve_dns(record_label, domain_name, record_type):
    rprint()
    rprint(record_label)
    return resolver.resolve(domain_name, record_type)

# Function that does the work of getting the various DNS records.
def get_dns_records(domain_name):
    # Print the header.
    rprint (f"[dark_orange]DNS for [green1]{domain_name}[/].\n")

    # Print the A record(s) for the domain.
    rprint ("[dark_orange]A record(s):[/]")
    a_answers = resolver.resolve(domain_name, 'A')
    get_a_records(a_answers)

    # Print the SOA record for the domain.
    soa_answers = resolve_dns("[dark_orange]SOA:[/]", domain_name, 'SOA')
    for rdata in soa_answers:
        rprint(f' serial: {rdata.serial} | tech: {rdata.rname} | mname: {rdata.mname}')
        rprint(f' refresh: {rdata.refresh} | retry: {rdata.retry} | expire: {rdata.expire} | minimum: {rdata.minimum}')

    # Print the nameservers for the domain with the related A record(s).
    ns_answers = resolve_dns("[dark_orange]Nameservers:[/]", domain_name, 'NS')
    for server in ns_answers:
        rprint(server.target)
        a_answers = resolver.resolve(server.target, 'A')
        get_a_records(a_answers)
        rprint()

    # Print the MX records for the domain with the related A record(s).
    rprint ("[dark_orange]MX:[/]")
    try:
        mx_answers = resolver.resolve(domain_name, 'MX',)
        try:
            for rdata in mx_answers:
                rprint('[hot_pink]Host[/]', rdata.exchange, '[hot_pink]has preference[/]', rdata.preference,)
                try:
                    a_answers = resolver.resolve(rdata.exchange, 'A')
                    for mx_rdata in a_answers:
                        rprint(mx_rdata.address, '[hot_pink]PTR:[/]', resolver.resolve((dns.reversename.from_address(mx_rdata.address)), "PTR")[0])
                    rprint()
                except Exception:
                    rprint()
        except Exception:
            rprint()
    except Exception:
        rprint('[red]There are no MX records defined.[/]\n')

    # Print the TXT record(s) for the domain.
    rprint ("[dark_orange]TXT:[/]")
    try:
        txt_answers = resolver.resolve(domain_name, 'TXT')
        for rdata in txt_answers:
            for txt_string in rdata.strings:
                print(str(txt_string, 'utf-8'))
        sys.exit()
    except Exception:
        rprint('There are no TXT records defined.\n')
        sys.exit()

# Performing the base whois check to be used later.
try:
    dns_exists = resolver.resolve(domain_name, 'SOA')
    #print (dns_exists.canonical_name)
    dns_failed = domain_name
except Exception:
    dns_failed = 'True'
    #print(Exception, dns_failed)

# Getting whois information for the parent domain entered.
try:
    get_info = (whois.whois(domain_name))

    # Checks to see if the domain is based on a valid extension.
    if not get_info.domain:
        rprint('[red]Invalid domain.  Please check the spelling of the domain!!![/]')
        sys.exit()

    # Checks to see if the domain is registered.
    if dns_failed != domain_name:
        try:
            rprint(f'[orange3]Domain[/] [green1]{clean_domain_name}[/] [orange3]is not registeed.[/]')
            sys.exit()
        except Exception:
            sys.exit()

    # Checks to see if the entry is the parent domain.
    if domain_name == clean_domain_name:
        get_dns_records(domain_name)
        sys.exit()

    # Checks to see if the entry is a subdomain and prints the A record(s) for the subdomain, and then prints the rest of the DNS.
    if domain_name != clean_domain_name:
        rprint (f'The entry [green1]{clean_domain_name}[/] is a subdomain of [green1]{domain_name}[/] and has the A [white]record(s):')
        # These next three lines print the A record(s) and then a blank line.
        a_answers = resolver.resolve(clean_domain_name, 'A')
        get_a_records(a_answers)
        print()
        # Print the rest of DNS for the domain.
        get_dns_records(domain_name)
    # Exits cleanly if none of the above are caught.
    else:
        sys.exit()

    # Checks to see if the domain is not able to be checked by the Python whois module.
    if not get_info.creation_date:
        rprint(f'[orange3]Domain[/] [green1]{clean_domain_name}[/] [orange3]cannot be checked by the whois module.[/]')
        # If the domain is not able to be checked via whois correctly the user is prompted to see if they want to get the DNS anyway.
        print('Do you want to to get DNS for the domain anyhow? (Y or N): ', end='')
        continue_to_dns = input()
        if continue_to_dns in ('y', 'Y', 'Yes', 'YES', 'yes'):
            get_dns_records(domain_name)
        else:
            sys.exit()

    # Checks to see if the entry is the parent domain.
    #if domain_name == clean_domain_name:
    #    get_dns_records(domain_name)
    #    sys.exit()

    # Checks to see if the entry is a subdomain and prints the A record(s) for the subdomain, and then prints the rest of the DNS.
    #if domain_name != clean_domain_name:
    #    rprint (f'The entry [green1]{clean_domain_name}[/] is a subdomain of [green1]{domain_name}[/] and has the A [white]record(s):')
        # These next three lines print the A record(s) and then a blank line.
    #    a_answers = resolver.resolve(clean_domain_name, 'A')
    #    get_a_records(a_answers)
    #    rprint()
        # Print the rest of DNS for the domain.
    #    get_dns_records(domain_name)
    # Exits cleanly if none of the above are caught.
    #else:
    #    sys.exit()

# Prints any errors that are not caught by the above.
except (whois.parser.PywhoisError) as e:
    rprint(f"Error: {e}")
    sys.exit()