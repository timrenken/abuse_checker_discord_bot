from ipwhois import IPWhois,exceptions
import pydig
import logging

logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s -  %(levelname)s -  %(message)s')

class IpAddress:

    # Initialize the IpAddress object with the given IP address
    def __init__(self, ip):
        self.address = ip

        # Look up information about the IP address using the whois_lookup method
        results = self.whois_lookup()

        # Assign the ASN, CIDR, and hostname of the IP address to object properties
        self.asn = results['asn']
        self.cidr = results['asn_cidr']
        self.host = results['asn_description']

        # If there are multiple networks associated with the IP address,
        # find the one with the same CIDR as the IP address and assign its
        # location and email information to object properties
        if len(results['nets']) > 1:
            for net in results['nets']:
                if self.cidr == net['cidr']:
                    self.location = f"{net['city']}, {net['country']}"
                    self.emails = net['emails']
        
        # If there is only one network associated with the IP address,
        # assign its location and email information to object properties
        else:
            net = results['nets'][0]
            self.location = f"{net['city']}, {net['country']}"
            self.emails = net['emails']

    # Look up information about the IP address using the IPWhois library
    def whois_lookup(self):
        obj = IPWhois(self.address)
        results = obj.lookup_whois(inc_nir=True)
        return results

class Domain:
    # This is the constructor method that initializes the domain and its IP addresses
    def __init__(self,domain):
        # Store the domain name in a property
        self.domain = domain
        # Get the IP addresses for the domain by calling the dig() method
        self.ips = self.dig()

    # This method performs a DNS lookup to get the IP addresses for the domain
    def dig(self):

        # Create a pydig resolver with the specified nameservers and additional arguments
        resolver = pydig.Resolver(
            nameservers = [
                "8.8.8.8",
                "8.8.4.4"
            ],
            additional_args=[
                '+time=10'
            ]
        )
        # Perform the DNS lookup to get the "A" records for the domain
        addresses = resolver.query(self.domain, "A")
        
        # Log the results of the DNS lookup
        logging.debug(addresses)

        # Check if there are any addresses returned
        if len(addresses) > 0:

            # Create an empty list to store the IP addresses
            ips = []

            # Loop over the addresses
            for address in addresses:
                try:
                    # Check if the address contains a line return character
                    if "\r" in address:
                        # If it does, split the address on the line return character to remove it
                        address = address.split("\r")[0]
                    
                    # Create an IpAddress object for the address
                    ip = IpAddress(address)

                    # Log the ASN for the address
                    logging.debug(ip.asn)

                    # Add the IpAddress object to the list of IP addresses
                    ips.append(ip)

                # If there is a ValueError, skip the address and continue
                except ValueError:
                    continue

        # Return the list of IP addresses objects
        return ips

class Url:
    # Initializes a new Url object with the given address
    def __init__(self, address):
        
        # Store the address of the url
        self.address = address

        # Parse the scheme (e.g. "http") from the address
        self.scheme = self.address.split(":")[0]

        # Parse the domain from the address
        self.domain = self.address.split("//")[1].split("/")[0]

        # Add the full domain attribute
        self.full_domain = self.domain

        # Initialize an empty dictionary for parameters
        self.parameters = {}

        # If the domain includes a port number, parse it and remove it from the domain
        if ":" in self.domain:
            self.port = int(self.domain.split(":")[1])
            self.domain = self.domain.split(":")[0]

        # Parse the path from the address
        self.path = "/".join(self.address.split("//")[1].split("/")[1:])

        # If the domain is a subdomain (e.g. "www.example.com"), remove the subdomain
        if len(self.domain.split(".")) > 2:
            self.domain = ".".join(self.domain.split(".")[-2:])

        # Log the domain for debugging purposes
        logging.debug(self.domain)

        # If the path includes parameters, parse them and remove them from the path
        if "?" in self.path:
            parameters = self.path.split("?")[1]
            for parameter in parameters.split("&"):
                key,value = parameter.split("=")
                self.parameters[key] = value
            if self.path.split("?")[0] == "":
                self.path = "/"
            else:
                self.path = self.path.split("?")[0]

        # Create a Domain object for the url's domain
        domain = Domain(self.domain)

        # Look up the IP addresses for the domain
        self.ips = domain.dig()

        
        
        
        