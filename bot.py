import os
import discord
from discord.ext import commands
from dotenv import load_dotenv
from objects import IpAddress,Url,Domain
from urlscan import UrlScan
from abuseipdb import AbuseIPDB
from virustotal import VT
import logging

logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s -  %(levelname)s -  %(message)s')

# Load environment variables from .env file
load_dotenv()

# Get the Discord bot token from the environment variables
token = os.getenv('DISCORD_TOKEN')

# Enable message content intent
intents = discord.Intents.default()
intents.message_content = True

# Initialize the Discord client with the command prefix "/check " and the enabled intents
client = commands.Bot(command_prefix="/check ", intents=intents)

client.remove_command('help')

@client.command()
async def help(ctx):
# Send a message with the available commands and their usage
    await ctx.send(
    "List of available commands:\n"
    "/check ip host <ip_address> - Get the hostname for the given IP address.\n"
    "/check ip score <ip_address> - Get the abuse score for the given IP address.\n"
    "/check domain host <domain> - Get the IP address and hostname for the given domain.\n"
    "/check url urlscan [uuid=<report_uuid>] <url> - Get the URLScan.io verdict of the given URL or report UUID.\n"
    "/check url vt <url> - Scan the given URL with VirusTotal and get the analysis results."

    )

@client.command()
async def ip(ctx,command,address):

    # List of accepted commands
    accepted_commands = ['host','score']

    # If the command is not in the accepted list, send an error message
    if command.lower() not in accepted_commands:
        await ctx.send('Invalid command')

    # If the command is "host", get the hostname for the given IP address and send it
    elif command.lower() == 'host':
        ip = IpAddress(address)
        await ctx.send(f"The owner of {address} is {ip.host}")
    
    # If the command is "score", get the abuse score for the given IP address and send it
    elif command.lower() =='score':
        abuse = AbuseIPDB(address)
        stats = abuse.get_results()
        await ctx.send(f"{address} has an abuse score of `{stats.score}` from {stats.users_reported} users.")

@client.command()
async def domain(ctx,command,domain):

    # List of accepted commands
    accepted_commmands =['host']

    # If the command is not in the accepted list, send an error message
    if command.lower() not in accepted_commmands:
        await ctx.send('Invalid command')
    
    # If the command is "host", get the IP address and hostname for the given domain and send it
    elif command.lower() == 'host':
        result = Domain(domain)
        for ip in result.ips:
            await ctx.send(f"The IP for {domain} is {ip.address} and it's hosted with {ip.host}")
        
@client.command()
async def url(ctx, command, arg):

    # List of accepted commands
    accepted_commands = ['urlscan', "vt"]

    # If the command is not in the accepted list, send an error message
    if command.lower() not in accepted_commands:
        await ctx.send('Invalid command')
    
    # If the command is "urlscan", get the verdict of the given URL and send it.
    elif command.lower() == 'urlscan':

        # If the argument starts with "uuid", assume the user is providing a report UUID
        if arg.startswith('uuid'):

            # Get the UUID value from the argument string
            result_uuid = arg.split("=")[1]

            # Create an instance of the UrlScan class with the given UUID
            results = UrlScan(result_uuid=result_uuid)

            # Send the report URL and verdict score to the user
            await ctx.send(f"The report URL is: {results.report_url}\nThe verdict score is: {results.verdict_score}")


        # If the argument doesn't start with "uuid", assume the user is providing a URL
        else:
            # Create an instance of the UrlScan class with the given URL
            results = UrlScan(address=arg)

            # Send the report URL and verdict score to the user
            await ctx.send(f"The report URL is: {results.report_url}\nScore: {results.verdict_score}")

    # If the command is "vt", scan the given URL with VirusTotal and send the analysis results.
    elif command.lower() == "vt":

        # Scan the given URL with VirusTotal
        vt = VT(arg)

        # Start assembling the message
        message = f"The results URL is: {vt.results_url}\n >> {vt.malicious_stats} engines determined this URL to be malicious"
        for engine,result in vt.results.items():
            message += f"\n   >> {engine}: {result}"
        
        # Send message
        await ctx.send(message)


client.run(token)
