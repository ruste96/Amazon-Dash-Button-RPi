# Import scapy Lib
from scapy.all import *

# Import telepot Lib
import telepot

# Bot token telegram (@botfather -> /new -> follow istructions)
TOKEN = ""
# Chat_id to send the message
CHAT_ID = ""

# Arping interface
IFACE = "eth0"

# Static ip button
IP_STATIC_BUTTON = ""
MAC_BUTTON = ""


# Start bot
bot = telepot.Bot(TOKEN)
print("Bot instantiated")


# Check button function
def check_button(pkt):
    if pkt.haslayer(ARP):
        if pkt[ARP].psrc == IP_STATIC_BUTTON: # Ip dash button amazon
            if pkt[ARP].hwsrc == MAC_BUTTON: # Mac address amazon button
                print("Amazon dash button pressed")
                print("Sending message to " + CHAT_ID)
                bot.sendMessage(CHAT_ID, "Amazon dash button pressed")


# Start sniffing
print("Start sniffing (CTRL+C stop)")
sniff(iface=IFACE, filter="arp", count=0, store=0, prn=check_button)
