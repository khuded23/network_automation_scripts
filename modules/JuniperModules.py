import json
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)
from netmiko import ConnectHandler
from netmiko.ssh_autodetect import SSHDetect
import requests


def JunosASpathPrependCheck(var:str)-> str:

    '''
    takes a juniper export policy-statement and will give out the as-path 
    prepend number
    '''
    y = re.findall("as-path-prepend (.*)",var)
    x = y[0].split(" ")
    return len(x)


def device_connection(host_id: str, credentials: dict) -> ConnectHandler:

    '''
    Connection handler for devices, auto detects the device type
    and returns connection element.
    '''

    remote_device = {
        "device_type": "juniper_junos",
        "host": host_id,
        "username": credentials.get("username"),
        "password": credentials.get("password"),
        "port": 22,

    } 

    try:
        connection = ConnectHandler(**remote_device)
    except(
        NetmikoTimeoutException,
        NetmikoAuthenticationException
    )as e:
        print(f"could not connect to {host_id} due to : {e}")
        connection=None
    
    return connection
