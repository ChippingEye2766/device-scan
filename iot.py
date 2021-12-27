from flask import Flask, request, make_response, send_from_directory, render_template

import requests
import json
import os
from xml.dom import expatbuilder


def getChilds(data):
    state = data[0].getAttribute('state')
    service = data[1].getAttribute('name')
    application = data[1].getAttribute('product').lower()
    application_version = data[1].getAttribute('version').lower()
    return state,service,application,application_version


def hit_cli_d(ip):
    """
    Hit post endpoint
    :param request_type: POST or GET
    :param url: endpoint
    :param query: request data
    :return: curl's response
    """
    os.system("nmap -sV -oX output.xml "+ip)
    document = expatbuilder.parse('output.xml', False)
    ports = document.getElementsByTagName('port')
    open_ports=[]
    port_states = []
    services_used=set()
    application_used= {}

    for port in ports:
        open_ports.append(port.getAttribute('portid'))
        state, service, application, application_version =getChilds(port.childNodes)
        port_states.append(state)
        services_used.add(service)
        application_used[application] = application_version


    output = "<!DOCTYPE html><html>"
    output += "<h1> ******** Results for " + ip + " ********* </h1><br/>"
    output += "<h3>  Ports (" + str(len(open_ports)) + ") </h3><br/>"
    output += "<table style='border:1px solid black'>"
    output += "<tr>"
    output += "<th style='border:1px solid black'> Port </th>"
    output += "<th style='border:1px solid black'> Status </th>"
    output += "</tr>"

    for i in range(len(open_ports)):
        if open_ports:
            port=open_ports[i]
            service=port_states[i]
            output += "<tr>"
            output += "<td style='border:1px solid black'>" +port + "</td>"
            output += "<td style='border:1px solid black'>" +service+ "</td>"
    output  += "</table>"
    output += "<h3>   Services hosted (" + str(len(services_used)) + ") </h3><br/>"
    output += " ".join(services_used) + "<br/><br/>"
    output += "<h3>  Application found (" + str(len(application_used.keys())) + ") </h3><br/>"
    output += " ".join(application_used.keys()) + "<br/><br/>"
    output =get_vuln(application_used,output)
    output += "</html>"
    return output

        

def getDataNmap(ip):
    data=hit_cli_d(ip)
    return data

def get_vuln(applications,output):
    auth_token = "AAAACT8uBPnNC/7Yod7h4Rviz9HLMHK+iEGA36o2b5L451CZ" # Appcheck Auth Token
    blackduck_api_endpoint = "https://appcheck.digital-security.a2z.com/api/components/{library}/vulns/?version={version}"
    headers = {"Authorization": "Bearer " + auth_token}
    # cafile = './ca-bundle.crt'
    cafile = '/Users/sbbanore/Downloads/Amazon.com Internal Root Certificate Authority.pem'

    output += "<table style='border:1px solid black'>"
    output += "<tr>"
    output += "<th style='border:1px solid black'> CVE </th>"
    output += "<th style='border:1px solid black'> CVSS SCORE </th>"
    output += "<th style='border:1px solid black'> SUMMARY</th>"
    output += "</tr>"

    for application in applications.keys():
        lib_name=application.split(" ")[0]
        lib_version= applications[application].split(" ")[0]
        url = blackduck_api_endpoint.format(library=lib_name, version=lib_version)
        response = requests.get(url, headers=headers, verify=cafile)
        if response.status_code != 200:
            continue
        obj = json.loads(response.text)
        if "vulns" in obj.keys():
            for vul in obj["vulns"]:
                if vul:
                    output += "<tr>"
                    output += "<td style='border:1px solid black'>" +vul["vuln"]["cve"] + "</td>"
                    output += "<td style='border:1px solid black'>" +vul['vuln']["cvss3_score"]+ "</td>"
                    output += "<td style='border:1px solid black'>" +vul["vuln"]["summary"]+ "</td>"
                    output += "</tr>"
    output+="</table>"
    return output

# if __name__ == '__main__':
#     getDataNmap("45.33.32.156")