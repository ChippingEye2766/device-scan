from flask import Flask, request, make_response, send_from_directory, render_template
import requests

app = Flask(__name__)


@app.route("/api/scan",methods = ['GET', 'POST'])
def shodan_search():
    ip = request.args.get("ip")
    data = getData(ip)
    return data
    # return render_template('template.html',output=data)

def getData(ip):
    BASE_URL = "https://api.shodan.io/shodan/host/"
    
    # Replace with api key
    API_KEY = "XXXX"
    resp = requests.get(url=BASE_URL + ip + "?key=" + API_KEY)
    data = resp.json()
    printed = []
    output = "<!DOCTYPE html><html>"
    output += "<h1> ******** Results for " + ip +" ********* </h1><br/>"
    output += "<h3>   Open Ports (" + str(len(data['ports'])) + ") </h3><br/>"
    output += str(data['ports']) + "<br/><br/>"
    output += "<h3>   Open CVEs (" + str(len(data['vulns'])) + ") </h3><br/>"
    output += "<table style='border:1px solid black'>"
    output += "<tr>"
    output += "<th style='border:1px solid black'> ID </th>"
    output += "<th style='border:1px solid black'> CVSS </th>"
    output += "<th style='border:1px solid black'> Summery </th>"
    output += "</tr>"

    for obj in data["data"]:
        if "vulns" in obj.keys():
            for vul in obj["vulns"]:
                if vul not in printed:
                    output += "<tr>"
                    output += "<td style='border:1px solid black'>" +vul + "</td>"
                    output += "<td style='border:1px solid black'>" +str(obj["vulns"][vul]["cvss"])+ "</td>"
                    output += "<td style='border:1px solid black'>" +obj["vulns"][vul]["summary"]+ "</td>"
                    printed.append(vul)
                    output += "</tr>"
    output += "</table>"

    output += "</html>"
    return output



    


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
