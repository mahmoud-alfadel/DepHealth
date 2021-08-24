from flask import Flask, redirect, url_for, render_template, request, session
import json
import sys
import os
import pandas as pd
from pprint import pprint
from datetime import datetime


app = Flask(__name__)
app.secret_key = os.urandom(12)  

def get_vulnerability_data(package_name):
    # github token
    data = []
    for _, row in vul_df.iterrows():
        if package_name == row['affects_name']:
            data.append(row.to_dict())
    
    
    return data










pkg_df = pd.read_csv("data/packages.csv")
vul_df = pd.read_csv("data/vulnerabilities.csv")
vul_df = vul_df.fillna("")
vul = json.loads(vul_df['affects_name'].value_counts().to_json())

def get_package_data():
    data = dict()
    for index, row in pkg_df.iterrows():
        item = dict()
        item['Package Name'] = row['Package name']
        item['AVG Time to Discover'] = row['Disclosed VS First Affected']
        item['AVG Time to Fix'] = 0
        try:
            item['AVG Time to Fix'] = max(( datetime.strptime(row['Discloded date'],"%m/%d/%Y") - datetime.strptime(row['FirstFixedRelease_Date'],"%m/%d/%Y")).days, 0)

        except Exception as e:
            # print(e)
            pass
        try:
            item['AVG Time to Discover'] = max(( datetime.strptime(row['Discloded date'],"%m/%d/%Y") - datetime.strptime(row['FirstAffectedRelease_Date'],"%m/%d/%Y")).days, 0)

        except Exception as e:
            #print(e)
            pass
        item['Number of Vulnerability Reports']  = vul.get(row['Package name'], 0)
        item['Severity Level']= row['Severity']
        if data.get(row['Package name']) != None:
            data[row['Package name']].append(dict(item))
        else:
            data[row['Package name']] = [dict(item)]
    packages = []
    for package, items in data.items():
        result = dict()
        result['Package Name'] = package
        attdh = []
        attdm = []
        attdl = []
        attfh = []
        attfm = []
        attfl = []
        severities = []
        for i, item in enumerate( items):
            if  item['Severity Level'] == 'H':
                attdh.append(item['AVG Time to Discover'])
                attfh.append(item['AVG Time to Fix'])
            if  item['Severity Level'] == 'M':
                attdm.append(item['AVG Time to Discover'])
                attfm.append(item['AVG Time to Fix'])
            if  item['Severity Level'] == 'L':
                attdl.append(item['AVG Time to Discover'])
                attfl.append(item['AVG Time to Fix'])
            severities.append(item['Severity Level'])
        result['AVG Time to Discover (H)'] = 0
        if attdh:
            result['AVG Time to Discover (H)'] = sum(attdh)//len(attdh)
        result['AVG Time to Discover (M)'] = 0
        if attdm:
            result['AVG Time to Discover (M)'] = sum(attdm)//len(attdm)
        
        result['AVG Time to Discover (L)'] = 0
        if attdl:
            result['AVG Time to Discover (L)'] = sum(attdl)//len(attdl)
        result['AVG Time to Fix (H)'] = 0
        result['AVG Time to Fix (M)'] = 0
        result['AVG Time to Fix (L)'] = 0
        if attfh:
            result['AVG Time to Fix (H)'] = sum(attfh)//len(attfh)
        if attfm:
            result['AVG Time to Fix (M)'] = sum(attfm)//len(attfm)
        if attfl:
            result['AVG Time to Fix (L)'] = sum(attfl)//len(attfl)
        result['H'] = severities.count('H')
        result['M'] = severities.count('M')
        result['L'] = severities.count('L')
        result['Number of Vulnerability Reports'] = len(severities)
        packages.append(result)
    return packages


@app.route('/')
def home():
    packages = get_package_data()
    # pprint(packages)
    return render_template('home.html', packages = packages)

@app.route('/package/<package_name>/')
def get_vulnerability(package_name):
    return render_template('package.html', packages = get_vulnerability_data(package_name))


if __name__ == "__main__":
    # app.run(debug=True, use_reloader=True, host="0.0.0.0")
    app.run(host="104.237.154.205", port=8443, use_reloader=True, debug=True)
