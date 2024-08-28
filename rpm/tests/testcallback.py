
import requests
client_cert = "client.crt"
client_key_file = "client.key"
x = requests.get('https://localhost:8443/gahainvpiwg0awhgiewn0ihaw0g', cert=(client_cert, client_key_file), verify="ca.crt")

print(x.text)