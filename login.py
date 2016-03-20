import base64
import json
import Crypto
import urllib2
from Crypto.Hash import SHA256


def handler(event, context):
    print('Received Event: %s' % json.dumps(event, indent=4))

    if not unicode('id_token') in event[unicode('data')]:
        return 'BAD REQUEST. id_token faltando'

    print('>> Verificando id_token')
    segments = map(base64padding, event[unicode('data')][unicode('id_token')].split('.'))
    header = json.loads(base64.b64decode(segments[0]))
    payload = json.loads(base64.b64decode(segments[1]))
    print('Header: %s' % json.dumps(header, indent=4))
    print('Payload: %s' % json.dumps(payload, indent=4))

    cert = getGoogleCertificates(header[u'kid'])

    dataToSign = '.'.join([segments[0], segments[1]])
    sig = segments[2]
    hash = SHA256.new()
    hash.update(dataToSign)

    return 'SUCCESS'


def base64padding(u64string):
    missing_padding = 4 - len(u64string) % 4
    if missing_padding:
        u64string += b'='* missing_padding
    return str(u64string)


def getGoogleCertificates(kid):
    cert_url = 'https://www.googleapis.com/oauth2/v1/certs'
    print('Obtendo Google certificados de: %s' % cert_url)

    try:
        resp = urllib2.urlopen(cert_url)
        cert_json = resp.read()
        cert_dic = json.loads(cert_json)
    except:
        raise Exception('INTERNAL SERVER ERROR. Nao foi possivel obter Google certificados')

    if kid not in cert_dic:
        raise Exception('UNAUTHORIZED. Certificado nao encontrado')
    print(kid +': '+ cert_dic[kid])

    return cert_dic[kid]


if __name__ == '__main__':
    print (handler({
        u'data': {
            u'id_token': 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImUwNWY4NzAxOWQ3OGY4ZWY3ZjI4YTUyYjYxOWM5ODgxZTZjNDc1MDYifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiIxMjUxNzU1MzI5MDgtZXBxZ3JoM2JsNTQ1cnAwam5uN2VhYzVycmJ2bGRvNW8uYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDA1OTUwNTM2MzQyMjYzNTg5NjIiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXpwIjoiMTI1MTc1NTMyOTA4LWFncTQ2Y3ZqdjM2bWYzN2xsdHQwY2pqa2JvZHRiaTVuLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiaGQiOiJjb25jcmV0ZXNvbHV0aW9ucy5jb20uYnIiLCJlbWFpbCI6InVpbHF1ZS5jcnV6QGNvbmNyZXRlc29sdXRpb25zLmNvbS5iciIsImlhdCI6MTQ1ODMyODA1MCwiZXhwIjoxNDU4MzMxNjUwLCJuYW1lIjoiVWlscXVlIENydXoiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDUuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy1ldzFWcVNaMHNEVS9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBMC9hcnZsODZBY1cxYy9zOTYtYy9waG90by5qcGciLCJnaXZlbl9uYW1lIjoiVWlscXVlIiwiZmFtaWx5X25hbWUiOiJDcnV6IiwibG9jYWxlIjoiZW4ifQ.MTSmgp_uYO5DMBVrwpAteD-rB3iK4Kt6CVYrj_fghjJgCJsRViBjeBiLJu4UXmjE7JR9g0KZPLK1-MAjkTmDLtwNikDjU4KfORDuyMDNZZOFYF0Siqc06ZNOq7UpAHbo-1dkpRn9Buyyc95f9P3gcDZR9HkRJ6fd0MkRydIbrxjnoxjuXGCXFFYDEg8x68YL02YpDOBw7GnqFEQzZJDVHNW88Umxrnfg4KRZMV-Wal0ziboHJmiRWue_g1f9mTgZm8dfl9BeSlQJvSK8PW6PTx7RkaI-Cu7w2S23ZfVO42dAcaLieAJrWWXZicRSjc1L0LrPJTn2M-j8l38St71ljw'
        }
    }, None))
