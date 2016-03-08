import base64
import json


def handler(event, context):
    print('Received Event: %s' % json.dumps(event, indent=4))

    if not unicode('id_token') in event[unicode('data')]:
        return 'BAD REQUEST. id_token faltando'

    print('>> Verificando id_token')
    segments = event[unicode('data')][unicode('id_token')].split('.')
    header = json.loads(base64.b64decode(segments[0]))
    payload = json.loads(base64.b64decode(segments[1]))
    print('Header: %s' % json.dumps(header, indent=4))
    print('Payload: %s' % json.dumps(payload, indent=4))

    dataToSign = '.'.join([segments[0], segments[1]])
    sig = segments[2]


    return 'SUCCESS'

if __name__ == '__main__':
    print handler({
        u'data': {
            u'id_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ'
        }
    }, None)
