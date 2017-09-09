"""

--- domainObjs --- [ARG]

dns_auth_and_renew takes an array of objects as its first argument. The form of this argument should be as follows:

domainObjs = [
    {
        "parent_domain": 'example.com',
        "subdomains": [                     # the domains we actually want certificates for
            '',                                 # for "example.com"
            'www',                              # for "www.example.com"
            'webdav'                            # for "webdav.example.com"
        ],
        "unauthorised": [],                 # internal use only, will be created if not supplied. Will lists the domains
                                            # that needed re authorizing
        "certs": [],                        # will be filled with the raw bytes of each generated certificate for each
                                            # subdomain, will be created if not supplied

        "challengeUpload_fcn": lambda record_key, record_value: updateZoneFile(record_key, record_value)
    }
]

    - You must supply the `updateZoneFile` function.
    - This function should add/replace a record in your zone file and ensure that the updated zone file begins
      propagating through the global DNS system.
    - dns_auth_and_renew will wait up to 1 hour for DNS propagation to complete.
    - Your function should update the zone file as shown below:

    @ 10800 IN A 80.190.80.190
    www 10800 IN CNAME example.com.
    webdav 10800 IN CNAME example.com.
    <record_key> 10800 IN TXT <record_value>       <<<<<< your function should add/update this <record_key>

    It is assumed that the same zone file update function can be used for all entries under the same parent_domain

---

--- writeCertsTo ---- [KWARG]

dns_auth_and_renew can be used to write certificates to a specific directory using the `writeCertsTo` keyword argument.

If this argument is falsy then no certificate files will be written.

Certificates will also be stored as bytes inside the "certs" field of the domainObj that is passed in.

---

--- account_path --- [KWARG]

The directory of the account.json file can be specified using the `account_path` keyword argument. It will default to
the current working directory.

---

returns True if successful, False otherwise.

---

"""


from manuale.cli import load_account, LETS_ENCRYPT_PRODUCTION, DEFAULT_ACCOUNT_PATH, DEFAULT_CERT_KEY_SIZE
import manuale.authorize as authorize
from manuale.acme import Acme
from manuale.issue import issue
import dns.resolver                     # from dnspython package
import time
import logging

logger = logging.getLogger(__name__)

LETS_ENCRYPT_SERVER = LETS_ENCRYPT_PRODUCTION
ACCOUNT_PATH = DEFAULT_ACCOUNT_PATH
AUTH_METHOD = 'dns-01'

def dns_auth_and_renew(domainObjs, writeCertsTo='.', account_path=None):

    if writeCertsTo:
        writeCerts = True
    else:
        writeCertsTo = None
        writeCerts = False

    if not account_path:
        account_path = ACCOUNT_PATH

    account = load_account(account_path)
    acme = Acme(LETS_ENCRYPT_SERVER, account)

    logger.info('Checking authorised domains')

    for parent_domain in domainObjs:
        for sd in parent_domain['subdomains']:
            domain = sd + '.' + parent_domain['parent_domain'] if sd else parent_domain['parent_domain']
            authObj = authorize.get_auth_obj(acme, domain)
            if authObj.get('status') == 'valid':
                pass
            else:
                challengeObj = authorize.get_challenge_obj(account, authObj, AUTH_METHOD)
                challengeUriPartial = "_acme-challenge." + sd if sd else "_acme-challenge"
                parent_domain['unauthorised'].append({
                    "subdomain": sd,
                    "challengeUriPartial": challengeUriPartial,
                    "challengeUriFull": challengeUriPartial + '.' + parent_domain['parent_domain'],
                    "challengeText": '"{}"'.format(challengeObj['txt_record']),
                    "challengeObj": challengeObj,
                    "authObj": authObj,
                    "authorised": False,
                    "uploaded": False
                })

    logger.info('uploading DNS challenges to unauthorised domains')

    for parent_domain in domainObjs:
        for cObj in parent_domain['unauthorised']:
            parent_domain['challengeUpload_fcn'](cObj['challengeUriPartial'], cObj['challengeText'])

    logger.info('waiting for DNS zone files to propogate')

    allUploaded = False
    totalWaitTime = 0
    checkInterval = 30
    maxWaitTime = 3600
    dnsResolver = dns.resolver.Resolver()
    dnsResolver.nameservers = ['8.8.8.8']
    while not allUploaded and totalWaitTime < maxWaitTime:
        allUploaded = True
        time.sleep(checkInterval)
        totalWaitTime += checkInterval
        for parent_domain in domainObjs:
            for cObj in parent_domain['unauthorised']:
                if not cObj['uploaded']:
                    try:
                        dnsText = dnsResolver.query(cObj['challengeUriFull'], 'TXT')[0].to_text()
                    except dns.resolver.NXDOMAIN:
                        dnsText = None

                    if dnsText and dnsText == cObj['challengeText']:
                        cObj['uploaded'] = True
                    else:
                        allUploaded = False

    if not allUploaded:
        logger.error('challenge upload failed. DNS challenge propagation timed out')
        logger.error('failed challenges:')
        for parent_domain in domainObjs:
            for cObj in parent_domain['unauthorised']:
                if not cObj['uploaded']:
                    logger.error('   ' + cObj['challengeUri'] + parent_domain)
        return False

    logger.info('DNS challenge propagation complete. Validating challenges...')

    allAuthorised = True
    for parent_domain in domainObjs:
        for cObj in parent_domain['unauthorised']:
            sd = cObj['subdomain']
            domain = sd + '.' + parent_domain['parent_domain'] if sd else parent_domain['parent_domain']
            challengeObj = cObj['challengeObj']
            auth = cObj['authObj']
            challenge = challengeObj['challenge']
            acme.validate_authorization(challenge['uri'], AUTH_METHOD, challengeObj['key_authorization'])
            if authorize.retrieve_verification(acme, domain, auth, AUTH_METHOD):
                cObj['authorized'] = True
            else:
                allAuthorised = False

    if not allAuthorised:
        logger.error('Authorisation Failed')
        logger.error('failed domains:')
        for parent_domain in domainObjs:
            for cObj in parent_domain['unauthorised']:
                if not cObj['authorized']:
                    logger.error('   ' + cObj['challengeUri'] + parent_domain)
        return False

    for parent_domain in domainObjs:
        for sd in parent_domain['subdomains']:
            domain = sd + '.' + parent_domain['parent_domain'] if sd else parent_domain['parent_domain']
            certObj = issue(
                LETS_ENCRYPT_SERVER,
                account,
                [domain],
                DEFAULT_CERT_KEY_SIZE,
                return_obj_only=(not writeCerts),
                output_path=writeCertsTo
            )
            for key in certObj:
                certObj[key] = certObj[key].decode('UTF-8')
            parent_domain["certs"].append({
                "domain": domain,
                "certs": certObj
            })

    return True
