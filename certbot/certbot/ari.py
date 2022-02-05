"""Cerbot implementation of the ACME Renewal Information (ARI) Extension."""
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509 import ocsp, Certificate
import datetime
import josepy as jose
from random import randrange
import requests
from typing import Union

from acme.messages import RenewalInfo
from certbot.interfaces import RenewableCert  # pylint: disable=unused-import

class AriChecker(object):
    """This class checks ACME Renewal Info."""

    def __init__(self, ari_endpoint: str) -> None:
        self.ari_endpoint = ari_endpoint.rstrip('/')

    def _compute_path(self, cert: Certificate, issuer: Certificate) -> str:
        # Rather than compute the serial, issuer key hash, and issuer name hash
        # ourselves, we instead build an OCSP Request and extract those fields.
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA1())
        ocspRequest = builder.build()

        # Construct the ARI path from the OCSP CertID sequence.
        key_hash = ocspRequest.issuer_key_hash.hex()
        name_hash = ocspRequest.issuer_name_hash.hex()
        serial = hex(ocspRequest.serial_number)[2:]
        path = f"{key_hash}/{name_hash}/{serial}"

        return '/'.join([self.ari_endpoint, path])

    def _get_ari(self, cert: Certificate, issuer: Certificate) -> Union[RenewalInfo, bool]:
        url = self._compute_path(cert, issuer)
        breakpoint()
        try:
            response = requests.get(url)
        except requests.exceptions.RequestException:
            return False
        if response.status_code != 200:
            return False

        try:
            json = response.json()
        except requests.exceptions.JSONDecodeError:
            return False

        try:
            ari = RenewalInfo.from_json(json)
        except jose.errors.DeserializationError:
            return False

        return ari

    def should_renew(self, cert: Certificate, issuer: Certificate) -> bool:
        """Checks whether the certificate should renew based on ARI information."""
        ari = self._get_ari(cert, issuer)
        if isinstance(ari, RenewalInfo):
            window_secs = ari.window.end + datetime.timedelta(seconds=1) - ari.window.start
            rand_offset = randrange(int(window_secs.total_seconds()))
            instant = ari.window.start + datetime.timedelta(seconds=rand_offset)
            return instant <= datetime.datetime.now()
        return False

    def should_renew_by_paths(self, cert_path: str, chain_path: str) -> bool:
        """Accepts cert and chain by path and passes them to should_renew()."""
        with open(cert_path, 'rb') as file_handler:
            cert = x509.load_pem_x509_certificate(file_handler.read())
        with open(chain_path, 'rb') as file_handler:
            issuer = x509.load_pem_x509_certificate(file_handler.read())
        return self.should_renew(cert, issuer)
