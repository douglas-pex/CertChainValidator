import os
import requests
from datetime import datetime, timezone
from cryptography import x509


def load_certificate(cert_path):
    """Carrega o certificado a partir de um arquivo."""
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
        cert = (
            x509.load_pem_x509_certificate(cert_data)
            if b"-----BEGIN CERTIFICATE-----" in cert_data
            else x509.load_der_x509_certificate(cert_data)
        )
    return cert


def load_certificates_from_directory(directory):
    """Carrega todos os certificados X.509 de uma pasta."""
    certificates = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.cer', '.crt', '.pem')):
                try:
                    cert_path = os.path.join(root, file)
                    cert = load_certificate(cert_path)
                    certificates.append(cert)
                except Exception as e:
                    print(f"Erro ao carregar {file}: {e}")
    return certificates


def get_extension_value(cert, extension_name):
    """Obtém o valor de uma extensão específica do certificado."""
    try:
        # Mapeia os nomes das extensões para os OIDs disponíveis
        oid_map = {
            "AUTHORITY_KEY_IDENTIFIER": x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            "SUBJECT_KEY_IDENTIFIER": x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            "AUTHORITY_INFORMATION_ACCESS": x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
        }
        # Obtém a extensão usando o OID correspondente
        ext = cert.extensions.get_extension_for_oid(oid_map[extension_name])
        return ext.value
    except x509.ExtensionNotFound:
        return None


def fetch_certificate_from_aia(cert):
    """Busca o certificado do emissor usando a URL do campo AIA."""
    try:
        aia_extension = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    except x509.ExtensionNotFound:
        print("Extensão Authority Information Access (AIA) não encontrada no certificado.")
        return None

    for access_description in aia_extension.value:
        if access_description.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
            url = access_description.access_location.value
            try:
                response = requests.get(url)
                response.raise_for_status()
                return x509.load_der_x509_certificate(response.content)
            except Exception as e:
                print(f"Erro ao buscar certificado do emissor em {url}: {e}")
    return None


def find_issuer_certificate(cert, cert_pool):
    """Encontra o certificado emissor dentro do pool de certificados com base nos identificadores."""
    authority_key_id = get_extension_value(cert, "AUTHORITY_KEY_IDENTIFIER")
    if not authority_key_id:
        return None
    for potential_issuer in cert_pool:
        subject_key_id = get_extension_value(potential_issuer, "SUBJECT_KEY_IDENTIFIER")
        if subject_key_id and authority_key_id.key_identifier == subject_key_id.digest:
            return potential_issuer
    return None


def fetch_ocsp_status(cert, issuer_cert):
    """Verifica o status de revogação do certificado usando OCSP (Online Certificate Status Protocol)."""
    # Simulação de revogação - Modifique conforme necessário para utilizar um servidor OCSP real.
    if cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "revoked.badssl.com":
        return True
    return False


def fetch_crl(cert):
    """Verifica o status de revogação do certificado utilizando CRL (Certificate Revocation List)."""
    # Simulação de revogação - Modifique conforme necessário para utilizar CRLs reais.
    if cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "revoked.badssl.com":
        return True
    return False


def is_revoked(cert, issuer_cert):
    """Verifica se o certificado foi revogado usando OCSP ou CRL."""
    is_revoked = fetch_ocsp_status(cert, issuer_cert)
    if is_revoked is None:
        is_revoked = fetch_crl(cert)
    return is_revoked


def validate_certificate_chain(entity_cert, trusted_root_certs):
    """Valida o certificado da entidade final e monta a cadeia de certificação."""
    chain = [entity_cert]
    current_cert = entity_cert
    seen_certs = {entity_cert}  # Para evitar duplicação
    found_trusted_root = False
    trusted_root_cert = None

    while True:
        issuer_cert = find_issuer_certificate(current_cert, trusted_root_certs)

        if not issuer_cert:
            print("Certificado emissor não encontrado no pool. Tentando buscar via AIA...")
            issuer_cert = fetch_certificate_from_aia(current_cert)
            if issuer_cert:
                if issuer_cert not in seen_certs:
                    chain.append(issuer_cert)
                    seen_certs.add(issuer_cert)
            else:
                break

        if issuer_cert and issuer_cert not in seen_certs:
            chain.append(issuer_cert)
            seen_certs.add(issuer_cert)

        current_cert = issuer_cert

        if current_cert in trusted_root_certs:
            found_trusted_root = True
            trusted_root_cert = current_cert
            break

    return chain, found_trusted_root, trusted_root_cert


def display_chain(chain, is_trusted, trusted_root_cert):
    """Exibe a cadeia de certificação e a confiabilidade."""
    print("\nCadeia de Certificação:")
    for idx, cert in enumerate(reversed(chain), start=1):
        print(f"\nCertificado {idx}: {cert.subject.rfc4514_string()}")

        # Verificar validade do certificado
        now = datetime.now(timezone.utc)
        valid_from = cert.not_valid_before_utc  # Método atualizado para evitar depreciação
        valid_until = cert.not_valid_after_utc  # Método atualizado para evitar depreciação
        is_valid = valid_from <= now <= valid_until

        # Verificar revogação
        revoked_status = is_revoked(cert, chain[idx-2] if idx > 1 else None)  # Renomeado para evitar conflito

        status = "Válido" if is_valid and not revoked_status else "Inválido, revogado" if revoked_status else "Inválido, fora do prazo de validade"
        print(f"Período de validade: {valid_from} até {valid_until}")
        print(f"Status do certificado: {status}")

        # Obter o identificador da chave pública do requerente
        subject_key_id = get_extension_value(cert, "SUBJECT_KEY_IDENTIFIER")
        if subject_key_id:
            # Exibindo em formato hexadecimal
            print(f"Identificador da Chave do Requerente: {subject_key_id.digest.hex()}")

        # Exibindo o Identificador da Chave da Autoridade, se presente
        authority_key_id = get_extension_value(cert, "AUTHORITY_KEY_IDENTIFIER")
        if authority_key_id:
            print(f"Identificador da Chave da Autoridade: {authority_key_id.key_identifier.hex()}")

    # Mensagem de sucesso ou erro
    if is_trusted:
        print("\nAutoridade de certificação raiz confiada pelo usuário.")
        if trusted_root_cert:
            print(f"\nCertificado que estabelece a confiança: {trusted_root_cert.subject.rfc4514_string()}")
    else:
        print("\nAutoridade de certificação raiz não confiada pelo usuário.")


def main():
    # Caminho do certificado da entidade final
    entity_cert_path = input("Digite o caminho do certificado de entidade final (arquivo .cer, .crt ou .pem): ").strip()
    entity_cert = load_certificate(entity_cert_path)

    # Caminho para a pasta contendo os certificados AC Raiz confiáveis
    trusted_root_cert_directory = input("Digite o caminho da pasta contendo os certificados AC Raiz confiáveis: ").strip()
    trusted_root_certs = load_certificates_from_directory(trusted_root_cert_directory)

    # Verifica se foi encontrado pelo menos um certificado raiz
    if not trusted_root_certs:
        print("Nenhum certificado AC Raiz confiável encontrado na pasta.")
        return

    # Valida o certificado da entidade final
    chain, is_trusted, trusted_root_cert = validate_certificate_chain(entity_cert, trusted_root_certs)

    # Exibe a cadeia e a confiabilidade
    display_chain(chain, is_trusted, trusted_root_cert)


if __name__ == "__main__":
    main()
