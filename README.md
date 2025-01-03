# **CertChainValidator**

CertChainValidator é um script Python para validar cadeias de certificação X.509. Ele verifica a validade de um certificado final em relação a uma autoridade de certificação raiz confiável e identifica se algum certificado na cadeia está revogado.

---
```bash
## **Pré-requisitos**
1. Certifique-se de ter o Python instalado no sistema (versão 3.6 ou superior recomendada).
2. Instale as dependências necessárias executando os comandos abaixo no terminal:


python -m pip install --upgrade pip
pip install -r requirements.txt

CASO DE ERRO AO EXECUTAR OS requirements.txt as dependências dos scripts estão abaixo:

pip install cryptography 
pip install requests


# **Como Usar o Script**

1. Execute o script no terminal:

python certchainvalidator.py

2. Quando solicitado, insira o caminho do certificado da entidade final no formato .cer, .crt ou .pem:

Digite o caminho do certificado de entidade final (arquivo .cer, .crt ou .pem):
C:/Users/dougl/Downloads/Certificados/BADSSL.crt

3. Em seguida, insira o caminho da pasta contendo os certificados raiz confiáveis:

Digite o caminho da pasta contendo os certificados AC Raiz confiáveis:
C:/Users/dougl/Downloads/AC_Confiavel

4. O script exibirá as informações sobre a cadeia de certificação, validade e status de revogação diretamente no terminal.

