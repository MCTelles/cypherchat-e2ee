# PASSO 1: Importar as ferramentas necessárias
def e2ee() -> None:
  from cryptography.hazmat.primitives.asymmetric import rsa, padding
  from cryptography.hazmat.primitives import hashes, serialization

  # PASSO 2: Instanciar o Par da Amanda
  instancia_privada_amanda = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048
  )
  publica_amanda = instancia_privada_amanda.public_key()

  # PASSO 3: Instanciar o Par do Bob (SEPARADO)
  instancia_privada_bob = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048
  )
  publica_bob = instancia_privada_bob.public_key()

  print("Chave Pública da Amanda:", publica_amanda)
  print("Chave Pública do Bob:", publica_bob)