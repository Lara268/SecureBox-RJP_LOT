# SecureBox - decisiones técnicas

## Algoritmos
- AEAD: AES-256-GCM
- Modo A: RSA-OAEP con SHA-256
- Modo B: X25519 + HKDF-SHA256
- Firma: Ed25519
- Formato: JSON + Base64
- Version: sbox-1

## Reglas
- Los bytes se guardan en Base64
- recipient_id = SHA-256 de la clave pública PEM
- Se firma el contenedor menos el campo "signature"
- Canonicalización:
  json.dumps(obj, sort_keys=True, separators=(",", ":"))