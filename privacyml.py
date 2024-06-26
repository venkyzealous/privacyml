# Import necessary libraries
import seal
from seal import ChooserEvaluator,     \
                 Ciphertext,           \
                 Decryptor,            \
                 Encryptor,            \
                 EncryptionParameters, \
                 Evaluator,            \
                 IntegerEncoder,       \
                 FractionalEncoder,    \
                 KeyGenerator,         \
                 MemoryPoolHandle,     \
                 Plaintext,            \
                 SEALContext,          \
                 EvaluationKeys,       \
                 GaloisKeys,           \
                 PolyCRTBuilder,       \
                 ChooserEncoder,       \
                 ChooserEvaluator,     \
                 ChooserPoly

# Set up encryption parameters
parms = EncryptionParameters()
parms.set_poly_modulus("1x^2048 + 1")
parms.set_coeff_modulus(seal.coeff_modulus_128(2048))
parms.set_plain_modulus(1 << 8)

# Create context, key generator, keys, encoder, encryptor and evaluator
context = SEALContext.Create(parms)
keygen = KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()
encoder = IntegerEncoder(context.plain_modulus())
encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)

# Encrypt data
data = [5, 6, 7, 8]  # Example data
encrypted_data = []
for value in data:
    plain = Plaintext()
    encoder.encode(value, plain)
    encrypted = Ciphertext()
    encryptor.encrypt(plain, encrypted)
    encrypted_data.append(encrypted)

# Perform computations on encrypted data
result_encrypted = Ciphertext(encrypted_data[0])
for i in range(1, len(encrypted_data)):
    evaluator.add(result_encrypted, encrypted_data[i])

# Decrypt result
result_plain = Plaintext()
decryptor.decrypt(result_encrypted, result_plain)
result = encoder.decode_int32(result_plain)

print("The sum of the data is " + str(result))

#TODO: Install PySEAL and run this. Then implement 3 usecases to show PI data encrypted and operation performed with full privacy