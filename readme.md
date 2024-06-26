Library: You would need a library that supports homomorphic encryption. PySEAL and TenSEAL are Python libraries that you can use.

Use Cases:

a. Secure Health Records Analysis: You can demonstrate how a machine learning model can be trained on encrypted health records without decrypting them. This way, patient privacy is maintained.

b. Secure Financial Transactions Analysis: Similar to the health records, you can show how a model can be trained on encrypted financial data, preserving the privacy of the individuals or organizations.

c. Secure Voting System: Homomorphic encryption can be used to ensure that the counting of votes is accurate while preserving the privacy of voters.


https://pyfhel.readthedocs.io/en/latest/
https://github.com/ibarrond/Pyfhel.git

PySEAL github
https://github.com/Huelse/SEAL-Python

https://www.microsoft.com/en-us/research/project/microsoft-seal/
https://github.com/tsmatz/homomorphic-encryption-microsoft-seal/blob/master/01-seal-python-bfv-with-c-wrapper.ipynb

echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null
sudo apt-get update
sudo apt install python3-pip


git clone https://github.com/Huelse/SEAL-Python.git
cd SEAL/
cmake -S . -B build -DSEAL_BUILD_SEAL_C=ON
cmake --build build
cd ..


import ctypes
seal_lib = ctypes.CDLL("./SEAL/build/lib/libsealc.so.3.7.2")

#
# Define native function's arguments
#
seal_lib.EncParams_Create1.argtypes = [ ctypes.c_byte, ctypes.POINTER(ctypes.c_void_p) ]
seal_lib.EncParams_SetPlainModulus1.argtypes = [ ctypes.c_void_p, ctypes.c_void_p ]
seal_lib.EncParams_SetPolyModulusDegree.argtypes = [ ctypes.c_void_p, ctypes.c_ulonglong ]
seal_lib.EncParams_SetCoeffModulus.argtypes = [ ctypes.c_void_p, ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ulonglong) ]
seal_lib.Modulus_Create1.argtypes = [ ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_void_p) ]
seal_lib.CoeffModulus_BFVDefault.argtypes = [ ctypes.c_ulonglong, ctypes.c_int, ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_ulonglong) ]
seal_lib.SEALContext_Create.argtypes = [ ctypes.c_void_p, ctypes.c_bool, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p) ]
seal_lib.KeyGenerator_Create1.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p) ]
seal_lib.KeyGenerator_SecretKey.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p) ]
seal_lib.KeyGenerator_CreatePublicKey.argtypes = [ ctypes.c_void_p, ctypes.c_bool, ctypes.POINTER(ctypes.c_void_p) ]
seal_lib.KeyGenerator_CreateRelinKeys.argtypes = [ ctypes.c_void_p, ctypes.c_bool, ctypes.POINTER(ctypes.c_void_p) ]
seal_lib.Encryptor_Create.argtypes = [ ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p) ]
seal_lib.Encryptor_Encrypt.argtypes = [ ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p ]
seal_lib.Decryptor_Create.argtypes = [ ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p) ]
seal_lib.Decryptor_Decrypt.argtypes = [ ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p ]
seal_lib.Plaintext_Create1.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p) ]
seal_lib.Plaintext_Create4.argtypes = [ ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p) ]
seal_lib.Plaintext_ToString.argtypes = [ ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_ulonglong) ]
seal_lib.Ciphertext_Create1.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p) ]
seal_lib.Ciphertext_SaveSize.argtypes = [ ctypes.c_void_p, ctypes.c_ubyte, ctypes.POINTER(ctypes.c_ulonglong) ]
seal_lib.Ciphertext_Save.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong, ctypes.c_ubyte, ctypes.POINTER(ctypes.c_ulonglong) ]
seal_lib.Ciphertext_Size.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong) ]
seal_lib.Serialization_ComprModeDefault.argtypes = [ ctypes.POINTER(ctypes.c_ubyte) ]
seal_lib.Evaluator_Create.argtypes = [ ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p) ]
seal_lib.Evaluator_Square.argtypes = [ ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p ]
seal_lib.Evaluator_AddPlain.argtypes = [ ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p ]
seal_lib.Evaluator_Multiply.argtypes = [ ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p ]
seal_lib.Evaluator_Relinearize.argtypes = [ ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p ]

#
# Define error handling
#
def HandleError(error):
    if (error != 0):
        raise OSError('Failed with result: %s' %hex(error))

#
# Create encryption parameter (BFV)
#
ptr_encparm = ctypes.c_void_p()
HandleError(seal_lib.EncParams_Create1(
    ctypes.c_byte(0x01), # 0x01 means BFV
    ctypes.byref(ptr_encparm)
))

#
# Set encryption parameter details
#

# 1. PolyModulusDegree
HandleError(seal_lib.EncParams_SetPolyModulusDegree(
    ptr_encparm,
    ctypes.c_ulonglong(4096)
))
# 2. Create CoeffModulus
# (Here I use a helper CoeffModulus_BFVDefault()
#  to select a good choice of CoeffModulus
#  for the given PolyModulusDegree.)
coeff_len = ctypes.c_ulong(0)
HandleError(seal_lib.CoeffModulus_BFVDefault(
    ctypes.c_ulonglong(4096),
    ctypes.c_int(128),
    ctypes.byref(coeff_len),
    None
))
coeff_arr = (ctypes.c_ulong * coeff_len.value)()
HandleError(seal_lib.CoeffModulus_BFVDefault(
    ctypes.c_ulonglong(4096),
    ctypes.c_int(128),
    ctypes.byref(coeff_len),
    ctypes.cast(coeff_arr, ctypes.POINTER(ctypes.c_ulong))
))
# for i in coeff_arr: print(i) # uncomment to check values
# 3. Set CoeffModulus
HandleError(seal_lib.EncParams_SetCoeffModulus(
    ptr_encparm,
    coeff_len,
    ctypes.cast(coeff_arr, ctypes.POINTER(ctypes.c_ulong))
))
# 4. PlainModulus
ptr_small_modulus = ctypes.c_void_p()
HandleError(seal_lib.Modulus_Create1(
    ctypes.c_ulonglong(1024),
    ctypes.byref(ptr_small_modulus)
))
HandleError(seal_lib.EncParams_SetPlainModulus1(
    ptr_encparm,
    ptr_small_modulus
))

#
# Create SEAL context
#
ptr_context = ctypes.c_void_p()
HandleError(seal_lib.SEALContext_Create(
    ptr_encparm,
    ctypes.c_bool(True),
    ctypes.c_int(128),
    ctypes.byref(ptr_context)
))

#
# Create keys for encryption, decryption, and relinearization
#

# Create key generator
ptr_key_generator = ctypes.c_void_p()
HandleError(seal_lib.KeyGenerator_Create1(
    ptr_context,
    ctypes.byref(ptr_key_generator)
))
# Get secret key used for decryption
# (Use SecretKey_Data when you show secret key text)
ptr_secret_key = ctypes.c_void_p()
HandleError(seal_lib.KeyGenerator_SecretKey(
    ptr_key_generator,
    ctypes.byref(ptr_secret_key)
))
# Create public key used for encryption
ptr_public_key = ctypes.c_void_p()
HandleError(seal_lib.KeyGenerator_CreatePublicKey(
    ptr_key_generator,
    ctypes.c_bool(False),
    ctypes.byref(ptr_public_key)
))
# Create relinearization key used for relinearization
ptr_relin_key = ctypes.c_void_p()
HandleError(seal_lib.KeyGenerator_CreateRelinKeys(
    ptr_key_generator,
    ctypes.c_bool(False),
    ctypes.byref(ptr_relin_key)
))

#
# Create encryption for x (= 7)
#

# Create encryptor
ptr_encryptor = ctypes.c_void_p()
HandleError(seal_lib.Encryptor_Create(
    ptr_context,
    ptr_public_key,
    None,
    ctypes.byref(ptr_encryptor)
))
# Convert integer to hex string (e.g, 17 --> "11")
string_x = format(7, "x")
# Create plain text for x
ptr_plain_x = ctypes.c_void_p()
HandleError(seal_lib.Plaintext_Create4(
    ctypes.c_char_p(bytes(string_x, "utf-8")),
    None,
    ctypes.byref(ptr_plain_x)
))
# Create cipher text
ptr_cipher_x = ctypes.c_void_p()
HandleError(seal_lib.Ciphertext_Create1(
    None,
    ctypes.byref(ptr_cipher_x)
))
# Encrypt
HandleError(seal_lib.Encryptor_Encrypt(
    ptr_encryptor,
    ptr_plain_x,
    ptr_cipher_x,
    None
))

#
# Encode and output cipher text for x
#
# (Here I only show base64 encoded string,
#  but this will be needed for passing a cipher data on network.)
#

# Get default compare mode
compr_mode = ctypes.c_ubyte()
HandleError(seal_lib.Serialization_ComprModeDefault(
    ctypes.byref(compr_mode)
))
# Get save size
save_size = ctypes.c_ulonglong()
HandleError(seal_lib.Ciphertext_SaveSize(
    ptr_cipher_x,
    compr_mode,
    ctypes.byref(save_size)
))
# Write encrypted bytes to buffer
save_size_output = ctypes.c_ulonglong()
byte_arr_x = (ctypes.c_ubyte * save_size.value)()
HandleError(seal_lib.Ciphertext_Save(    
    ptr_cipher_x,
    ctypes.cast(byte_arr_x, ctypes.POINTER(ctypes.c_ubyte)),
    save_size,
    compr_mode,
    ctypes.byref(save_size_output)
))
# Base64 encode
byte_nparr_x = np.array(byte_arr_x[:save_size_output.value], dtype = ctypes.c_ubyte)
b64_x = base64.b64encode(byte_nparr_x)
print("********** Base64 encoded x **********")
print(b64_x)

#
# Compute x^2
#

# Create Evaluator
ptr_evaluator = ctypes.c_void_p()
HandleError(seal_lib.Evaluator_Create(
    ptr_context,
    ctypes.byref(ptr_evaluator)
))
# Create cipher text for result
ptr_cipher_res = ctypes.c_void_p()
HandleError(seal_lib.Ciphertext_Create1(
    None,
    ctypes.byref(ptr_cipher_res)
))
# Square x
HandleError(seal_lib.Evaluator_Square(
    ptr_evaluator,
    ptr_cipher_x,
    ptr_cipher_res,
    None
))

#
# Relinearize and compute x^3
#

# Output the size of cipher
cipher_size = ctypes.c_ulonglong()
HandleError(seal_lib.Ciphertext_Size(
    ptr_cipher_res,
    ctypes.byref(cipher_size)
))
print("Size of cipher (before relinearization) : {}".format(cipher_size.value))
# Relinearize to reduce the size of a cipher 
HandleError(seal_lib.Evaluator_Relinearize(
    ptr_evaluator,
    ptr_cipher_res,
    ptr_relin_key,
    ptr_cipher_res,
    None
))
# Output the size of cipher
HandleError(seal_lib.Ciphertext_Size(
    ptr_cipher_res,
    ctypes.byref(cipher_size)
))
print("Size of cipher (after relinearization) : {}".format(cipher_size.value))
# Compute x^3
HandleError(seal_lib.Evaluator_Multiply(
    ptr_evaluator,
    ptr_cipher_res,
    ptr_cipher_x,
    ptr_cipher_res,
    None
))
# Output the size of cipher
HandleError(seal_lib.Ciphertext_Size(
    ptr_cipher_res,
    ctypes.byref(cipher_size)
))
print("Size of cipher (after compute x^3) : {}".format(cipher_size.value))
# Relinearize to reduce the size of a cipher 
HandleError(seal_lib.Evaluator_Relinearize(
    ptr_evaluator,
    ptr_cipher_res,
    ptr_relin_key,
    ptr_cipher_res,
    None
))
# Output the size of cipher
HandleError(seal_lib.Ciphertext_Size(
    ptr_cipher_res,
    ctypes.byref(cipher_size)
))
print("Size of cipher (after relinearization) : {}".format(cipher_size.value))

#
# Compute x^3 + 5
#

# Create plain text for 5
string_5 = format(5, "x") # Convert to hex string
ptr_plain_5 = ctypes.c_void_p()
HandleError(seal_lib.Plaintext_Create4(
    ctypes.c_char_p(bytes(string_5, "utf-8")),
    None,
    ctypes.byref(ptr_plain_5)
))
# Add 5
HandleError(seal_lib.Evaluator_AddPlain(
    ptr_evaluator,
    ptr_cipher_res,
    ptr_plain_5,
    ptr_cipher_res
))

#
# Decrypt result
#

# Create Decryptor
ptr_decryptor = ctypes.c_void_p()
HandleError(seal_lib.Decryptor_Create(
    ptr_context,
    ptr_secret_key,
    ctypes.byref(ptr_decryptor)
))
# Create plain text for result
ptr_plain_res = ctypes.c_void_p()
HandleError(seal_lib.Plaintext_Create1(
    None,
    ctypes.byref(ptr_plain_res)
))
# Decrypt result
HandleError(seal_lib.Decryptor_Decrypt(
    ptr_decryptor,
    ptr_cipher_res,
    ptr_plain_res
))
# Convert to string
result_len = ctypes.c_ulonglong()
HandleError(seal_lib.Plaintext_ToString(
    ptr_plain_res,
    None,
    ctypes.byref(result_len)
))
char_arr_res = (ctypes.c_char * (result_len.value + 1))()
HandleError(seal_lib.Plaintext_ToString(
    ptr_plain_res,
    ctypes.cast(char_arr_res, ctypes.c_char_p),
    ctypes.byref(result_len)
))
decrypted_hex_text = ctypes.cast(char_arr_res, ctypes.c_char_p)
print("********** Result is **********")
print(int(decrypted_hex_text.value.decode("utf-8"), 16))

