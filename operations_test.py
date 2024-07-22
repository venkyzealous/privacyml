from pyspark.sql import SparkSession
from pyspark.sql.functions import col, regexp_replace
import numpy as np
from Pyfhel import Pyfhel




#initialize HE
HE = Pyfhel()           # Creating empty Pyfhel object
ckks_params = {
    'scheme': 'CKKS',   # can also be 'ckks'
    'n': 2**14,         # Polynomial modulus degree. For CKKS, n/2 values can be
                        #  encoded in a single ciphertext.
                        #  Typ. 2^D for D in [10, 15]
    'scale': 2**30,     # All the encodings will use it for float->fixed point
                        #  conversion: x_fix = round(x_float * scale)
                        #  You can use this as default scale or use a different
                        #  scale on each operation (set in HE.encryptFrac)
    'qi_sizes': [60, 30, 30, 30, 60] # Number of bits of each prime in the chain.
                        # Intermediate values should be  close to log2(scale)
                        # for each operation, to have small rounding errors.
}
HE.contextGen(**ckks_params)  # Generate context for ckks scheme
HE.keyGen()             # Key Generation: generates a pair of public/secret keys
HE.rotateKeyGen()



arr_x = np.array([0.1, 0.2, -0.3], dtype=np.float64)    # Always use type float64!
arr_y = np.array([-1.5, 2.3, 4.7], dtype=np.float64)

ptxt_x = HE.encodeFrac(arr_x)   # Creates a PyPtxt plaintext with the encoded arr_x
ptxt_y = HE.encodeFrac(arr_y)   # plaintexts created from arrays shorter than 'n' are filled with zeros.

ctxt_x = HE.encryptPtxt(ptxt_x) # Encrypts the plaintext ptxt_x and returns a PyCtxt
ctxt_y = HE.encryptPtxt(ptxt_y) #  Alternatively you can use HE.encryptFrac(arr_y)

# Otherwise, a single call to `HE.encrypt` would detect the data type,
#  encode it and encrypt it
#> ctxt_x = HE.encrypt(arr_x)

print("\n2. Fixed-point Encoding & Encryption, ")
print("->\tarr_x ", arr_x,'\n\t==> ptxt_x ', ptxt_x,'\n\t==> ctxt_x ', ctxt_x)
print("->\tarr_y ", arr_y,'\n\t==> ptxt_y ', ptxt_y,'\n\t==> ctxt_y ', ctxt_y)

# Ciphertext-ciphertext ops:
ccSum = ctxt_x + ctxt_y       # Calls HE.add(ctxt_x, ctxt_y, in_new_ctxt=True)
                            #  `ctxt_x += ctxt_y` for inplace operation
ccSub = ctxt_x - ctxt_y       # Calls HE.sub(ctxt_x, ctxt_y, in_new_ctxt=True)
                            #  `ctxt_x -= ctxt_y` for inplace operation
ccMul = ctxt_x * ctxt_y       # Calls HE.multiply(ctxt_x, ctxt_y, in_new_ctxt=True)
                            #  `ctxt_x *= ctxt_y` for inplace operation
cSq   = ctxt_x**2            # Calls HE.square(ctxt_x, in_new_ctxt=True)
                            #  `ctxt_x **= 2` for inplace operation
cNeg  = -ctxt_x              # Calls HE.negate(ctxt_x, in_new_ctxt=True)
                            #
# cPow  = ctxt_x**3          # pow Not supported in CKKS
cRotR = ctxt_x >> 2          # Calls HE.rotate(ctxt_x, k=2, in_new_ctxt=True)
                            #  `ctxt_x >>= 2` for inplace operation
cRotL = ctxt_x << 2          # Calls HE.rotate(ctxt_x, k=-2, in_new_ctxt=True)
                            #  `ctxt_x <<= 2` for inplace operation

# Ciphetext-plaintext ops
cpSum = ctxt_x + ptxt_y       # Calls HE.add_plain(ctxt_x, ptxt_y, in_new_ctxt=True)
                            # `ctxt_x += ctxt_y` for inplace operation
cpSub = ctxt_x - ptxt_y       # Calls HE.sub_plain(ctxt_x, ptxt_y, in_new_ctxt=True)
                            # `ctxt_x -= ctxt_y` for inplace operation
cpMul = ctxt_x * ptxt_y       # Calls HE.multiply_plain(ctxt_x, ptxt_y, in_new_ctxt=True)
                            # `ctxt_x *= ctxt_y` for inplace operation


print("3. Secure operations")
print(" Ciphertext-ciphertext: ")
print("->\tctxt_x + ctxt_y = ccSum: ", ccSum)
print("->\tctxt_x - ctxt_y = ccSub: ", ccSub)
print("->\tctxt_x * ctxt_y = ccMul: ", ccMul)
print(" Single ciphertext: ")
print("->\tctxt_x**2      = cSq  : ", cSq  )
print("->\t- ctxt_x       = cNeg : ", cNeg )
print("->\tctxt_x >> 4    = cRotR: ", cRotR)
print("->\tctxt_x << 4    = cRotL: ", cRotL)
print(" Ciphertext-plaintext: ")
print("->\tctxt_x + ptxt_y = cpSum: ", cpSum)
print("->\tctxt_x - ptxt_y = cpSub: ", cpSub)
print("->\tctxt_x * ptxt_y = cpMul: ", cpMul)

print("\n4. Relinearization-> Right after each multiplication.")
print(f"ccMul before relinearization (size {ccMul.size()}): {ccMul}")
HE.relinKeyGen()
~ccMul    # Equivalent to HE.relinearize(ccMul). Relin always happens in-place.
print(f"ccMul after relinearization (size {ccMul.size()}): {ccMul}")


#  1. Mean
c_mean = (ctxt_x + ctxt_y) / 2
#  2. MSE
c_mse_1 = ~((ctxt_x - c_mean)**2)
c_mse_2 = (~(ctxt_y - c_mean)**2)
c_mse = (c_mse_1 + c_mse_2)/ 3
#  3. Cumulative sum
c_mse += (c_mse << 1)
c_mse += (c_mse << 2)  # element 0 contains the result
print("\n5. Rescaling & Mod Switching.")
print("->\tMean: ", c_mean)
print("->\tMSE_1: ", c_mse_1)
print("->\tMSE_2: ", c_mse_2)
print("->\tMSE: ", c_mse)

r_x    = HE.decryptFrac(ctxt_x)
r_y    = HE.decryptFrac(ctxt_y)
rccSum = HE.decryptFrac(ccSum)
rccSub = HE.decryptFrac(ccSub)
rccMul = HE.decryptFrac(ccMul)
rcSq   = HE.decryptFrac(cSq  )
rcNeg  = HE.decryptFrac(cNeg )
rcRotR = HE.decryptFrac(cRotR)
rcRotL = HE.decryptFrac(cRotL)
rcpSum = HE.decryptFrac(cpSum)
rcpSub = HE.decryptFrac(cpSub)
rcpMul = HE.decryptFrac(cpMul)
rmean  = HE.decryptFrac(c_mean)
rmse   = HE.decryptFrac(c_mse)

# Note: results are approximate! if you increase the decimals, you will notice
#  the errors
_r = lambda x: np.round(x, decimals=3)
print("6. Decrypting results")
print(" Original ciphertexts: ")
print("   ->\tctxt_x --(decr)--> ", _r(r_x))
print("   ->\tctxt_y --(decr)--> ", _r(r_y))
print(" Ciphertext-ciphertext Ops: ")
print("   ->\tctxt_x + ctxt_y = ccSum --(decr)--> ", _r(rccSum))
print("   ->\tctxt_x - ctxt_y = ccSub --(decr)--> ", _r(rccSub))
print("   ->\tctxt_x * ctxt_y = ccMul --(decr)--> ", _r(rccMul))
print(" Single ciphertext: ")
print("   ->\tctxt_x**2      = cSq   --(decr)--> ", _r(rcSq  ))
print("   ->\t- ctxt_x       = cNeg  --(decr)--> ", _r(rcNeg ))
print("   ->\tctxt_x >> 4    = cRotR --(decr)--> ", _r(rcRotR))
print("   ->\tctxt_x << 4    = cRotL --(decr)--> ", _r(rcRotL))
print(" Ciphertext-plaintext ops: ")
print("   ->\tctxt_x + ptxt_y = cpSum --(decr)--> ", _r(rcpSum))
print("   ->\tctxt_x - ptxt_y = cpSub --(decr)--> ", _r(rcpSub))
print("   ->\tctxt_x * ptxt_y = cpMul --(decr)--> ", _r(rcpMul))
print(" Mean Squared error: ")
print("   ->\tmean(ctxt_x, ctxt_y) = c_mean --(decr)--> ", _r(rmean))
print("   ->\tmse(ctxt_x, ctxt_y)  = c_mse  --(decr)--> ", _r(rmse))

exit

sample_data = [{"name": "John    D.", "balance":20.5,"credit":20.0}
               #,
 # {"name": "Alice   G.", "balance": 25.0,"credit":20.0},
 # {"name": "Bob  T.", "balance": 35.0,"credit":20.0},
 # {"name": "Eve   A.", "balance": 28.5,"credit":20.0}
 ]



# Create a SparkSession
spark = SparkSession.builder.appName("Testing PySpark Example").getOrCreate()
df = spark.createDataFrame(nd_array)

# Adding credit and balance columns and updating the balance column with new balance
df = df.withColumn("new_balance", col("balance") + col("credit"))
#df = df.withColumn("decrypt_balance",HE.decryptInt("new_balance"))

df.show()


